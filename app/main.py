import io
import json
import os
from typing import Literal, Optional

import paramiko
import winrm
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Text, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.getenv("DB_PATH", "/data/rcommander.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class ServerRow(Base):
    __tablename__ = "servers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=22)
    type = Column(String, nullable=False, default="ssh")
    description = Column(Text, default="")
    credential_id = Column(Integer, nullable=True)
    server_group = Column(String, default="")


class CredentialRow(Base):
    __tablename__ = "credentials"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    password = Column(Text, default="")
    private_key = Column(Text, default="")
    description = Column(Text, default="")


class CommandRow(Base):
    __tablename__ = "commands"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    command = Column(Text, nullable=False)
    description = Column(Text, default="")


Base.metadata.create_all(engine)


def _migrate():
    """Add columns introduced after initial release without dropping existing data."""
    migrations = {
        "servers":     [("description",   "TEXT NOT NULL DEFAULT ''"),
                        ("credential_id", "INTEGER"),
                        ("server_group",  "TEXT NOT NULL DEFAULT ''")],
        "credentials": [("description",   "TEXT NOT NULL DEFAULT ''")],
        "commands":    [("description",   "TEXT NOT NULL DEFAULT ''")],
    }
    with engine.connect() as conn:
        for table, columns in migrations.items():
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            for column, col_def in columns:
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
        conn.commit()


_migrate()

app = FastAPI(title="RCommander")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ServerIn(BaseModel):
    name: str
    host: str
    port: int = 22
    type: Literal["ssh", "winrm"] = "ssh"
    description: str = ""
    credential_id: Optional[int] = None
    server_group: str = ""


class CredentialIn(BaseModel):
    name: str
    username: str
    password: str = ""
    private_key: str = ""
    description: str = ""


class CommandIn(BaseModel):
    name: str
    command: str
    description: str = ""


class ExecuteRequest(BaseModel):
    server_id: int
    credential_id: int
    command_id: int


class ImportResult(BaseModel):
    created: int
    skipped: int
    errors: list[str]


# ── Helpers ───────────────────────────────────────────────────────────────────

def row_to_dict(row) -> dict:
    d = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    if "password" in d:
        d["has_password"] = bool(d["password"])
        del d["password"]
    if "private_key" in d:
        d["has_private_key"] = bool(d["private_key"])
        del d["private_key"]
    return d


def _create_row(db, row):
    db.add(row)
    try:
        db.commit()
        db.refresh(row)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Name already exists")
    return row_to_dict(row)


def _delete_row(db, row):
    if not row:
        raise HTTPException(404, "Not found")
    db.delete(row)
    db.commit()


def _load_private_key(key_content: str):
    key_file = io.StringIO(key_content)
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            key_file.seek(0)
            return cls.from_private_key(key_file)
        except Exception:
            continue
    raise ValueError("Unsupported or invalid private key format")


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj)}\n\n"


def _ssh_stream(host: str, port: int, username: str, password: str, private_key: str, command: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict = {"username": username, "timeout": 15}
        if private_key:
            connect_kwargs["pkey"] = _load_private_key(private_key)
        elif password:
            connect_kwargs["password"] = password
        else:
            raise ValueError("No authentication method provided")

        client.connect(host, port=port, **connect_kwargs)
        _, stdout, stderr = client.exec_command(command, get_pty=True)

        for line in iter(lambda: stdout.readline(4096), ""):
            if not line:
                break
            yield _sse({"type": "stdout", "text": line})

        err = stderr.read().decode("utf-8", errors="replace")
        if err:
            yield _sse({"type": "stderr", "text": err})

        code = stdout.channel.recv_exit_status()
        yield _sse({"type": "exit", "code": code})
    except Exception as exc:
        yield _sse({"type": "error", "text": str(exc)})
    finally:
        client.close()
        yield _sse({"type": "done"})


def _winrm_stream(host: str, port: int, username: str, password: str, command: str):
    try:
        protocol = "https" if port == 5986 else "http"
        endpoint = f"{protocol}://{host}:{port}/wsman"
        s = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="basic",
            server_cert_validation="ignore",
        )
        if command.strip().lower().startswith("powershell") or command.strip().startswith("$"):
            result = s.run_ps(command)
        else:
            result = s.run_cmd(command)

        stdout = result.std_out.decode("utf-8", errors="replace")
        stderr = result.std_err.decode("utf-8", errors="replace")
        if stdout:
            yield _sse({"type": "stdout", "text": stdout})
        if stderr:
            yield _sse({"type": "stderr", "text": stderr})
        yield _sse({"type": "exit", "code": result.status_code})
    except Exception as exc:
        yield _sse({"type": "error", "text": str(exc)})
    finally:
        yield _sse({"type": "done"})


# ── Servers ───────────────────────────────────────────────────────────────────

@app.get("/api/servers")
def list_servers():
    with Session() as db:
        return [row_to_dict(r) for r in db.query(ServerRow).order_by(ServerRow.name).all()]


@app.post("/api/servers", status_code=201)
def create_server(data: ServerIn):
    with Session() as db:
        return _create_row(db, ServerRow(**data.model_dump()))


@app.put("/api/servers/{server_id}")
def update_server(server_id: int, data: ServerIn):
    with Session() as db:
        row = db.get(ServerRow, server_id)
        if not row:
            raise HTTPException(404, "Not found")
        for k, v in data.model_dump().items():
            setattr(row, k, v)
        db.commit()
        db.refresh(row)
        return row_to_dict(row)


@app.post("/api/servers/import")
def import_servers(servers: list[ServerIn]) -> ImportResult:
    created = skipped = 0
    errors: list[str] = []
    with Session() as db:
        for s in servers:
            if db.query(ServerRow.id).filter_by(name=s.name).scalar():
                skipped += 1
                continue
            db.add(ServerRow(**s.model_dump()))
            created += 1
        try:
            db.commit()
        except Exception as exc:
            db.rollback()
            errors.append(str(exc))
    return ImportResult(created=created, skipped=skipped, errors=errors)


@app.delete("/api/servers/{server_id}", status_code=204)
def delete_server(server_id: int):
    with Session() as db:
        _delete_row(db, db.get(ServerRow, server_id))


# ── Groups ────────────────────────────────────────────────────────────────────

class GroupRename(BaseModel):
    old_name: str
    new_name: str


@app.get("/api/groups")
def list_groups():
    with Session() as db:
        rows = db.query(ServerRow.server_group).filter(
            ServerRow.server_group != ""
        ).distinct().order_by(ServerRow.server_group).all()
        return [r[0] for r in rows]


@app.put("/api/groups/rename")
def rename_group(data: GroupRename):
    if not data.new_name.strip():
        raise HTTPException(400, "New name cannot be empty")
    with Session() as db:
        db.query(ServerRow).filter(ServerRow.server_group == data.old_name).update(
            {ServerRow.server_group: data.new_name.strip()}
        )
        db.commit()
    return {"ok": True}


@app.delete("/api/groups/{name}", status_code=204)
def delete_group(name: str):
    with Session() as db:
        db.query(ServerRow).filter(ServerRow.server_group == name).update(
            {ServerRow.server_group: ""}
        )
        db.commit()


# ── Credentials ───────────────────────────────────────────────────────────────

@app.get("/api/credentials")
def list_credentials():
    with Session() as db:
        return [row_to_dict(r) for r in db.query(CredentialRow).order_by(CredentialRow.name).all()]


@app.post("/api/credentials", status_code=201)
def create_credential(data: CredentialIn):
    with Session() as db:
        return _create_row(db, CredentialRow(**data.model_dump()))


@app.put("/api/credentials/{cred_id}")
def update_credential(cred_id: int, data: CredentialIn):
    with Session() as db:
        row = db.get(CredentialRow, cred_id)
        if not row:
            raise HTTPException(404, "Not found")
        for k, v in data.model_dump().items():
            if k in ("password", "private_key") and v == "":
                continue
            setattr(row, k, v)
        db.commit()
        db.refresh(row)
        return row_to_dict(row)


@app.delete("/api/credentials/{cred_id}", status_code=204)
def delete_credential(cred_id: int):
    with Session() as db:
        _delete_row(db, db.get(CredentialRow, cred_id))


# ── Commands ──────────────────────────────────────────────────────────────────

@app.get("/api/commands")
def list_commands():
    with Session() as db:
        return [row_to_dict(r) for r in db.query(CommandRow).order_by(CommandRow.name).all()]


@app.post("/api/commands", status_code=201)
def create_command(data: CommandIn):
    with Session() as db:
        return _create_row(db, CommandRow(**data.model_dump()))


@app.put("/api/commands/{cmd_id}")
def update_command(cmd_id: int, data: CommandIn):
    with Session() as db:
        row = db.get(CommandRow, cmd_id)
        if not row:
            raise HTTPException(404, "Not found")
        for k, v in data.model_dump().items():
            setattr(row, k, v)
        db.commit()
        db.refresh(row)
        return row_to_dict(row)


@app.delete("/api/commands/{cmd_id}", status_code=204)
def delete_command(cmd_id: int):
    with Session() as db:
        _delete_row(db, db.get(CommandRow, cmd_id))


# ── Execute ───────────────────────────────────────────────────────────────────

@app.post("/api/execute")
def execute(req: ExecuteRequest):
    with Session() as db:
        server = db.get(ServerRow, req.server_id)
        cred = db.get(CredentialRow, req.credential_id)
        cmd = db.get(CommandRow, req.command_id)
        if not server or not cred or not cmd:
            raise HTTPException(404, "Server, credential, or command not found")
        s_type = server.type
        s_host, s_port = server.host, server.port
        c_user, c_pass, c_key = cred.username, cred.password, cred.private_key
        c_command = cmd.command

    def stream():
        if s_type == "ssh":
            yield from _ssh_stream(s_host, s_port, c_user, c_pass, c_key, c_command)
        elif s_type == "winrm":
            yield from _winrm_stream(s_host, s_port, c_user, c_pass, c_command)
        else:
            yield _sse({"type": "error", "text": f"Unknown server type: {s_type}"})
            yield _sse({"type": "done"})

    return StreamingResponse(stream(), media_type="text/event-stream")


# ── Health & static ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
