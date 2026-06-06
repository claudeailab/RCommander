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
from sqlalchemy import Column, Integer, String, Text, create_engine, or_, text
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
    server_id = Column(Integer, nullable=True)
    shell_type = Column(String, default="cmd")


class GroupRow(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True, nullable=False)


class FolderCredentialRow(Base):
    __tablename__ = "folder_credentials"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True, nullable=False)
    credential_id = Column(Integer, nullable=False)


Base.metadata.create_all(engine)


def _migrate():
    """Add columns introduced after initial release without dropping existing data."""
    migrations = {
        "servers":     [("description",   "TEXT NOT NULL DEFAULT ''"),
                        ("credential_id", "INTEGER"),
                        ("server_group",  "TEXT NOT NULL DEFAULT ''")],
        "credentials": [("description",   "TEXT NOT NULL DEFAULT ''")],
        "commands":    [("description",   "TEXT NOT NULL DEFAULT ''"),
                        ("server_id",     "INTEGER"),
                        ("shell_type",    "TEXT NOT NULL DEFAULT 'cmd'")],
    }
    with engine.connect() as conn:
        for table, columns in migrations.items():
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            for column, col_def in columns:
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
        conn.commit()


_migrate()

APP_VERSION = "1.3.4"

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
    server_id: Optional[int] = None
    shell_type: str = "cmd"


class ExecuteRequest(BaseModel):
    server_id: int
    credential_id: int
    command_id: int


class ImportResult(BaseModel):
    created: int
    skipped: int
    errors: list[str]


class GroupIn(BaseModel):
    path: str


class FolderCredentialIn(BaseModel):
    credential_id: int


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
    import select
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
        # get_pty=True gives a real PTY so programs emit colours/formatting
        # exactly as they would in an interactive SSH session
        _, stdout, stderr = client.exec_command(command, get_pty=True, timeout=None)
        channel = stdout.channel

        # Stream raw chunks — PTY output uses \r\n and cursor codes that
        # don't split cleanly on \n, so send chunks as-is
        buf_out = b""
        buf_err = b""

        while not channel.closed or channel.recv_ready() or channel.recv_stderr_ready():
            readable, _, _ = select.select([channel], [], [], 0.2)
            if readable:
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if chunk:
                        buf_out += chunk
                        while b"\n" in buf_out:
                            line, buf_out = buf_out.split(b"\n", 1)
                            yield _sse({"type": "stdout", "text": line.decode("utf-8", errors="replace") + "\n"})
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096)
                    if chunk:
                        buf_err += chunk
                        while b"\n" in buf_err:
                            line, buf_err = buf_err.split(b"\n", 1)
                            yield _sse({"type": "stderr", "text": line.decode("utf-8", errors="replace") + "\n"})

        # Flush any remaining partial output (no trailing newline)
        if buf_out:
            yield _sse({"type": "stdout", "text": buf_out.decode("utf-8", errors="replace")})
        if buf_err:
            yield _sse({"type": "stderr", "text": buf_err.decode("utf-8", errors="replace")})

        code = channel.recv_exit_status()
        yield _sse({"type": "exit", "code": code})
    except Exception as exc:
        yield _sse({"type": "error", "text": str(exc)})
    finally:
        client.close()
        yield _sse({"type": "done"})


def _winrm_stream(host: str, port: int, username: str, password: str, command: str, shell_type: str = "cmd"):
    try:
        protocol = "https" if port == 5986 else "http"
        endpoint = f"{protocol}://{host}:{port}/wsman"
        s = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="basic",
            server_cert_validation="ignore",
        )
        if shell_type == "powershell":
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

@app.get("/api/version")
def get_version():
    return {"version": APP_VERSION}


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
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Name already exists")
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
    """Return all known folder paths — explicit + those derived from server assignments."""
    with Session() as db:
        explicit = {r.path for r in db.query(GroupRow).all()}
        derived: set[str] = set()
        for (sg,) in db.query(ServerRow.server_group).filter(ServerRow.server_group != "").all():
            parts = sg.split("/")
            for i in range(1, len(parts) + 1):
                derived.add("/".join(parts[:i]))
        return sorted(explicit | derived)


@app.post("/api/groups", status_code=201)
def create_group(data: GroupIn):
    path = data.path.strip().strip("/")
    if not path:
        raise HTTPException(400, "Path cannot be empty")
    with Session() as db:
        if not db.query(GroupRow.id).filter_by(path=path).scalar():
            db.add(GroupRow(path=path))
            db.commit()
    return {"path": path}


@app.put("/api/groups/rename")
def rename_group(data: GroupRename):
    if not data.new_name.strip():
        raise HTTPException(400, "New name cannot be empty")
    old, new = data.old_name, data.new_name.strip()
    prefix = old + "/"
    with Session() as db:
        db.query(ServerRow).filter(ServerRow.server_group == old).update(
            {ServerRow.server_group: new}
        )
        for row in db.query(ServerRow).filter(ServerRow.server_group.like(prefix + "%")).all():
            row.server_group = new + "/" + row.server_group[len(prefix):]
        db.query(GroupRow).filter(GroupRow.path == old).update({GroupRow.path: new})
        for row in db.query(GroupRow).filter(GroupRow.path.like(prefix + "%")).all():
            row.path = new + "/" + row.path[len(prefix):]
        db.query(FolderCredentialRow).filter(FolderCredentialRow.path == old).update(
            {FolderCredentialRow.path: new}
        )
        for row in db.query(FolderCredentialRow).filter(FolderCredentialRow.path.like(prefix + "%")).all():
            row.path = new + "/" + row.path[len(prefix):]
        db.commit()
    return {"ok": True}


@app.delete("/api/groups/{name:path}", status_code=204)
def delete_group(name: str):
    with Session() as db:
        db.query(ServerRow).filter(
            or_(ServerRow.server_group == name,
                ServerRow.server_group.like(name + "/%"))
        ).update({ServerRow.server_group: ""}, synchronize_session="fetch")
        db.query(GroupRow).filter(
            or_(GroupRow.path == name,
                GroupRow.path.like(name + "/%"))
        ).delete(synchronize_session="fetch")
        db.query(FolderCredentialRow).filter(
            or_(FolderCredentialRow.path == name,
                FolderCredentialRow.path.like(name + "/%"))
        ).delete(synchronize_session="fetch")
        db.commit()


# ── Folder Credentials ────────────────────────────────────────────────────────

@app.get("/api/folder-credentials")
def list_folder_credentials():
    with Session() as db:
        return [{"path": r.path, "credential_id": r.credential_id}
                for r in db.query(FolderCredentialRow).all()]


@app.put("/api/folder-credentials/{path:path}", status_code=200)
def set_folder_credential(path: str, data: FolderCredentialIn):
    with Session() as db:
        row = db.query(FolderCredentialRow).filter_by(path=path).first()
        if row:
            row.credential_id = data.credential_id
        else:
            db.add(FolderCredentialRow(path=path, credential_id=data.credential_id))
        db.commit()
    return {"path": path, "credential_id": data.credential_id}


@app.delete("/api/folder-credentials/{path:path}", status_code=204)
def delete_folder_credential(path: str):
    with Session() as db:
        db.query(FolderCredentialRow).filter_by(path=path).delete()
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
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Name already exists")
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
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Name already exists")
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
        c_shell_type = cmd.shell_type or "cmd"

    def stream():
        if s_type == "ssh":
            yield from _ssh_stream(s_host, s_port, c_user, c_pass, c_key, c_command)
        elif s_type == "winrm":
            yield from _winrm_stream(s_host, s_port, c_user, c_pass, c_command, c_shell_type)
        else:
            yield _sse({"type": "error", "text": f"Unknown server type: {s_type}"})
            yield _sse({"type": "done"})

    return StreamingResponse(stream(), media_type="text/event-stream")


# ── Health & static ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
