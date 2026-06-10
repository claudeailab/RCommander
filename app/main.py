import asyncio
import io
import json
import os
import secrets
import time
from typing import Literal, Optional

import paramiko
import winrm
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response, StreamingResponse
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
    vnc_dsm_file_id = Column(Integer, nullable=True)
    vnc_client_key_file_id = Column(Integer, nullable=True)


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


class VncFileRow(Base):
    __tablename__ = "vnc_files"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    file_type = Column(String, nullable=False, default="other")  # dsm | client_key | server_pubkey | other
    original_name = Column(String, nullable=False)
    description = Column(Text, default="")


Base.metadata.create_all(engine)

VNC_FILES_DIR = "/data/vnc-files"
os.makedirs(VNC_FILES_DIR, exist_ok=True)


def _migrate():
    """Add columns introduced after initial release without dropping existing data."""
    migrations = {
        "servers":     [("description",           "TEXT NOT NULL DEFAULT ''"),
                        ("credential_id",          "INTEGER"),
                        ("server_group",           "TEXT NOT NULL DEFAULT ''"),
                        ("vnc_dsm_file_id",        "INTEGER"),
                        ("vnc_client_key_file_id", "INTEGER")],
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

APP_VERSION = "1.6.3"

# ── VNC session store (short-lived, in-memory) ────────────────────────────────
_vnc_sessions: dict = {}


def _prune_vnc_sessions() -> None:
    cutoff = time.time() - 300  # 5-minute TTL
    for k in [k for k, v in _vnc_sessions.items() if v["ts"] < cutoff]:
        del _vnc_sessions[k]


_VNC_PAGE_TMPL = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VNC — %%NAME%%</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #000; display: flex; flex-direction: column; height: 100vh; font-family: system-ui, sans-serif; }
#bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; display: flex; align-items: center; gap: 10px; flex-shrink: 0; color: #e6edf3; font-size: 13px; }
#status { margin-left: auto; font-size: 12px; }
#vnc { flex: 1; overflow: hidden; }
#vnc > div, #vnc canvas { width: 100% !important; height: 100% !important; }
</style>
</head>
<body>
<div id="bar">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2">
    <rect x="2" y="3" width="20" height="14" rx="2"/>
    <line x1="8" y1="21" x2="16" y2="21"/>
    <line x1="12" y1="17" x2="12" y2="21"/>
  </svg>
  VNC — %%NAME%%
  <span id="status" style="color:#8b949e">Connecting…</span>
</div>
<div id="vnc"><div id="t"></div></div>
<script type="module">
import RFB from 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/core/rfb.js';
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const url = proto + '://' + location.host + '/ws/vnc/%%TOKEN%%';
const rfb = new RFB(document.getElementById('t'), url, { credentials: { password: %%PW%% } });
rfb.scaleViewport = true;
rfb.resizeSession = true;
rfb.addEventListener('connect', () => {
  const s = document.getElementById('status');
  s.textContent = 'Connected'; s.style.color = '#3fb950';
});
rfb.addEventListener('disconnect', ev => {
  const s = document.getElementById('status');
  s.textContent = ev.detail.clean ? 'Disconnected' : 'Connection lost';
  s.style.color = '#f85149';
});
rfb.addEventListener('credentialsrequired', () => {
  rfb.sendCredentials({ password: prompt('VNC Password:') || '' });
});
</script>
</body>
</html>"""


def _vnc_page(token: str, name: str, password: str) -> str:
    safe = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        _VNC_PAGE_TMPL
        .replace("%%TOKEN%%", token)
        .replace("%%PW%%", json.dumps(password))
        .replace("%%NAME%%", safe)
    )


# ── SSH session store ──────────────────────────────────────────────────────────
_ssh_sessions: dict = {}

def _prune_ssh_sessions() -> None:
    cutoff = time.time() - 300
    for k in [k for k, v in _ssh_sessions.items() if v["ts"] < cutoff]:
        del _ssh_sessions[k]

def _load_private_key_for_session(key_str: str):
    import io
    for cls in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
        try:
            return cls.from_private_key(io.StringIO(key_str))
        except Exception:
            continue
    return None


# ── RDP session store (short-lived, in-memory) ────────────────────────────────
_rdp_sessions: dict = {}


def _prune_rdp_sessions() -> None:
    cutoff = time.time() - 300
    for k in [k for k, v in _rdp_sessions.items() if v["ts"] < cutoff]:
        del _rdp_sessions[k]


def _guac_encode(opcode: str, *args) -> str:
    """Encode a Guacamole protocol instruction."""
    parts = [str(opcode)] + [str(a) for a in args]
    return ",".join(f"{len(p)}.{p}" for p in parts) + ";"


def _guac_parse_instr(instr: str) -> list:
    """Parse a Guacamole instruction into a list of string elements."""
    elements = []
    s = instr.rstrip(";")
    i = 0
    while i < len(s):
        dot = s.index(".", i)
        length = int(s[i:dot])
        value = s[dot + 1:dot + 1 + length]
        elements.append(value)
        i = dot + 1 + length
        if i < len(s) and s[i] == ",":
            i += 1
    return elements


async def _guac_read_instr(reader: asyncio.StreamReader) -> str:
    """Read one complete Guacamole instruction (up to and including ';')."""
    data = await reader.readuntil(b";")
    return data.decode("utf-8", errors="replace")


async def _guac_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session: dict) -> str:
    """Negotiate an RDP connection with guacd. Returns the ready instruction to forward to the browser."""
    host_label = f"{session['host']}:{session['port']}"
    writer.write(_guac_encode("select", "rdp").encode())
    await writer.drain()

    args_instr = await _guac_read_instr(reader)
    elements = _guac_parse_instr(args_instr)
    param_names = elements[1:]  # first element is opcode "args"
    print(f"[RDP {host_label}] guacd args ({len(param_names)}): {param_names}")

    writer.write(_guac_encode("size", "1280", "800", "96").encode())
    writer.write(_guac_encode("audio").encode())
    writer.write(_guac_encode("video").encode())
    writer.write(_guac_encode("image", "image/png", "image/jpeg").encode())
    writer.write(_guac_encode("timezone", "UTC").encode())
    await writer.drain()

    rdp_defaults: dict = {
        "hostname": session["host"],
        "port": str(session["port"]),
        "username": session["username"],
        "password": session["password"],
        "width": "1280",
        "height": "800",
        "dpi": "96",
        "color-depth": "32",
        "security": session.get("rdp_security", "nla"),
        "ignore-cert": "true",
        "client-name": "rcommander",
        "console": "true" if session.get("rdp_console") else "false",
        "timezone": "UTC",
        "disable-audio": "true",
        "disable-auth": "false",
        "enable-font-smoothing": "false",
        "enable-wallpaper": "true",
        "enable-theming": "true",
        "enable-full-window-drag": "false",
        "enable-desktop-composition": "true",
        "enable-menu-animations": "false",
        "disable-bitmap-caching": "false",
        "disable-offscreen-caching": "false",
        "disable-glyph-caching": "false",
        "resize-method": "display-update",
        "cursor": "local",
    }
    # Send "" for VERSION_* slots — guacd uses legacy-compatible mode which works reliably
    connect_args = [rdp_defaults.get(p, "") for p in param_names]
    print(f"[RDP {host_label}] connecting with security={rdp_defaults['security']} console={rdp_defaults['console']} user={rdp_defaults['username']!r}")
    writer.write(_guac_encode("connect", *connect_args).encode())
    await writer.drain()

    # Read guacd's response — either "ready" (success) or "error" (failure)
    response = await asyncio.wait_for(_guac_read_instr(reader), timeout=15)
    parts = _guac_parse_instr(response)
    print(f"[RDP {host_label}] guacd response: {response[:120]!r}")
    if parts and parts[0] == "error":
        msg = parts[1] if len(parts) > 1 else "unknown error"
        raise RuntimeError(f"guacd: {msg}")
    return response  # "ready" instruction; caller must forward to browser


_SSH_PAGE_TMPL = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SSH — %%NAME%%</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; display:flex; flex-direction:column; height:100vh; overflow:hidden; }
#bar { background:#161b22; border-bottom:1px solid #30363d; padding:8px 16px; display:flex; align-items:center; gap:10px; flex-shrink:0; color:#e6edf3; font-size:13px; }
#status { margin-left:auto; font-size:12px; color:#8b949e; }
#terminal { flex:1; overflow:hidden; padding:4px; }
</style>
</head>
<body>
<div id="bar">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
  SSH — %%NAME%%
  <span id="status">Connecting…</span>
</div>
<div id="terminal"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
const status = document.getElementById('status');
const term = new Terminal({ cursorBlink:true, fontSize:14, fontFamily:'Menlo,Monaco,"Courier New",monospace', theme:{background:'#0d1117',foreground:'#e6edf3',cursor:'#58a6ff'} });
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal'));
fitAddon.fit();
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(proto + '://' + location.host + '/ws/ssh/%%TOKEN%%');
ws.onopen = function() { status.textContent='Connected'; status.style.color='#3fb950'; sendResize(); };
ws.onclose = function() { status.textContent='Disconnected'; status.style.color='#f85149'; term.write('\\r\\n\\r\\n\\x1b[1;31mConnection closed.\\x1b[0m\\r\\n'); };
ws.onerror = function() { status.textContent='Error'; status.style.color='#f85149'; };
ws.onmessage = function(e) { term.write(e.data); };
term.onData(function(data) { if (ws.readyState===WebSocket.OPEN) ws.send(data); });
function sendResize() { if (ws.readyState===WebSocket.OPEN) ws.send(JSON.stringify({type:'resize',cols:term.cols,rows:term.rows})); }
window.addEventListener('resize', function() { fitAddon.fit(); sendResize(); });
term.onResize(function() { sendResize(); });
</script>
</body>
</html>"""

def _ssh_page(token: str, name: str) -> str:
    safe = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _SSH_PAGE_TMPL.replace("%%TOKEN%%", token).replace("%%NAME%%", safe)


_RDP_PAGE_TMPL = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RDP — %%NAME%%</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#000; display:flex; flex-direction:column; height:100vh; font-family:system-ui,sans-serif; overflow:hidden; }
#bar { background:#161b22; border-bottom:1px solid #30363d; padding:8px 16px; display:flex; align-items:center; gap:10px; flex-shrink:0; color:#e6edf3; font-size:13px; }
#status { margin-left:auto; font-size:12px; color:#8b949e; }
#display { flex:1; overflow:hidden; position:relative; cursor:none; }
#display > div { position:absolute; top:0; left:0; }
</style>
</head>
<body>
<div id="bar">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2">
    <rect x="2" y="3" width="20" height="14" rx="2"/>
    <line x1="8" y1="21" x2="16" y2="21"/>
    <line x1="12" y1="17" x2="12" y2="21"/>
  </svg>
  RDP — %%NAME%%
  <span id="status">Connecting…</span>
</div>
<div id="display"></div>
<script type="module">
(async function() {
  const status = document.getElementById('status');
  let Guacamole;
  try {
    const mod = await import('/guacamole-common.js');
    Guacamole = mod.default;
    if (!Guacamole || !Guacamole.WebSocketTunnel) throw new Error('Guacamole.WebSocketTunnel not found in module');
  } catch(e) {
    status.textContent = 'Library error: ' + e.message;
    status.style.color = '#f85149';
    return;
  }
  try {
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    var wsUrl = proto + '://' + location.host + '/ws/rdp/%%TOKEN%%';

    var tunnel = new Guacamole.WebSocketTunnel(wsUrl);
    var client = new Guacamole.Client(tunnel);

    var displayDiv = document.getElementById('display');
    var displayEl = client.getDisplay().getElement();
    displayDiv.appendChild(displayEl);

    client.onerror = function(err) {
      status.textContent = 'Error: ' + (err.message || 'Connection failed');
      status.style.color = '#f85149';
    };

    tunnel.onstatechange = function(state) {
      if (state === Guacamole.Tunnel.State.OPEN) {
        status.textContent = 'Connected';
        status.style.color = '#3fb950';
        scaleDisplay();
        // After 3s the desktop is fully loaded — resize to actual window dimensions
        // to force Windows to repaint the full screen (fixes incomplete background)
        setTimeout(function() {
          var w = displayDiv.clientWidth || 1280;
          var h = displayDiv.clientHeight || 800;
          if (w !== 1280 || h !== 800) { client.sendSize(w, h); }
        }, 3000);
      } else if (state === Guacamole.Tunnel.State.CLOSED) {
        if (status.style.color !== 'rgb(248, 81, 73)') {
          status.textContent = 'Disconnected';
          status.style.color = '#f85149';
        }
      }
    };

    client.connect();
    window.onunload = function() { client.disconnect(); };

    var display = client.getDisplay();
    display.showCursor(true);
    displayEl.addEventListener('contextmenu', function(e) { e.preventDefault(); });
    var mouse = new Guacamole.Mouse(displayEl);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = function(mouseState) {
      client.sendMouseState(mouseState);
    };

    var keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = function(keysym) { client.sendKeyEvent(1, keysym); };
    keyboard.onkeyup = function(keysym) { client.sendKeyEvent(0, keysym); };

    function scaleDisplay() {
      var w = displayDiv.clientWidth;
      var h = displayDiv.clientHeight;
      var dw = display.getWidth();
      var dh = display.getHeight();
      if (dw && dh) {
        display.scale(Math.min(w / dw, h / dh));
      }
    }
    window.addEventListener('resize', scaleDisplay);
    display.onresize = scaleDisplay;
  } catch(e) {
    status.textContent = 'JS error: ' + e.message;
    status.style.color = '#f85149';
  }
})();
</script>
</body>
</html>"""


def _rdp_page(token: str, name: str) -> str:
    safe = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _RDP_PAGE_TMPL.replace("%%TOKEN%%", token).replace("%%NAME%%", safe)


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
    vnc_dsm_file_id: Optional[int] = None
    vnc_client_key_file_id: Optional[int] = None


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

# ── Remote Access ─────────────────────────────────────────────────────────────

class VncSessionIn(BaseModel):
    server_id: int
    credential_id: int
    port: int = 5900


class SshSessionIn(BaseModel):
    server_id: int
    credential_id: int
    port: int = 22


class RdpSessionIn(BaseModel):
    server_id: int
    credential_id: int
    port: int = 3389
    rdp_security: str = "nla"
    rdp_console: bool = False
    width: int = 1280
    height: int = 800


@app.post("/api/vnc-session")
def create_vnc_session(data: VncSessionIn):
    _prune_vnc_sessions()
    with Session() as db:
        server = db.get(ServerRow, data.server_id)
        cred = db.get(CredentialRow, data.credential_id)
        if not server or not cred:
            raise HTTPException(404, "Server or credential not found")
        token = secrets.token_urlsafe(16)
        _vnc_sessions[token] = {
            "host": server.host,
            "port": data.port,
            "password": cred.password or "",
            "name": server.name,
            "ts": time.time(),
        }
    return {"token": token}


@app.get("/vnc/{token}", response_class=HTMLResponse)
def vnc_session_page(token: str):
    session = _vnc_sessions.get(token)
    if not session:
        return HTMLResponse("<h1 style='font-family:sans-serif;padding:2rem'>Session expired or not found.</h1>", status_code=404)
    return HTMLResponse(_vnc_page(token, session["name"], session["password"]))


@app.websocket("/ws/vnc/{token}")
async def vnc_ws_proxy(websocket: WebSocket, token: str):
    session = _vnc_sessions.pop(token, None)
    if not session:
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="binary")

    try:
        reader, writer = await asyncio.open_connection(session["host"], session["port"])
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
        return

    async def ws_to_tcp():
        try:
            while True:
                data = await websocket.receive_bytes()
                writer.write(data)
                await writer.drain()
        except Exception:
            pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send_bytes(data)
        except Exception:
            pass

    tasks = [asyncio.ensure_future(ws_to_tcp()), asyncio.ensure_future(tcp_to_ws())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    writer.close()
    try:
        await websocket.close()
    except Exception:
        pass


@app.post("/api/rdp-session")
def create_rdp_session(data: RdpSessionIn):
    _prune_rdp_sessions()
    with Session() as db:
        server = db.get(ServerRow, data.server_id)
        cred = db.get(CredentialRow, data.credential_id) if data.credential_id else None
        if not server:
            raise HTTPException(404, "Server not found")
        token = secrets.token_urlsafe(16)
        _rdp_sessions[token] = {
            "host": server.host,
            "port": data.port,
            "username": cred.username if cred else "",
            "password": cred.password if cred else "",
            "rdp_security": data.rdp_security,
            "rdp_console": data.rdp_console,
            "width": data.width,
            "height": data.height,
            "name": server.name,
            "ts": time.time(),
        }
    return {"token": token}


@app.get("/rdp/{token}", response_class=HTMLResponse)
def rdp_session_page(token: str):
    session = _rdp_sessions.get(token)
    if not session:
        return HTMLResponse("<h1 style='font-family:sans-serif;padding:2rem'>Session expired or not found.</h1>", status_code=404)
    return HTMLResponse(_rdp_page(token, session["name"]))


@app.websocket("/ws/rdp/{token}")
async def rdp_ws_proxy(websocket: WebSocket, token: str):
    session = _rdp_sessions.get(token)
    if not session:
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="guacamole")

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 4822)
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
        return

    try:
        ready_instr = await _guac_handshake(reader, writer, session)
        await websocket.send_text(ready_instr)
    except Exception as e:
        err_instr = _guac_encode("error", str(e), "516")
        try:
            await websocket.send_text(err_instr)
        except Exception:
            pass
        writer.close()
        try:
            await websocket.close()
        except Exception:
            pass
        return

    host_label = f"{session['host']}:{session['port']}"

    async def ws_to_tcp():
        try:
            while True:
                msg = await websocket.receive_text()
                writer.write(msg.encode())
                await writer.drain()
        except Exception:
            pass

    async def tcp_to_ws():
        chunks = 0
        total = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    print(f"[RDP {host_label}] guacd closed after {chunks} chunks / {total} bytes")
                    break
                chunks += 1
                total += len(data)
                if chunks <= 3:
                    print(f"[RDP {host_label}] chunk #{chunks}: {len(data)} bytes | preview: {data[:80]!r}")
                await websocket.send_text(data.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"[RDP {host_label}] proxy error after {chunks} chunks: {e}")

    tasks = [asyncio.ensure_future(ws_to_tcp()), asyncio.ensure_future(tcp_to_ws())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    writer.close()
    try:
        await websocket.close()
    except Exception:
        pass


def _open_ssh_channel(client: paramiko.SSHClient):
    ch = client.invoke_shell(term="xterm-256color", width=220, height=50)
    ch.settimeout(0.1)
    return ch

def _read_ssh_channel(channel) -> bytes | None:
    import socket
    try:
        data = channel.recv(4096)
        return data if data else None
    except socket.timeout:
        return b""
    except Exception:
        return None


@app.post("/api/ssh-session")
def create_ssh_session(data: SshSessionIn):
    _prune_ssh_sessions()
    with Session() as db:
        server = db.get(ServerRow, data.server_id)
        cred = db.get(CredentialRow, data.credential_id) if data.credential_id else None
        if not server:
            raise HTTPException(404, "Server not found")
        token = secrets.token_urlsafe(16)
        _ssh_sessions[token] = {
            "host": server.host,
            "port": data.port,
            "username": cred.username if cred else "",
            "password": cred.password if cred else "",
            "private_key": cred.private_key if cred else "",
            "name": server.name,
            "ts": time.time(),
        }
    return {"token": token}


@app.get("/ssh/{token}", response_class=HTMLResponse)
def ssh_session_page(token: str):
    session = _ssh_sessions.get(token)
    if not session:
        return HTMLResponse("<h3>Session expired or not found</h3>", status_code=404)
    return HTMLResponse(_ssh_page(token, session["name"]))


@app.websocket("/ws/ssh/{token}")
async def ssh_ws_proxy(websocket: WebSocket, token: str):
    session = _ssh_sessions.get(token)
    if not session:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    loop = asyncio.get_event_loop()
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pkey = await loop.run_in_executor(None, lambda: _load_private_key_for_session(session["private_key"]) if session.get("private_key") else None)
        await loop.run_in_executor(None, lambda: ssh_client.connect(
            hostname=session["host"], port=session["port"],
            username=session["username"],
            password=session["password"] or None,
            pkey=pkey, timeout=10, look_for_keys=False, allow_agent=False,
        ))
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n\033[1;31mSSH connection failed: {e}\033[0m\r\n")
            await websocket.close()
        except Exception:
            pass
        return
    channel = await loop.run_in_executor(None, lambda: _open_ssh_channel(ssh_client))

    async def ws_to_ssh():
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "resize":
                        channel.resize_pty(width=int(msg.get("cols", 80)), height=int(msg.get("rows", 24)))
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass
                channel.send(data.encode("utf-8"))
        except Exception:
            pass

    async def ssh_to_ws():
        try:
            while True:
                data = await loop.run_in_executor(None, lambda: _read_ssh_channel(channel))
                if data is None:
                    break
                await websocket.send_text(data.decode("utf-8", errors="replace"))
        except Exception:
            pass

    tasks = [asyncio.ensure_future(ws_to_ssh()), asyncio.ensure_future(ssh_to_ws())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    try:
        channel.close()
    except Exception:
        pass
    ssh_client.close()
    try:
        await websocket.close()
    except Exception:
        pass


# ── VNC Files ─────────────────────────────────────────────────────────────────

@app.post("/api/vnc-files", status_code=201)
async def upload_vnc_file(
    name: str = Form(...),
    file_type: str = Form("other"),
    description: str = Form(""),
    file: UploadFile = File(...),
):
    content = await file.read()
    with Session() as db:
        row = VncFileRow(
            name=name,
            file_type=file_type,
            original_name=file.filename or name,
            description=description,
        )
        db.add(row)
        try:
            db.commit()
            db.refresh(row)
        except Exception:
            db.rollback()
            raise HTTPException(409, "Name already exists")
        dest = os.path.join(VNC_FILES_DIR, f"{row.id}.bin")
        with open(dest, "wb") as f:
            f.write(content)
        return {c.name: getattr(row, c.name) for c in row.__table__.columns}


@app.get("/api/vnc-files")
def list_vnc_files():
    with Session() as db:
        return [{c.name: getattr(r, c.name) for c in r.__table__.columns}
                for r in db.query(VncFileRow).order_by(VncFileRow.name).all()]


@app.delete("/api/vnc-files/{file_id}", status_code=204)
def delete_vnc_file(file_id: int):
    with Session() as db:
        row = db.get(VncFileRow, file_id)
        if not row:
            raise HTTPException(404, "Not found")
        db.delete(row)
        db.commit()
    path = os.path.join(VNC_FILES_DIR, f"{file_id}.bin")
    if os.path.exists(path):
        os.remove(path)


# ── Health & static ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
