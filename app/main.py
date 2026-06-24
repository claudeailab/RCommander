import asyncio
import hashlib
import io
import json
import os
import secrets
import socket
import time
from typing import Literal, Optional

import paramiko
import winrm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import OFB as _OFB  # type: ignore[assignment]
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
    remote_access_credential_id = Column(Integer, nullable=True)
    server_group = Column(String, default="")
    vnc_dsm_file_id = Column(Integer, nullable=True)
    vnc_client_key_file_id = Column(Integer, nullable=True)
    connection_types = Column(String, default="")


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
    credential_id = Column(Integer, nullable=True)
    remote_access_credential_id = Column(Integer, nullable=True)
    connection_types = Column(String, default="")
    vnc_dsm_file_id = Column(Integer, nullable=True)
    vnc_client_key_file_id = Column(Integer, nullable=True)


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
        "servers":            [("description",                   "TEXT NOT NULL DEFAULT ''"),
                               ("credential_id",                  "INTEGER"),
                               ("remote_access_credential_id",    "INTEGER"),
                               ("server_group",                   "TEXT NOT NULL DEFAULT ''"),
                               ("vnc_dsm_file_id",                "INTEGER"),
                               ("vnc_client_key_file_id",         "INTEGER"),
                               ("connection_types",               "TEXT NOT NULL DEFAULT ''")],
        "credentials":        [("description",   "TEXT NOT NULL DEFAULT ''")],
        "commands":           [("description",   "TEXT NOT NULL DEFAULT ''"),
                               ("server_id",     "INTEGER"),
                               ("shell_type",    "TEXT NOT NULL DEFAULT 'cmd'")],
        "folder_credentials": [("remote_access_credential_id",    "INTEGER"),
                               ("connection_types",               "TEXT NOT NULL DEFAULT ''"),
                               ("vnc_dsm_file_id",                "INTEGER"),
                               ("vnc_client_key_file_id",         "INTEGER")],
    }
    with engine.connect() as conn:
        for table, columns in migrations.items():
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            for column, col_def in columns:
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
        conn.commit()


_migrate()

APP_VERSION = "1.6.88"

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
#disc-btn { background:none; border:1px solid #da3633; color:#da3633; border-radius:5px; padding:3px 12px; font-size:12px; cursor:pointer; font-weight:600; }
#disc-btn:hover { background:rgba(218,54,51,.15); }
#vnc { flex: 1; overflow: hidden; position: relative; }
#vnc > div { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
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
  <span id="status" style="color:#8b949e">Loading…</span>
  <button id="cad-btn" style="background:none;border:1px solid #444;color:#ccc;border-radius:5px;padding:3px 10px;font-size:12px;cursor:pointer" onclick="window._vncCad && window._vncCad()" title="Send Ctrl+Alt+Del">Ctrl+Alt+Del</button>
  <button id="disc-btn" onclick="window._vncDisconnect && window._vncDisconnect()">Disconnect</button>
</div>
<div id="vnc"><div id="t"></div></div>
<script type="module">
const setStatus = (text, color) => {
  const s = document.getElementById('status');
  s.textContent = text; s.style.color = color || '#8b949e';
};
window.addEventListener('unhandledrejection', ev => {
  setStatus('Error: ' + (ev.reason?.message || ev.reason), '#f85149');
});
try {
  setStatus('Loading noVNC…');
  const { default: RFB } = await import('/novnc-core/rfb.js');
  setStatus('Connecting…');
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = proto + '://' + location.host + '/ws/vnc/%%TOKEN%%';
  const rfb = new RFB(document.getElementById('t'), url, { credentials: { password: %%PW%% } });
  rfb.scaleViewport = true;
  rfb.resizeSession = true;
  rfb.qualityLevel = 6;
  rfb.compressionLevel = 2;
  rfb.addEventListener('connect', () => setStatus('Connected', '#3fb950'));
  rfb.addEventListener('disconnect', ev => {
    const reason = ev.detail.reason || '';
    setStatus(ev.detail.clean ? 'Disconnected' : ('Connection lost' + (reason ? ': ' + reason : '')), '#f85149');
    console.error('[VNC] disconnect', ev.detail);
  });
  rfb.addEventListener('credentialsrequired', () => {
    rfb.sendCredentials({ password: prompt('VNC Password:') || '' });
  });
  rfb.addEventListener('securityfailure', ev => {
    setStatus('Auth failed: ' + (ev.detail.reason || ev.detail.status), '#f85149');
    console.error('[VNC] securityfailure', ev.detail);
  });
  window._vncCad = function() { try { rfb.sendCtrlAltDel(); } catch(_) {} };
  window._vncDisconnect = function() { try { rfb.disconnect(); } catch(_) {} window.close(); };
} catch(e) {
  setStatus('Failed to load: ' + e.message, '#f85149');
  console.error('[VNC] init error', e);
}
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


def _guac_last_instr_end(buf: bytes) -> int:
    """Return the byte index of the ';' that ends the last complete Guacamole
    instruction in *buf*, or -1 if *buf* contains no complete instruction.

    Parses the LENGTH.VALUE structure so that a ';' that appears inside a
    value (e.g. clipboard text) is never mistaken for an instruction boundary.
    """
    pos = 0
    last_end = -1
    n = len(buf)
    while pos < n:
        p = pos
        while True:
            dot = buf.find(b".", p)
            if dot == -1:
                return last_end
            length_bytes = buf[p:dot]
            try:
                length = int(length_bytes)
            except ValueError:
                return last_end
            val_end = dot + 1 + length
            if val_end >= n:
                return last_end
            term = buf[val_end]
            if term == 0x3B:   # ord(";")
                last_end = val_end
                pos = val_end + 1
                break
            elif term == 0x2C:  # ord(",")
                p = val_end + 1
            else:
                return last_end
    return last_end


async def _guac_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session: dict) -> str:
    """Negotiate an RDP connection with guacd. Returns the ready instruction to forward to the browser."""
    host_label = f"{session['host']}:{session['port']}"
    writer.write(_guac_encode("select", "rdp").encode())
    await writer.drain()

    args_instr = await _guac_read_instr(reader)
    elements = _guac_parse_instr(args_instr)
    param_names = elements[1:]  # first element is opcode "args"
    print(f"[RDP {host_label}] guacd args ({len(param_names)}): {param_names}")

    w = str(session.get("width", 1280))
    h = str(session.get("height", 800))
    dpi = str(session.get("dpi", 96))
    writer.write(_guac_encode("size", w, h, dpi).encode())
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
        "width": str(session.get("width", 1280)),
        "height": str(session.get("height", 800)),
        "dpi": str(session.get("dpi", 96)),
        "color-depth": str(session.get("color_depth", 32)),
        "security": session.get("rdp_security", "any"),
        "ignore-cert": "true",
        "client-name": "rcommander",
        "console": "true" if session.get("rdp_console") else "false",
        "timezone": "UTC",
        "disable-audio": "true" if session.get("disable_audio", True) else "false",
        "disable-auth": "false",
        "enable-font-smoothing": "true" if session.get("enable_font_smoothing", False) else "false",
        "enable-wallpaper": "true" if session.get("enable_wallpaper", True) else "false",
        "enable-theming": "true",
        "enable-full-window-drag": "false",
        "enable-desktop-composition": "true" if session.get("enable_desktop_composition", True) else "false",
        "enable-menu-animations": "false",
        "disable-bitmap-caching": "true",
        "disable-offscreen-caching": "true",
        "disable-glyph-caching": "true",
        "resize-method": session.get("resize_method", "display-update"),
        "cursor": session.get("cursor", "local"),
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
#disc-btn { background:none; border:1px solid #da3633; color:#da3633; border-radius:5px; padding:3px 12px; font-size:12px; cursor:pointer; font-weight:600; }
#disc-btn:hover { background:rgba(218,54,51,.15); }
#terminal { flex:1; overflow:hidden; padding:4px; }
</style>
</head>
<body>
<div id="bar">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
  SSH — %%NAME%%
  <span id="status">Connecting…</span>
  <button id="disc-btn" onclick="ws && ws.close(); window.close()">Disconnect</button>
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
#disc-btn { background:none; border:1px solid #da3633; color:#da3633; border-radius:5px; padding:3px 12px; font-size:12px; cursor:pointer; font-weight:600; }
#disc-btn:hover { background:rgba(218,54,51,.15); }
#display { flex:1; overflow:hidden; position:relative; cursor:none; }
#display > div { position:absolute !important; top:0 !important; left:0 !important; overflow:hidden; }
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
  <button id="disc-btn" onclick="window._rdpDisconnect && window._rdpDisconnect()">Disconnect</button>
</div>
<div id="display"></div>
<script type="module">
(async function() {
  var status = document.getElementById('status');
  var displayDiv = document.getElementById('display');

  var Guacamole;
  try {
    var mod = await import('/guacamole-common.js');
    Guacamole = mod.default;
    if (!Guacamole || !Guacamole.WebSocketTunnel) throw new Error('Guacamole.WebSocketTunnel not found');
  } catch(e) {
    status.textContent = 'Library error: ' + e.message;
    status.style.color = '#f85149';
    return;
  }

  // Use the actual display-area dimensions so guacd negotiates the right resolution
  // with Windows from the start — avoids the GDI partial-paint / missing-background issue
  var initW = displayDiv.offsetWidth  || window.innerWidth  || 1280;
  var initH = displayDiv.offsetHeight || (window.innerHeight - document.getElementById('bar').offsetHeight) || 800;

  try {
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    var wsUrl = proto + '://' + location.host + '/ws/rdp/%%TOKEN%%?w=' + initW + '&h=' + initH;

    var tunnel = new Guacamole.WebSocketTunnel(wsUrl);
    var client = new Guacamole.Client(tunnel);
    var display = client.getDisplay();
    var displayEl = display.getElement();
    displayDiv.appendChild(displayEl);

    window._rdpDisconnect = function() { try { client.disconnect(); } catch(_) {} window.close(); };
    window.onunload = function() { try { client.disconnect(); } catch(_) {} };

    client.onerror = function(err) {
      status.textContent = 'Error: ' + (err.message || 'Connection failed');
      status.style.color = '#f85149';
    };

    tunnel.onstatechange = function(state) {
      if (state === Guacamole.Tunnel.State.OPEN) {
        status.textContent = 'Connected';
        status.style.color = '#3fb950';
      } else if (state === Guacamole.Tunnel.State.CLOSED) {
        if (status.style.color !== 'rgb(248, 81, 73)') {
          status.textContent = 'Disconnected';
          status.style.color = '#f85149';
        }
      }
    };

    // Scale the display canvas to fit the container when guacd changes its size
    display.onresize = function() {
      var cw = displayDiv.clientWidth, ch = displayDiv.clientHeight;
      var dw = display.getWidth(),    dh = display.getHeight();
      if (cw && ch && dw && dh) display.scale(Math.min(cw / dw, ch / dh));
    };

    // On browser resize, tell guacd the new dimensions so Windows redraws at native size
    window.addEventListener('resize', function() {
      var w = displayDiv.clientWidth, h = displayDiv.clientHeight;
      if (w > 0 && h > 0) client.sendSize(w, h);
    });

    client.connect();

    display.showCursor(true);
    displayEl.addEventListener('contextmenu', function(e) { e.preventDefault(); });

    var mouse = new Guacamole.Mouse(displayEl);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = function(mouseState) {
      client.sendMouseState(mouseState);
    };

    var keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = function(keysym) { client.sendKeyEvent(1, keysym); };
    keyboard.onkeyup   = function(keysym) { client.sendKeyEvent(0, keysym); };

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
    remote_access_credential_id: Optional[int] = None
    server_group: str = ""
    vnc_dsm_file_id: Optional[int] = None
    vnc_client_key_file_id: Optional[int] = None
    connection_types: str = ""


class CredentialIn(BaseModel):
    name: str
    username: str = ""
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
    credential_id: Optional[int] = None
    remote_access_credential_id: Optional[int] = None
    connection_types: Optional[str] = None
    vnc_dsm_file_id: Optional[int] = None
    vnc_client_key_file_id: Optional[int] = None


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
        return [{"path": r.path, "credential_id": r.credential_id,
                 "remote_access_credential_id": r.remote_access_credential_id,
                 "connection_types": r.connection_types or "",
                 "vnc_dsm_file_id": r.vnc_dsm_file_id,
                 "vnc_client_key_file_id": r.vnc_client_key_file_id}
                for r in db.query(FolderCredentialRow).all()]


@app.put("/api/folder-credentials/{path:path}", status_code=200)
def set_folder_credential(path: str, data: FolderCredentialIn):
    ct = data.connection_types or ""
    with Session() as db:
        row = db.query(FolderCredentialRow).filter_by(path=path).first()
        nothing_set = (
            data.credential_id is None and
            data.remote_access_credential_id is None and
            not ct and
            data.vnc_dsm_file_id is None and
            data.vnc_client_key_file_id is None
        )
        if nothing_set:
            if row:
                db.delete(row)
                db.commit()
            return {"path": path, "credential_id": None, "remote_access_credential_id": None,
                    "connection_types": "", "vnc_dsm_file_id": None, "vnc_client_key_file_id": None}
        if row:
            row.credential_id = data.credential_id
            row.remote_access_credential_id = data.remote_access_credential_id
            row.connection_types = ct
            row.vnc_dsm_file_id = data.vnc_dsm_file_id
            row.vnc_client_key_file_id = data.vnc_client_key_file_id
        else:
            db.add(FolderCredentialRow(path=path, credential_id=data.credential_id,
                                       remote_access_credential_id=data.remote_access_credential_id,
                                       connection_types=ct,
                                       vnc_dsm_file_id=data.vnc_dsm_file_id,
                                       vnc_client_key_file_id=data.vnc_client_key_file_id))
        # Force-propagate: clear server-level overrides so every server in this
        # folder (and sub-folders) inherits the folder settings.
        for server in db.query(ServerRow).all():
            sg = server.server_group or ""
            if sg == path or sg.startswith(path + "/"):
                if data.credential_id is not None:
                    server.credential_id = None
                if data.remote_access_credential_id is not None:
                    server.remote_access_credential_id = None
                if ct:
                    server.connection_types = ""
                if data.vnc_dsm_file_id is not None:
                    server.vnc_dsm_file_id = None
                if data.vnc_client_key_file_id is not None:
                    server.vnc_client_key_file_id = None
        db.commit()
    return {"path": path, "credential_id": data.credential_id,
            "remote_access_credential_id": data.remote_access_credential_id,
            "connection_types": ct,
            "vnc_dsm_file_id": data.vnc_dsm_file_id,
            "vnc_client_key_file_id": data.vnc_client_key_file_id}


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
    credential_id: Optional[int] = None
    port: int = 5900


class SshSessionIn(BaseModel):
    server_id: int
    credential_id: int
    port: int = 22


class RdpSessionIn(BaseModel):
    server_id: int
    credential_id: int
    port: int = 3389
    rdp_security: str = "any"
    rdp_console: bool = False
    width: int = 1280
    height: int = 800
    color_depth: int = 32
    disable_audio: bool = True
    enable_wallpaper: bool = True
    enable_font_smoothing: bool = False
    enable_desktop_composition: bool = True
    resize_method: str = "display-update"
    cursor: str = "local"
    dpi: int = 96


def _get_effective_vnc_client_key(server: "ServerRow", db) -> Optional[int]:
    if server.vnc_client_key_file_id:
        return server.vnc_client_key_file_id
    if server.server_group:
        parts = server.server_group.split("/")
        for i in range(len(parts), 0, -1):
            path = "/".join(parts[:i])
            fc = db.query(FolderCredentialRow).filter_by(path=path).first()
            if fc and fc.vnc_client_key_file_id:
                return fc.vnc_client_key_file_id
    return None


@app.post("/api/vnc-session")
def create_vnc_session(data: VncSessionIn):
    _prune_vnc_sessions()
    with Session() as db:
        server = db.get(ServerRow, data.server_id)
        if not server:
            raise HTTPException(404, "Server not found")
        cred = db.get(CredentialRow, data.credential_id) if data.credential_id else None
        # Resolve effective VNC client key for DSM
        client_key_id = _get_effective_vnc_client_key(server, db)
        client_key_path = None
        if client_key_id:
            p = os.path.join(VNC_FILES_DIR, f"{client_key_id}.bin")
            if os.path.exists(p):
                client_key_path = p
        token = secrets.token_urlsafe(16)
        _vnc_sessions[token] = {
            "host": server.host,
            "port": data.port,
            "password": cred.password or "" if cred else "",
            "name": server.name,
            "ts": time.time(),
            "client_key_path": client_key_path,
        }
    return {"token": token}


@app.get("/vnc/{token}", response_class=HTMLResponse)
def vnc_session_page(token: str):
    session = _vnc_sessions.get(token)
    if not session:
        return HTMLResponse("<h1 style='font-family:sans-serif;padding:2rem'>Session expired or not found.</h1>", status_code=404)
    return HTMLResponse(_vnc_page(token, session["name"], session["password"]))


def _load_rsa_private_key(key_data: bytes):
    """Try every known format for loading an RSA private key."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    # 1. Standard PEM / DER (PKCS#1 or PKCS#8)
    for loader in [serialization.load_pem_private_key, serialization.load_der_private_key]:
        try:
            return loader(key_data, password=None)
        except Exception:
            pass

    # 2. DER with a non-zero byte offset (custom header up to 20 bytes)
    #    Some tools prepend file size, magic, or metadata before the DER SEQUENCE.
    for off in range(1, min(20, len(key_data))):
        if key_data[off] == 0x30:
            try:
                return serialization.load_der_private_key(key_data[off:], password=None)
            except Exception:
                pass

    # 3. Microsoft CryptoAPI PRIVATEKEYBLOB (bType=0x07 bVersion=0x02 magic=b'RSA2')
    try:
        if len(key_data) >= 20 and key_data[0] == 0x07 and key_data[1] == 0x02 and key_data[8:12] == b'RSA2':
            bitlen = int.from_bytes(key_data[12:16], 'little')
            pubexp = int.from_bytes(key_data[16:20], 'little')
            half = bitlen // 16
            ksize = bitlen // 8
            off = 20
            def _le(b): return int.from_bytes(b, 'little')
            n  = _le(key_data[off:off+ksize]); off += ksize
            p  = _le(key_data[off:off+half]);  off += half
            q  = _le(key_data[off:off+half]);  off += half
            dp = _le(key_data[off:off+half]);  off += half
            dq = _le(key_data[off:off+half]);  off += half
            qi = _le(key_data[off:off+half]);  off += half
            d  = _le(key_data[off:off+ksize])
            pub = RSAPublicNumbers(e=pubexp, n=n)
            priv = RSAPrivateNumbers(p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi, public_numbers=pub)
            return priv.private_key(default_backend())
    except Exception:
        pass

    # Nothing worked — log first 32 bytes so we can diagnose the format.
    print(f"[RSA] load failed: size={len(key_data)} "
          f"hex[0:32]={key_data[:32].hex()} "
          f"hex[0:4]={key_data[:4].hex()}")
    return None


def _vnc_des_response(password: str, challenge: bytes) -> bytes:
    """VNC DES challenge-response: bit-reversed key bytes, ECB mode."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography.hazmat.primitives.ciphers.algorithms import DES as _DES
        key = (password.encode("latin-1") + b"\x00" * 8)[:8]
        key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
        enc = Cipher(_DES(key), modes.ECB()).encryptor()
        return enc.update(challenge[:16]) + enc.finalize()
    except Exception as e:
        print(f"[VNC] DES unavailable ({e}) — VNC auth will fail")
        return b"\x00" * 16


class _DSMAuthFailure(Exception):
    """Raised when the VNC server returns SecurityResult != 0 for DSM type-17."""


def _arc4(key: bytes, data: bytes) -> bytes:
    """RC4 stream cipher (encrypt == decrypt)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = []
    i = j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)


def _parse_rsapubkey_ber(data: bytes):
    """
    Parse a BER/DER-encoded RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e })
    and return a cryptography public key object.  Accepts BER 0x10 SEQUENCE tag
    (used by UltraVNC SecureVNCPlugin2) as well as standard DER 0x30.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    buf = bytearray(data)
    if buf[0] in (0x10, 0x30):
        buf[0] = 0x30  # normalise to DER constructed SEQUENCE
    pos = 0
    if buf[pos] != 0x30:
        raise ValueError(f"Expected SEQUENCE tag, got 0x{buf[pos]:02x}")
    pos += 1
    if buf[pos] & 0x80:
        llen = buf[pos] & 0x7f
        pos += 1 + llen
    else:
        pos += 1
    # modulus
    if buf[pos] != 0x02:
        raise ValueError(f"Expected INTEGER for modulus, got 0x{buf[pos]:02x}")
    pos += 1
    if buf[pos] & 0x80:
        llen = buf[pos] & 0x7f
        n_len = int.from_bytes(buf[pos + 1:pos + 1 + llen], "big")
        pos += 1 + llen
    else:
        n_len = buf[pos]; pos += 1
    n = int.from_bytes(buf[pos:pos + n_len], "big")
    pos += n_len
    # exponent
    if buf[pos] != 0x02:
        raise ValueError(f"Expected INTEGER for exponent, got 0x{buf[pos]:02x}")
    pos += 1
    if buf[pos] & 0x80:
        llen = buf[pos] & 0x7f
        e_len = int.from_bytes(buf[pos + 1:pos + 1 + llen], "big")
        pos += 1 + llen
    else:
        e_len = buf[pos]; pos += 1
    e = int.from_bytes(buf[pos:pos + e_len], "big")
    return RSAPublicNumbers(e=e, n=n).public_key()


async def _launch_securevnc_helper(host: str, port: int, label: str,
                                    client_key_path: str = ""):
    """
    Launch ultravnc_dsm_helper in 'securevnc' mode as a local TCP proxy.
    The helper connects to host:port, performs the RSA/AES key exchange
    natively, and presents a plain (unencrypted) VNC stream on a local port.
    Returns (reader, writer, proc, keystore_symlink) — caller must
    proc.terminate() and optionally os.unlink(keystore_symlink) on cleanup.

    client_key_path: path to the ViewerClientAuth.pkey DER-encoded RSA private
    key.  The helper requires the keyfile name to END in 'ClientAuth.pkey' to
    trigger client authentication mode, so we create a per-session symlink with
    that suffix.
    """
    # Bind an ephemeral port to discover a free number, then release it.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        local_port = s.getsockname()[1]

    safe_host = host.replace(":", "_")

    # The helper uses the keyfile name suffix to determine auth mode:
    #   ends in 'ClientAuth.pkey'     → RSA client key authentication
    #   ends in 'ClientAuth.pkey.rsa' → client auth + server RSA keystore
    # We symlink the stored key to a temp path ending in 'ClientAuth.pkey'.
    keystore_symlink = f"/tmp/svnc_{safe_host}_{port}_{local_port}_ClientAuth.pkey"
    try:
        os.unlink(keystore_symlink)
    except FileNotFoundError:
        pass
    if client_key_path and os.path.exists(client_key_path):
        os.symlink(client_key_path, keystore_symlink)
        keystore = keystore_symlink
        print(f"[VNC {label}] DSM ClientAuth key: {client_key_path} → {keystore_symlink}")
    else:
        # No client key — run without a keystore; helper falls back to WARNING
        keystore = keystore_symlink  # non-existent path → no keystore
        print(f"[VNC {label}] DSM no client key — helper will warn and continue")

    # Strip DISPLAY/XAUTHORITY so that 'wish' (Tcl/Tk, installed with ssvnc)
    # fails immediately with "no display name" rather than blocking while
    # trying to connect to an unreachable X11 socket.
    env = {k: v for k, v in os.environ.items()
           if k not in ("DISPLAY", "XAUTHORITY")}
    env["ULTRAVNC_DSM_HELPER_NOIPV6"] = "1"

    proc = await asyncio.create_subprocess_exec(
        "/usr/lib/ssvnc/ultravnc_dsm_helper",
        "securevnc", keystore, str(local_port), f"{host}:{port}",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    # Retry connecting until the helper has bound the port (up to ~4 s).
    reader = writer = None
    for delay in (0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2):
        await asyncio.sleep(delay)
        if proc.returncode is not None:
            out_b, err_b = b"", b""
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            except Exception:
                pass
            raise RuntimeError(
                f"DSM helper exited early (rc={proc.returncode}) "
                f"stdout={out_b.decode(errors='replace')!r} "
                f"stderr={err_b.decode(errors='replace')!r}"
            )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
            break
        except OSError:
            pass
    if writer is None:
        proc.terminate()
        raise RuntimeError(f"DSM helper never bound :{local_port}")

    # Brief pause to let the helper complete its remote DSM exchange, then
    # drain any stderr it has printed (diagnostic).
    for _ in range(5):
        await asyncio.sleep(0.5)
        try:
            err_chunk = await asyncio.wait_for(proc.stderr.read(4096), timeout=0.05)
            if err_chunk:
                print(f"[VNC {label}] DSM helper: {err_chunk.decode(errors='replace')!r}")
        except (asyncio.TimeoutError, Exception):
            pass
        if proc.returncode is not None:
            out_b, err_b = b"", b""
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            except Exception:
                pass
            raise RuntimeError(
                f"DSM helper exited (rc={proc.returncode}) "
                f"stdout={out_b.decode(errors='replace')!r} "
                f"stderr={err_b.decode(errors='replace')!r}"
            )

    print(f"[VNC {label}] DSM helper ready :{local_port} → {host}:{port}")
    return reader, writer, proc, keystore_symlink


async def _server_rfb_handshake(reader, writer, client_key_path: str,
                                 password: str, label: str,
                                 dsm_exponent: int = 65537,
                                 dsm_reverse_modulus: bool = True,
                                 dsm_reverse_cipher: bool = False,
                                 dsm_raw_rsa: bool = False,
                                 dsm_force_sub_type: int = 0):
    """
    Full server-side RFB handshake.  Handles version exchange, security type
    selection (type 17 UltraVNC-DSM, type 1 None, type 2 VNC-auth) and reads
    the SecurityResult.  Returns (enc_ctx, dec_ctx) — both None for plain sessions.
    Raises ValueError on any failure that should abort the connection.
    """
    # --- version exchange ---
    sv = await asyncio.wait_for(reader.readexactly(12), timeout=30.0)
    if not sv.startswith(b"RFB "):
        raise ValueError(f"Expected RFB banner, got {sv!r}")
    try:
        srv_minor = int(sv[8:11])
    except Exception:
        srv_minor = 3
    writer.write(b"RFB 003.008\n")
    await writer.drain()
    print(f"[VNC {label}] Server RFB {sv[4:11].decode()}")

    enc_ctx = dec_ctx = None
    selected = 0

    if srv_minor <= 3:
        # RFB 3.3 — server chooses security type
        sec_data = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        selected = int.from_bytes(sec_data, "big")
        if selected == 0:
            rlen = int.from_bytes(await reader.readexactly(4), "big")
            reason = (await reader.readexactly(rlen)).decode(errors="replace")
            raise ValueError(f"Server refused: {reason}")
        if selected == 2:
            challenge = await asyncio.wait_for(reader.readexactly(16), timeout=5.0)
            writer.write(_vnc_des_response(password, challenge))
            await writer.drain()
        # RFB 3.3 has no SecurityResult
        print(f"[VNC {label}] Auth type {selected} (RFB 3.3)")
        return enc_ctx, dec_ctx, b""

    # RFB 3.7 / 3.8 — client selects from list
    num = (await asyncio.wait_for(reader.readexactly(1), timeout=5.0))[0]
    if num == 0:
        rlen = int.from_bytes(await reader.readexactly(4), "big")
        reason = (await reader.readexactly(rlen)).decode(errors="replace")
        raise ValueError(f"Server refused: {reason}")
    types = list(await asyncio.wait_for(reader.readexactly(num), timeout=5.0))
    print(f"[VNC {label}] Security types offered: {types}")

    if 17 in types and client_key_path:
        selected = 17
        writer.write(bytes([17]))
        await writer.drain()

        with open(client_key_path, "rb") as f:
            key_data = f.read()
        print(f"[VNC {label}] Key file: {client_key_path} size={len(key_data)} "
              f"magic={key_data[:4].hex() if len(key_data)>=4 else 'short'}")
        private_key = _load_rsa_private_key(key_data)
        if private_key is None:
            raise ValueError("Cannot load RSA private key")
        key_size = (private_key.key_size + 7) // 8

        # Drain the full server greeting (TCP may deliver it in multiple chunks).
        # Format: [caps/nonce(4)][sub_count(1)][sub_types(sub_count)]
        # Typical: ff ff ff ff 02 73 72  (7 bytes, but may arrive as 4 + 3)
        server_greeting = b""
        while len(server_greeting) < key_size:
            try:
                chunk = await asyncio.wait_for(reader.read(512), timeout=0.5)
                if not chunk:
                    break
                server_greeting += chunk
            except asyncio.TimeoutError:
                break   # no more data — greeting is complete
        print(f"[VNC {label}] Type-17 greeting: {len(server_greeting)}B "
              f"hex={server_greeting.hex()}")

        chosen = 0x72  # default: server sent key directly (pre-installed pubkey mode)
        if len(server_greeting) >= key_size:
            encrypted_key = server_greeting[:key_size]
            dsm_leftover_enc = server_greeting[key_size:]
            print(f"[VNC {label}] DSM: server sent key directly (pre-installed pubkey), "
                  f"leftover={len(dsm_leftover_enc)}B")
        else:
            # Parse greeting: [caps(4)][count(1)][sub_types(count)]
            sub_count = server_greeting[4] if len(server_greeting) >= 5 else 0
            sub_types = list(server_greeting[5:5 + sub_count]) if sub_count else []
            print(f"[VNC {label}] DSM: sub_types={[hex(t) for t in sub_types]}")

            # 0x73 = server sends its own RSA public key; client generates+encrypts AES key (Path B)
            # 0x72 = server encrypts AES key with our pre-configured public key (Path A)
            # dsm_force_sub_type overrides the selection when non-zero.
            if dsm_force_sub_type and dsm_force_sub_type in sub_types:
                chosen = dsm_force_sub_type
            elif dsm_force_sub_type:
                chosen = dsm_force_sub_type  # try forced type even if not listed
            elif 0x72 in sub_types:
                chosen = 0x72  # prefer 0x72: server uses our installed pubkey (Path A)
            elif 0x73 in sub_types:
                chosen = 0x73
            elif sub_types:
                chosen = sub_types[0]
            else:
                chosen = 0x72
            writer.write(bytes([chosen]))
            await writer.drain()
            print(f"[VNC {label}] DSM: sent sub-type 0x{chosen:02x}")

            dsm_leftover_enc = b""

            # Read server reply after sub-type selection.
            # For 0x73: server sends [22B plugin header][270B BER RSA pubkey][4B flags][42B challenge] = 338B.
            # For 0x72: server sends [22B header][key_size RSA-encrypted AES key][leftover].
            # Read in a loop until we have enough bytes or the server goes silent.
            after_sub = b""
            need = 340 if chosen == 0x73 else (22 + key_size)  # 22B hdr+256B mod+4B flags+~57B chal
            deadline = asyncio.get_event_loop().time() + 3.0
            while len(after_sub) < need and asyncio.get_event_loop().time() < deadline:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    if not chunk:
                        break
                    after_sub += chunk
                except asyncio.TimeoutError:
                    if after_sub:
                        break  # got some data; server has gone quiet
            print(f"[VNC {label}] DSM: server after sub-type 0x{chosen:02x}: "
                  f"{len(after_sub)}B hex={after_sub[:32].hex()}")

            if chosen == 0x73:
                # Sub-type 0x73: UltraVNC SecureVNCPlugin2 "server key" mode.
                if len(after_sub) < 283:  # need at least 22+256+4+1 bytes
                    raise ValueError(f"DSM 0x73: server reply too short ({len(after_sub)}B)")
                hdr22 = after_sub[:22]
                # Print diagnostic hex to determine the exact structure.
                print(f"[VNC {label}] DSM 0x73: total={len(after_sub)}B "
                      f"hdr={hdr22.hex()}")
                print(f"[VNC {label}] DSM 0x73: data[22:86]={after_sub[22:86].hex()}")
                print(f"[VNC {label}] DSM 0x73: data[-30:]={after_sub[-30:].hex()}")

                # Scan offsets 22-26 for a 256-byte big-endian value with odd LSB
                # (RSA moduli are always odd since they are products of two odd primes).
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
                server_pub = None
                raw_mod = b""
                flags4 = b""
                rc4_chal = b""
                for _off in range(22, 28):
                    if len(after_sub) < _off + 256 + 4 + 1:
                        continue
                    _cand = after_sub[_off:_off + 256]
                    _n = int.from_bytes(_cand, "big")
                    _odd = bool(_n & 1)
                    _msb = _cand[0]
                    print(f"[VNC {label}] DSM 0x73: try offset={_off} "
                          f"msb=0x{_msb:02x} lsb=0x{_cand[-1]:02x} odd={_odd}")
                    if _odd:
                        try:
                            server_pub = RSAPublicNumbers(e=65537, n=_n).public_key()
                            raw_mod = _cand
                            flags4 = after_sub[_off + 256:_off + 260]
                            rc4_chal = after_sub[_off + 260:]
                            print(f"[VNC {label}] DSM 0x73: using offset={_off} "
                                  f"key={server_pub.key_size}b flags={flags4.hex()} "
                                  f"challenge={len(rc4_chal)}B")
                            break
                        except Exception as _ke:
                            print(f"[VNC {label}] DSM 0x73: offset={_off} key err: {_ke}")
                            server_pub = None

                if server_pub is None:
                    raise ValueError(f"DSM 0x73: no valid RSA modulus found at offsets 22-27")

                # Derive RC4 key = SHA1(raw 256-byte server modulus).
                rc4_key = hashlib.sha1(raw_mod).digest()  # 20 bytes
                print(f"[VNC {label}] DSM 0x73: rc4_key={rc4_key.hex()} "
                      f"challenge_raw={rc4_chal.hex()}")

                # RC4-decrypt the challenge to recover the AES session key sent by the server.
                # Protocol: server RC4-encrypts its chosen AES key with key=SHA1(pubkey_bytes)
                # and puts it in the challenge. Client decrypts → RSA-encrypts back as proof.
                challenge_dec = _arc4(rc4_key, rc4_chal)
                print(f"[VNC {label}] DSM 0x73: challenge_dec={challenge_dec.hex()}")

                # AES-128 session key = first 16 bytes of decrypted challenge.
                aes_key_73 = challenge_dec[:16]
                aes_iv_73 = bytes(16)  # IV = all zeros

                # RSA-encrypt the AES key with the server's public key (PKCS#1 v1.5, BE).
                enc_aes_73 = server_pub.encrypt(aes_key_73, asym_padding.PKCS1v15())

                # Send: RSA-encrypted AES key + 3 null bytes (from binary analysis).
                writer.write(enc_aes_73 + b"\x00\x00\x00")
                await writer.drain()
                print(f"[VNC {label}] DSM 0x73: sent {len(enc_aes_73)}B RSA-encrypted AES key "
                      f"+ 3 null bytes; aes_key={aes_key_73.hex()} iv=zeros")

                # Set up AES-128-OFB cipher contexts.
                enc_ctx = Cipher(algorithms.AES(aes_key_73), _OFB(aes_iv_73)).encryptor()
                dec_ctx = Cipher(algorithms.AES(aes_key_73), _OFB(aes_iv_73)).decryptor()

                # Read SecurityResult (4 bytes) — plain RFB or AES-OFB encrypted.
                raw_sr73 = await asyncio.wait_for(reader.readexactly(4), timeout=8.0)
                dec_sr73 = dec_ctx.update(raw_sr73)
                sr73_plain = int.from_bytes(raw_sr73, "big")
                sr73_dec = int.from_bytes(dec_sr73, "big")
                print(f"[VNC {label}] DSM 0x73: SecurityResult raw={raw_sr73.hex()} "
                      f"plain={sr73_plain} aes_dec={sr73_dec}")
                if sr73_plain == 0 or sr73_dec == 0:
                    ok_via = "plain" if sr73_plain == 0 else "AES"
                    print(f"[VNC {label}] DSM 0x73: Auth OK! (SR=0 via {ok_via})")
                    return enc_ctx, dec_ctx, b""
                raise _DSMAuthFailure(
                    f"DSM 0x73: SR plain={sr73_plain} aes_dec={sr73_dec} — auth rejected"
                )

            if len(after_sub) >= key_size:
                # Response structure: [22-byte fixed header][key_size RSA ciphertext][leftover]
                hdr_size = 22
                encrypted_key = after_sub[hdr_size:hdr_size + key_size]
                dsm_leftover_enc = after_sub[hdr_size + key_size:]
                print(f"[VNC {label}] DSM: hdr={after_sub[:hdr_size].hex()} "
                      f"leftover_raw={dsm_leftover_enc.hex()}")
            else:
                # Send RSA public key as raw big-endian modulus (no DER/ASN.1 wrapper)
                pub_nums = private_key.public_key().public_numbers()
                raw_modulus = pub_nums.n.to_bytes(key_size, "big")
                writer.write(raw_modulus)
                await writer.drain()
                print(f"[VNC {label}] DSM: sent raw modulus ({len(raw_modulus)}B), "
                      f"waiting for {key_size}B encrypted session key")

                try:
                    enc_buf = await asyncio.wait_for(reader.read(key_size * 2), timeout=5.0)
                    print(f"[VNC {label}] DSM: server replied {len(enc_buf)}B "
                          f"hex={enc_buf[:16].hex()}")
                except asyncio.TimeoutError:
                    raise ValueError("DSM: server did not respond after receiving public key")

                if len(enc_buf) < key_size:
                    raise ValueError(f"DSM: expected {key_size}B, got {len(enc_buf)}B")
                encrypted_key = enc_buf[:key_size]
                dsm_leftover_enc = enc_buf[key_size:]

        print(f"[VNC {label}] DSM: decrypting {len(encrypted_key)}B session key")
        # Collect AES key candidates from all padding schemes and byte orderings.
        # Windows CryptoAPI (CryptEncrypt) reverses the RSA ciphertext bytes before
        # sending, so we must try both the raw bytes and the reversed bytes.
        # Exact 16-byte results are inserted at the front (highest priority).
        raw_candidates = []
        priv_nums = private_key.private_numbers()
        for enc_bytes, ord_pfx in [(encrypted_key, ""), (encrypted_key[::-1], "REV-")]:
            for pad in [asym_padding.PKCS1v15(),
                        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                                          algorithm=hashes.SHA1(), label=None),
                        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                                          algorithm=hashes.SHA256(), label=None)]:
                try:
                    plaintext = private_key.decrypt(enc_bytes, pad)
                    n = len(plaintext)
                    pad_name = f"{ord_pfx}{type(pad).__name__}"
                    print(f"[VNC {label}] DSM {pad_name} → {n}B: {plaintext.hex()}")
                    if n == 16:
                        raw_candidates.insert(0, (f"{pad_name}-16B", plaintext))
                    elif n == 32:
                        raw_candidates.append((f"{pad_name}-first16", plaintext[:16]))
                        raw_candidates.append((f"{pad_name}-last16", plaintext[16:]))
                        raw_candidates.append((f"{pad_name}-32B", plaintext))
                    elif n >= 16:
                        raw_candidates.append((f"{pad_name}-first16-of-{n}B", plaintext[:16]))
                        raw_candidates.append((f"{pad_name}-last16-of-{n}B", plaintext[-16:]))
                except Exception as e:
                    print(f"[VNC {label}] DSM {ord_pfx}{type(pad).__name__} failed: {e}")
            # Raw RSA decryption (no padding) — try last-16 and first-16 of m=c^d mod n
            try:
                c_int = int.from_bytes(enc_bytes, "big")
                m_int = pow(c_int, priv_nums.d, priv_nums.public_numbers.n)
                raw_dec = m_int.to_bytes(key_size, "big")
                print(f"[VNC {label}] DSM {ord_pfx}RAW → last16={raw_dec[-16:].hex()} first16={raw_dec[:16].hex()}")
                raw_candidates.append((f"{ord_pfx}RAW-last16", raw_dec[-16:]))
                raw_candidates.append((f"{ord_pfx}RAW-first16", raw_dec[:16]))
            except Exception as e:
                print(f"[VNC {label}] DSM {ord_pfx}RAW failed: {e}")

        # Add password-derived AES key candidates (in case server verifies key == f(password)).
        if password:
            pw_b = password.encode("utf-8")
            pw_padded = (pw_b[:16] + b"\x00" * 16)[:16]
            raw_candidates.insert(0, ("pw-md5", hashlib.md5(pw_b).digest()))
            raw_candidates.insert(1, ("pw-sha1", hashlib.sha1(pw_b).digest()[:16]))
            raw_candidates.insert(2, ("pw-sha256", hashlib.sha256(pw_b).digest()[:16]))
            raw_candidates.insert(3, ("pw-raw", pw_padded))

        # Path A: probe each candidate — find the key that decrypts leftover SR to 0.
        # OFB keystream is data-independent, so we can probe without advancing real state.
        path_a_aes_key = None
        path_a_iv = bytes(16)   # IV that produced SR=0
        path_a_sr_offset = 0    # byte offset of SR within dsm_leftover_dec
        dsm_leftover_dec = b""
        # Hypothesis: server frame = [22B header][256B key][16B IV][remaining]
        # so dsm_leftover_enc[:16] is the AES-OFB IV and leftover[16:] is ciphertext.
        _has_iv_prefix = len(dsm_leftover_enc) >= 20  # need at least IV(16) + SR(4)
        _iv_prefix = dsm_leftover_enc[:16] if _has_iv_prefix else None
        for key_desc, key_bytes in raw_candidates:
            try:
                # Standard probe: IV=zeros, SR at leftover[0:4]
                probe = Cipher(algorithms.AES(key_bytes), _OFB(bytes(16))).decryptor()
                dec_left = probe.update(dsm_leftover_enc) if dsm_leftover_enc else b""
                sr = int.from_bytes(dec_left[:4], "big") if len(dec_left) >= 4 else -1
                print(f"[VNC {label}] DSM key={key_desc} ({key_bytes.hex()[:16]}…) "
                      f"leftover-SR(IV=0)=0x{sr:08x}")
                if sr == 0:
                    path_a_aes_key = key_bytes
                    path_a_iv = bytes(16)
                    path_a_sr_offset = 0
                    dsm_leftover_dec = dec_left
                    print(f"[VNC {label}] DSM Auth OK via Path A ({key_desc}, IV=zeros)")
                    break
                # IV-prefix probe: IV=leftover[:16], SR at leftover[16:20]
                if _has_iv_prefix:
                    probe2 = Cipher(algorithms.AES(key_bytes), _OFB(_iv_prefix)).decryptor()
                    dec2 = probe2.update(dsm_leftover_enc[16:])
                    sr2 = int.from_bytes(dec2[:4], "big") if len(dec2) >= 4 else -1
                    print(f"[VNC {label}] DSM key={key_desc} ({key_bytes.hex()[:16]}…) "
                          f"leftover-SR(IV=left[:16])=0x{sr2:08x}")
                    if sr2 == 0:
                        path_a_aes_key = key_bytes
                        path_a_iv = _iv_prefix
                        path_a_sr_offset = 16
                        dsm_leftover_dec = dec2  # ciphertext after IV prefix, decrypted
                        print(f"[VNC {label}] DSM Auth OK via Path A ({key_desc}, IV=leftover[:16])")
                        break
            except Exception as e:
                print(f"[VNC {label}] DSM probe {key_desc} failed: {e}")

        # If a candidate confirmed SR=0, use it and return.
        if path_a_aes_key is not None:
            enc_ctx = Cipher(algorithms.AES(path_a_aes_key), _OFB(path_a_iv)).encryptor()
            dec_ctx = Cipher(algorithms.AES(path_a_aes_key), _OFB(path_a_iv)).decryptor()
            if dsm_leftover_enc:
                # Fast-forward the decryptor past bytes already consumed by the probe.
                consumed = len(dsm_leftover_enc) - path_a_sr_offset
                dec_ctx.update(bytes(consumed))
            dsm_pre_buf = dsm_leftover_dec[4:]  # bytes after the SR that belong to RFB stream
            print(f"[VNC {label}] DSM AES active via Path A "
                  f"(key={path_a_aes_key.hex()}, IV={path_a_iv.hex()})")
            return enc_ctx, dec_ctx, dsm_pre_buf

        # No candidate confirmed SR=0.
        # If leftover exists but is < 4 bytes, we can't probe SR — accept first candidate.
        # If leftover is empty (0x73 mode: server is waiting for our key), fall to Path B.
        # If leftover is ≥ 4 bytes with non-zero SR, fall to Path B on this same connection.
        path_a_fallback_ok = False
        fallback_aes_key = None
        if raw_candidates and dsm_leftover_enc:
            fb_desc, fallback_aes_key = raw_candidates[0]
            probe = Cipher(algorithms.AES(fallback_aes_key), _OFB(bytes(16))).decryptor()
            dsm_leftover_dec = probe.update(dsm_leftover_enc)
            sr_fb = int.from_bytes(dsm_leftover_dec[:4], "big") if len(dsm_leftover_dec) >= 4 else -1
            print(f"[VNC {label}] DSM: no SR=0 match; fallback {fb_desc} leftover-SR=0x{sr_fb:08x}")
            if len(dsm_leftover_dec) < 4:
                path_a_fallback_ok = True
        else:
            print(f"[VNC {label}] DSM: no SR=0 match; no leftover to probe — falling to Path B")

        if path_a_fallback_ok and fallback_aes_key is not None:
            iv = bytes(16)
            enc_ctx = Cipher(algorithms.AES(fallback_aes_key), _OFB(iv)).encryptor()
            dec_ctx = Cipher(algorithms.AES(fallback_aes_key), _OFB(iv)).decryptor()
            dec_ctx.update(bytes(len(dsm_leftover_enc)))
            print(f"[VNC {label}] DSM AES tentative via Path A fallback (key={fallback_aes_key.hex()})")
            return enc_ctx, dec_ctx, dsm_leftover_dec

        # In sub-type 0x72, the 256 bytes from the server is an encrypted AES key (Path A only).
        # If leftover was empty (server sent exactly [22B header][256B key] with no bundled SR),
        # the SecurityResult arrives as the next 4 bytes on the wire — read them now.
        if chosen == 0x72:
            if not dsm_leftover_enc and raw_candidates:
                print(f"[VNC {label}] DSM 0x72: no leftover — reading SR from network")
                try:
                    sr_raw = await asyncio.wait_for(reader.readexactly(4), timeout=8.0)
                except Exception as _sr_e:
                    raise _DSMAuthFailure(f"DSM 0x72: failed to read SR: {_sr_e}")
                for _key_desc, _key_bytes in raw_candidates:
                    try:
                        _probe = Cipher(algorithms.AES(_key_bytes), _OFB(bytes(16))).decryptor()
                        _sr_dec = int.from_bytes(_probe.update(sr_raw), "big")
                        print(f"[VNC {label}] DSM 0x72 SR key={_key_desc} dec=0x{_sr_dec:08x}")
                        if _sr_dec == 0:
                            enc_ctx = Cipher(algorithms.AES(_key_bytes), _OFB(bytes(16))).encryptor()
                            dec_ctx = Cipher(algorithms.AES(_key_bytes), _OFB(bytes(16))).decryptor()
                            dec_ctx.update(sr_raw)  # advance past SR bytes
                            print(f"[VNC {label}] DSM 0x72 Auth OK! ({_key_desc})")
                            return enc_ctx, dec_ctx, b""
                    except Exception as _ke:
                        print(f"[VNC {label}] DSM 0x72 SR probe {_key_desc}: {_ke}")
                _sr_plain = int.from_bytes(sr_raw, "big")
                if _sr_plain == 0:
                    # SR is plaintext — cipher starts at position 0 for RFB data
                    _key_bytes = raw_candidates[0][1]
                    enc_ctx = Cipher(algorithms.AES(_key_bytes), _OFB(bytes(16))).encryptor()
                    dec_ctx = Cipher(algorithms.AES(_key_bytes), _OFB(bytes(16))).decryptor()
                    print(f"[VNC {label}] DSM 0x72 Auth OK! (plain SR, {raw_candidates[0][0]})")
                    return enc_ctx, dec_ctx, b""
                raise _DSMAuthFailure(
                    f"DSM 0x72: SR raw=0x{_sr_plain:08x}, no AES key gave SR=0"
                )
            raise _DSMAuthFailure(f"0x72 Path A exhausted — no valid AES key found in server payload")

        # Path B: treat encrypted_key as the SERVER's RSA public key modulus.
        # Windows CryptoAPI exports the modulus in little-endian (reversed) byte order.
        # We encrypt a random AES session key with the server's public key and send it.
        # Server decrypts with its private key, both sides use the shared AES key.
        print(f"[VNC {label}] DSM: Path A exhausted — trying Path B on same connection "
              f"(e={dsm_exponent}, mod={'LE' if dsm_reverse_modulus else 'BE'}, "
              f"cipher={'LE' if dsm_reverse_cipher else 'BE'}, "
              f"rsa={'raw' if dsm_raw_rsa else 'PKCS1v15'})")
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        if dsm_reverse_modulus:
            server_n = int.from_bytes(encrypted_key[::-1], "big")
        else:
            server_n = int.from_bytes(encrypted_key, "big")
        actual_rev_mod = dsm_reverse_modulus
        if not (server_n & 1):
            # Preferred byte order gives even modulus — automatically try the alternate.
            alt_n = int.from_bytes(encrypted_key, "big") if dsm_reverse_modulus else int.from_bytes(encrypted_key[::-1], "big")
            if alt_n & 1:
                print(f"[VNC {label}] DSM Path B: {'LE' if dsm_reverse_modulus else 'BE'} modulus even, "
                      f"falling back to {'BE' if dsm_reverse_modulus else 'LE'}")
                server_n = alt_n
                actual_rev_mod = not dsm_reverse_modulus
            else:
                # Both LE and BE are even — not a valid RSA modulus, but proceed anyway
                # to reach the SecurityResult so we can read any server reason string.
                print(f"[VNC {label}] DSM Path B: both LE and BE modulus are even "
                      f"(not a valid RSA key) — proceeding anyway for diagnostics")
        try:
            path_b_aes_key = os.urandom(16)
            key_size = (server_n.bit_length() + 7) // 8
            if dsm_raw_rsa:
                # Raw RSA: c = m^e mod n, message is zero-padded AES key (right-aligned)
                m_bytes = b"\x00" * (key_size - len(path_b_aes_key)) + path_b_aes_key
                m_int = int.from_bytes(m_bytes, "big")
                c_int = pow(m_int, dsm_exponent, server_n)
                encrypted_session = c_int.to_bytes(key_size, "big")
            else:
                server_pub = RSAPublicNumbers(e=dsm_exponent, n=server_n).public_key()
                encrypted_session = server_pub.encrypt(path_b_aes_key, asym_padding.PKCS1v15())
        except Exception as key_err:
            raise _DSMAuthFailure(
                f"e={dsm_exponent},mod={'LE' if actual_rev_mod else 'BE'}: "
                f"key/encrypt error: {key_err}"
            ) from key_err
        wire_cipher = encrypted_session[::-1] if dsm_reverse_cipher else encrypted_session
        print(f"[VNC {label}] DSM Path B: wire_cipher first8={wire_cipher[:8].hex()} "
              f"last8={wire_cipher[-8:].hex()} "
              f"({'LE/reversed' if dsm_reverse_cipher else 'BE/as-is'})")
        writer.write(wire_cipher)
        await writer.drain()
        print(f"[VNC {label}] DSM Path B: sent {len(wire_cipher)}B encrypted session key "
              f"(e={dsm_exponent}, mod={'LE' if actual_rev_mod else 'BE'}, "
              f"cipher={'LE' if dsm_reverse_cipher else 'BE'}, "
              f"rsa={'raw' if dsm_raw_rsa else 'PKCS1v15'}), "
              f"our AES key={path_b_aes_key.hex()}")
        # Use leftover[:16] as IV if available (hypothesis: server embeds IV in leftover frame).
        iv = dsm_leftover_enc[:16] if len(dsm_leftover_enc) >= 16 else bytes(16)
        print(f"[VNC {label}] DSM Path B: IV={iv.hex()} "
              f"(source={'leftover[:16]' if len(dsm_leftover_enc) >= 16 else 'zeros'})")
        enc_ctx = Cipher(algorithms.AES(path_b_aes_key), _OFB(iv)).encryptor()
        dec_ctx = Cipher(algorithms.AES(path_b_aes_key), _OFB(iv)).decryptor()
        print(f"[VNC {label}] DSM: discarding {len(dsm_leftover_enc)}B pre-exchange leftover")
        raw = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        plain_result = int.from_bytes(raw, "big")
        dec_raw = dec_ctx.update(raw)
        enc_result = int.from_bytes(dec_raw, "big")
        print(f"[VNC {label}] DSM Path B: SecurityResult raw={raw.hex()} "
              f"plain=0x{plain_result:08x} aes_dec=0x{enc_result:08x}")
        if plain_result == 0:
            print(f"[VNC {label}] DSM Auth OK via Path B (plain SR)")
            return enc_ctx, dec_ctx, b""
        if enc_result == 0:
            print(f"[VNC {label}] DSM Auth OK via Path B (AES SR)")
            return enc_ctx, dec_ctx, b""
        # Read extra bytes for diagnostics.
        try:
            extra = await asyncio.wait_for(reader.read(100), timeout=0.5)
            if extra:
                print(f"[VNC {label}] DSM Path B extra after SR: {extra.hex()!r}")
                if len(extra) >= 4:
                    rlen = int.from_bytes(extra[:4], "big")
                    if 0 < rlen <= 200 and len(extra) >= 4 + rlen:
                        print(f"[VNC {label}] DSM Path B reason: "
                              f"{extra[4:4 + rlen].decode(errors='replace')!r}")
            else:
                print(f"[VNC {label}] DSM Path B: server closed connection after SR={plain_result}")
                raise _DSMAuthFailure(f"Server closed after SR=0x{plain_result:08x}")
        except asyncio.TimeoutError:
            # Server sent nothing after SR — proceed optimistically.
            # SR=1 in UltraVNC DSM may not be a standard RFB failure code.
            print(f"[VNC {label}] DSM Path B: no data after SR={plain_result} — proceeding")
            return enc_ctx, dec_ctx, b""
        except _DSMAuthFailure:
            raise
        except Exception:
            pass
        # Server sent data after SR=1 (reason string or more RFB data).
        # Proceed: SR might not follow standard RFB semantics in UltraVNC DSM.
        print(f"[VNC {label}] DSM Path B: proceeding despite SR=0x{plain_result:08x}")
        return enc_ctx, dec_ctx, b""
    elif 1 in types:
        selected = 1
        writer.write(bytes([1]))
        await writer.drain()
    elif 2 in types:
        selected = 2
        writer.write(bytes([2]))
        await writer.drain()
        challenge = await asyncio.wait_for(reader.readexactly(16), timeout=5.0)
        writer.write(_vnc_des_response(password, challenge))
        await writer.drain()
    else:
        raise ValueError(f"No supported security type in {types}")

    # SecurityResult: RFB 3.8 always; RFB 3.7 only for non-None types
    # (type-17/DSM already returned above after consuming SecurityResult from leftover)
    if srv_minor >= 8 or (srv_minor == 7 and selected != 1):
        raw = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        if dec_ctx:
            raw = dec_ctx.update(raw)
        result = int.from_bytes(raw, "big")
        if result != 0:
            msg = "Authentication failed"
            if srv_minor >= 8:
                rlen_raw = await reader.readexactly(4)
                if dec_ctx:
                    rlen_raw = dec_ctx.update(rlen_raw)
                rlen = int.from_bytes(rlen_raw, "big")
                reason_raw = await reader.readexactly(rlen)
                if dec_ctx:
                    reason_raw = dec_ctx.update(reason_raw)
                msg = reason_raw.decode(errors="replace")
            raise ValueError(f"SecurityResult failure: {msg}")
        print(f"[VNC {label}] Auth OK (type {selected})")

    return enc_ctx, dec_ctx, b""


async def _client_rfb_handshake(websocket, label: str):
    """
    Server-side of the RFB handshake toward noVNC.
    We present RFB 3.8 with security type 1 (None) — the session token is
    the real authentication gate.  Raises on timeout or disconnect.
    """
    await websocket.send_bytes(b"RFB 003.008\n")
    msg = await asyncio.wait_for(websocket.receive(), timeout=10.0)
    if msg.get("type") == "websocket.disconnect":
        raise ValueError("noVNC disconnected during version exchange")
    cv = msg.get("bytes") or msg.get("text", "").encode()
    print(f"[VNC {label}] noVNC version: {cv[:11]}")
    # Send security type list: count=1, type=1 (None)
    await websocket.send_bytes(bytes([1, 1]))
    msg = await asyncio.wait_for(websocket.receive(), timeout=5.0)
    if msg.get("type") == "websocket.disconnect":
        raise ValueError("noVNC disconnected during security negotiation")
    # Send SecurityResult = OK
    await websocket.send_bytes(b"\x00\x00\x00\x00")
    print(f"[VNC {label}] noVNC handshake complete")


@app.websocket("/ws/vnc/{token}")
async def vnc_ws_proxy(websocket: WebSocket, token: str):
    session = _vnc_sessions.pop(token, None)
    if not session:
        await websocket.close(code=1008)
        return

    host_label = f"{session['host']}:{session['port']}"
    client_key_path = session.get("client_key_path")
    password = session.get("password", "") or ""

    await websocket.accept()

    # Phase 1: connect to VNC server (Python DSM for SecureVNCPlugin2 ClientAuth, or plain TCP)
    try:
        reader, writer = await asyncio.open_connection(session["host"], session["port"])
        sock = writer.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        mode = "DSM ClientAuth" if client_key_path else "plain"
        print(f"[VNC {host_label}] TCP connected ({mode})")
        enc_ctx, dec_ctx, srv_pre_buf = await _server_rfb_handshake(
            reader, writer, client_key_path or "", password, host_label)
    except Exception as e:
        print(f"[VNC {host_label}] Connection/handshake failed ({type(e).__name__}): {e}")
        try:
            await websocket.close()
        except Exception:
            pass
        return

    # Phase 2: simplified RFB handshake toward noVNC
    try:
        await _client_rfb_handshake(websocket, host_label)
    except Exception as e:
        print(f"[VNC {host_label}] Client handshake failed: {e}")
        writer.close()
        try:
            await websocket.close()
        except Exception:
            pass
        return

    # Phase 3: bidirectional relay (decrypt from server, encrypt to server)
    async def ws_to_tcp():
        msgs = 0
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    print(f"[VNC {host_label}] client disconnected after {msgs} msgs")
                    break
                data = msg.get("bytes") or (msg.get("text", "").encode() if "text" in msg else None)
                if data:
                    msgs += 1
                    if enc_ctx:
                        data = enc_ctx.update(data)
                    writer.write(data)
                    await writer.drain()
        except Exception as e:
            print(f"[VNC {host_label}] ws_to_tcp ended: {e}")

    async def tcp_to_ws():
        chunks = 0
        try:
            if srv_pre_buf:
                print(f"[VNC {host_label}] forwarding {len(srv_pre_buf)}B pre-buffered RFB data")
                await websocket.send_bytes(srv_pre_buf)
                chunks += 1
            while True:
                data = await reader.read(65536)
                if not data:
                    print(f"[VNC {host_label}] server closed after {chunks} chunks")
                    break
                chunks += 1
                if dec_ctx:
                    data = dec_ctx.update(data)
                try:
                    await websocket.send_bytes(data)
                except Exception as e:
                    print(f"[VNC {host_label}] send_bytes failed: {e}")
                    break
        except Exception as e:
            print(f"[VNC {host_label}] tcp_to_ws ended: {e}")

    tasks = [asyncio.ensure_future(ws_to_tcp()), asyncio.ensure_future(tcp_to_ws())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    writer.close()
    print(f"[VNC {host_label}] proxy closed")
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
            "color_depth": data.color_depth,
            "disable_audio": data.disable_audio,
            "enable_wallpaper": data.enable_wallpaper,
            "enable_font_smoothing": data.enable_font_smoothing,
            "enable_desktop_composition": data.enable_desktop_composition,
            "resize_method": data.resize_method,
            "cursor": data.cursor,
            "dpi": data.dpi,
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

    # Override width/height with actual browser viewport passed as ?w=&h=
    try:
        bw = int(websocket.query_params.get("w", 0))
        bh = int(websocket.query_params.get("h", 0))
        if bw > 0 and bh > 0:
            session = dict(session)
            session["width"] = bw
            session["height"] = bh
    except (ValueError, TypeError):
        pass

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
        # Send exactly one complete Guacamole instruction per WebSocket frame.
        # guacamole-common-js WebSocketTunnel.onmessage resets its parser state
        # on every message, so partial instructions silently corrupt the stream.
        # readuntil(b";") is safe for all RDP draw instructions because base64,
        # numbers and simple strings (the only value types) never contain ";".
        count = 0
        try:
            while True:
                instr = await reader.readuntil(b";")
                count += 1
                if count <= 5:
                    print(f"[RDP {host_label}] instr #{count}: {instr[:100]!r}")
                try:
                    await websocket.send_text(instr.decode("utf-8", errors="replace"))
                except Exception:
                    # WebSocket already closed — stop sending
                    break
        except asyncio.IncompleteReadError:
            print(f"[RDP {host_label}] guacd closed after {count} instructions")
        except Exception as e:
            print(f"[RDP {host_label}] tcp_to_ws error after {count} instructions: {e}")

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
