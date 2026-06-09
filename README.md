# RCommander

A self-hosted web UI for running commands on remote servers over SSH (Linux/Mac) and WinRM (Windows).

![RCommander](screenshot.png)

## Features

- **Servers** — manage SSH and WinRM hosts with host, port, type, and optional description
- **Nested folders** — organise servers into folders and sub-folders for large inventories
- **Folder credentials** — assign credentials to a folder; all servers inside inherit them
- **Credentials** — store username/password or SSH private key pairs securely
- **Commands** — save reusable commands with a shell type badge (SH, CMD, PS)
- **Shell types** — mark each command as SH (bash/shell), CMD (Windows batch), or PowerShell
- **Execute (Single)** — pick a server and command, stream live output in a built-in terminal
- **Execute (Multiple)** — run a command on multiple servers simultaneously with a searchable folder tree
- **Command search** — filter the command dropdown as you type
- **Server filter** — search servers by name, host, or group in the Execute (Multiple) tree
- **Select filtered** — Select All only picks servers matching the active search query
- **Unlock** — override a locked command's pre-selected server with one click
- **CSV import** — bulk-import servers from a CSV file
- **Clone server** — duplicate an existing server as a starting point
- **Responsive** — works on desktop and mobile
- **Remote Access** — connect to servers via VNC (in-browser session) or RDP (downloads a pre-filled .rdp file)
- **SQLite persistence** — single-file database stored under `/data`

## Quick Start

Add this to your `docker-compose.yml`:

```yaml
  rcommander:
    image: ghcr.io/claudeailab/rcommander
    container_name: rcommander
    hostname: rcommander
    restart: unless-stopped
    user: "0"
    environment:
      TZ: ${TZ}
    ports:
      - 8090:8090
    volumes:
      - ./config/rcommander:/data
```

Then run:

```bash
docker compose up -d
```

Open **http://your-host:8090**

## Updating

```bash
docker compose pull rcommander && docker compose up -d rcommander
```

## WinRM Setup (Windows)

Run the following in **PowerShell as Administrator** on the target Windows host:

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true
Restart-Service WinRM
New-NetFirewallRule -DisplayName "WinRM 5985" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
```

