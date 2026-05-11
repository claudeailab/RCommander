# RCommander

A self-hosted web UI for running commands on remote servers over SSH (Linux) and WinRM (Windows).

![RCommander](screenshot.png)

## Features

- **Servers** — manage a list of SSH and WinRM hosts
- **Credentials** — store username/password or SSH private key pairs
- **Commands** — save reusable commands
- **Execute** — pick a server, credentials, and command; stream output live in the browser
- Fully responsive — works on desktop and mobile
- SQLite persistence via `/data` volume

## Quick Start

```yaml
  rcommander:
    image: claudeailab/rcommander
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

## WinRM Setup (Windows)

Run the following in **PowerShell as Administrator** on the target Windows host:

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true
Restart-Service WinRM
New-NetFirewallRule -DisplayName "WinRM 5985" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
```
