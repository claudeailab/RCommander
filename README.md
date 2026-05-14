# RCommander

A self-hosted web UI for running commands on remote servers over SSH (Linux) and WinRM (Windows).

![RCommander](screenshot.png)

## Features

- **Servers** — manage SSH and WinRM hosts, organised into nested folders
- **Folder tree** — create folders and subfolders to group servers; inline rename, delete, and add subfolder actions on every folder
- **Credentials** — store username/password or SSH private key pairs; credentials are linked directly to servers
- **Commands** — save reusable commands with descriptions
- **Execute** — drill down through the folder hierarchy to pick a server, choose a command, and stream live output in a built-in terminal
- **CSV import** — bulk-import servers from a CSV file
- Fully responsive — works on desktop and mobile
- SQLite persistence via `/data` volume

## Quick Start

Add this to your `docker-compose.yml` file:

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
