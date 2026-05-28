# RCommander

A self-hosted web UI for running commands on remote servers over SSH (Linux/Mac) and WinRM (Windows).

![RCommander](screenshot.png)

## Features

- **Servers** — manage SSH and WinRM hosts
- **Nested folders** — organise servers into folders and sub-folders
- **Folder credentials** — assign credentials to a folder; all servers inside inherit them
- **Credentials** — store username/password or SSH private key pairs
- **Commands** — save reusable commands; optionally lock a command to a specific server
- **Execute** — pick a server and command, stream live output in a built-in terminal
- **Command search** — filter the command dropdown as you type
- **Unlock** — override a locked command's pre-selected server with one click
- **CSV import** — bulk-import servers from a CSV file
- **Clone server** — duplicate an existing server as a starting point
- **Responsive** — works on desktop and mobile
- **SQLite persistence** — single-file database under `/data`

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

## Changelog

### Recent additions
- Folder-level credentials with inheritance — assign once per folder, all servers inside pick it up
- Locked commands — link a command to a server; Execute auto-selects both and shows an Unlock button to override
- Command search — live filter in the Execute command dropdown
- Edit Folder modal — rename, move, and set credentials for a folder in one dialog
- New Folder from the More menu now includes a parent-folder picker for creating sub-folders
- Mobile layout improvements — folder rows use Edit/Delete buttons directly instead of a ⋮ menu
