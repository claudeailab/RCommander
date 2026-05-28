# RCommander

A self-hosted web UI for running commands on remote servers over SSH (Linux/Mac) and WinRM (Windows).

![RCommander](screenshot.png)

## Features

- **Servers** — add and manage SSH and WinRM hosts with name, host/IP, port, type, and description
- **Nested folders** — organise servers into folders and sub-folders; edit (rename, move, set credentials) or delete any folder in one place
- **Folder credentials** — assign a credential to a folder so all servers inside inherit it automatically; servers with their own credential always take priority
- **Credentials** — store username + password or SSH private key pairs; inherited credentials are shown with a dashed badge on the server list
- **Commands** — save reusable commands with descriptions; optionally lock a command to a specific server so Execute pre-selects both automatically
- **Execute** — pick a server (navigating the folder tree) and a command, then run it and watch live streaming output in a built-in terminal
- **Command search** — the command dropdown on Execute includes a live search filter for long command lists
- **Unlock** — when a locked command pre-selects a server, a one-click Unlock button resets the selection for ad-hoc use
- **CSV import** — bulk-import servers from a CSV file
- **Clone server** — duplicate an existing server entry as a starting point
- **Responsive UI** — works on desktop and mobile; folder and server rows adapt their layout for small screens
- **SQLite persistence** — all data stored in a single file under `/data`; easy to back up

## Quick Start

Add this to your `docker-compose.yml`:

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

## Changelog

### Recent additions
- Folder-level credentials with inheritance — assign once per folder, all servers inside pick it up
- Locked commands — link a command to a server; Execute auto-selects both and shows an Unlock button to override
- Command search — live filter in the Execute command dropdown
- Edit Folder modal — rename, move, and set credentials for a folder in one dialog
- New Folder from the More menu now includes a parent-folder picker for creating sub-folders
- Mobile layout improvements — folder rows use Edit/Delete buttons directly instead of a ⋮ menu
