# RCommander — Claude Guidelines

## Docker & Build

- The web app runs as a Docker container; always build multi-arch: **linux/amd64** and **linux/arm64**
- Host the image on **GitHub Container Registry**: `ghcr.io/claudeailab/rcommander`
- After merging any branch or pull request, trigger the GitHub Actions build workflow

## Versioning

- Always display a discreet version number in the web app (e.g. in the sidebar)
- Bump the version with every push to main

## UX

- The web app must be functional and intuitive on both **desktop and mobile**

## GitHub README

- Include a **Features** section with bullet points and a short description of each feature
- Include an **Updating** section with:
  ```bash
  docker compose pull rcommander && docker compose up -d rcommander
  ```

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

## docker-compose.yml template

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
