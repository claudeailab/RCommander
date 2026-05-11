# RCommander

R Commander (Rcmdr) running in a browser via noVNC — no desktop required.

![RCommander Web UI](screenshot.png)

## Quick Start

```yaml
services:
  rcommander:
    image: aristosv/rcommander
    container_name: rcommander
    hostname: rcommander
    restart: unless-stopped
    user: "0"
    environment:
      TZ: America/New_York
    ports:
      - 8090:8090
    volumes:
      - ./config/rcommander:/data
```

Open **http://your-host:8090/vnc.html** in your browser.

## Features

- Full R Commander GUI accessible from any browser
- Persistent `/data` volume for scripts and datasets
- Multi-arch: `linux/amd64` and `linux/arm64`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TZ` | Timezone (e.g. `America/New_York`) |
