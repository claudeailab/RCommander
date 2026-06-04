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

- Include an **Updating** section with:
  ```bash
  docker compose pull rcommander && docker compose up -d rcommander
  ```

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
