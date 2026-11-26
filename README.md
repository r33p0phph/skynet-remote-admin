# Skynet Remote Admin

Diagnostics dashboard for an Unraid server: host health, array and SMART status, Docker container
status and (redacted) logs, backup health, and a backup manager that writes CRC-verified ZIP snapshots
of a fixed list of configuration folders. It cannot change containers or the array; its only write
access is the backup destination folder.

The app name above is separate from the build label, which lives in `VERSION`.

## Layout

| Path | What it is |
|---|---|
| `app/server.py` | The FastAPI app (single file) |
| `tests/` | Unit tests, plus tests against real Unraid files |
| `tests/data/real-unraid/` | Sanitized sample from a real Unraid 7.x server (masked drive IDs); always tested, including in CI |
| `scripts/collect_fixtures.sh` | Run on the Unraid host to copy (masked) real files for testing |
| `VERSION` | Internal build label |

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `ADMIN_USER`, `ADMIN_PASSWORD` | Required. ASCII only. The app refuses to start without them |
| `DOCKER_HOST` | Defaults to `tcp://docker-socket-proxy:2375` |
| `APPDATA_ROOT` | Defaults to `/host/mnt/user/appdata`. Use `/host/mnt/cache/appdata` if appdata is on a cache pool |
| `CENTRAL_BACKUP_DIR` | Where the backup manager writes archives. Defaults to `/host/backups` (the writable mount) |
| `BACKUP_DESTINATION_LABEL` | How that folder is shown in the UI. Defaults to `/mnt/datastorage/backups/skynet` |
| `SHOW_FULL_SERIALS` | `1` to show full drive serials (masked to the last 4 characters by default) |

## Host mounts

Read-only: `/proc` -> `/host/proc`, `/sys` -> `/host/sys`, `/mnt` -> `/host/mnt`,
`/var/local/emhttp` -> `/host/emhttp` (mount the directory, not single files: Unraid replaces them).
Optional, read-only: `/boot` -> `/host/boot` (needed for the optional Unraid Boot Configuration backup
and the flash usage row), `/var/log` -> `/host/var/log`.

Read-write, one folder only: the backup destination, e.g. `/mnt/datastorage/backups/skynet` -> `/host/backups`.
The folder must be writable by the container's user.

## Backup manager

Items are a fixed allowlist in `BACKUP_ITEMS` (Nginx Proxy Manager, Radarr, Sonarr, Prowlarr, qBittorrent,
Seerr, Skynet MCP configuration, and the optional Unraid Boot Configuration, which is unchecked by default).
The browser sends item IDs only, never paths. Symlinks are not followed, `.env`/`.envx`/`.env.*` files are
left out of the Skynet MCP archive, the destination's free space is checked first, and each archive is
written as `.partial`, CRC-tested, then renamed. Applications are not stopped, so archives are live
snapshots. Archives can contain secrets (keys, certificates, password hashes): keep the destination private.
Starting a backup needs the `X-Requested-With: skynet-admin` header, which the page adds itself, so a page on
another site cannot trigger one. There is no retention or deletion.

The Docker socket proxy should allow only what the app uses: `CONTAINERS=1`, `INFO=1`, `VERSION=1`, `POST=0`,
on a network that is not published.

## Development

```
pip install -r requirements-dev.txt
pytest -q
```

Tests against real hardware are skipped until you run `bash scripts/collect_fixtures.sh` on the Unraid host
(from the repo root) and put the resulting `fixtures/` folder next to `app/`. It is git-ignored on purpose.

## Branches

Work happens on `dev`. `main` is the release: merge to it only after the build has been confirmed
working on the server.

## Security notes

- Put Cloudflare Access (or equivalent) in front of the hostname. The built-in Basic auth is a second layer.
- Log redaction is pattern based and best effort. Treat container logs as sensitive.
