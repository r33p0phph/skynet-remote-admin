# Skynet Remote Admin

Read-only diagnostics dashboard for an Unraid server: host health, array and SMART status,
backup inventory, Docker container status and (redacted) logs. It can read, never change.

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
| `CENTRAL_BACKUP_DIR` | Defaults to `/host/mnt/user/backups/skynet` |
| `SHOW_FULL_SERIALS` | `1` to show full drive serials (masked to the last 4 characters by default) |

## Host mounts (all read-only)

`/proc` -> `/host/proc`, `/sys` -> `/host/sys`, `/mnt` -> `/host/mnt`, `/var/local/emhttp` -> `/host/emhttp`.
Optional: `/boot` -> `/host/boot`, `/var/log` -> `/host/var/log`.

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
