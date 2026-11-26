"""Skynet Remote Admin: read-only diagnostics and scoped configuration backups for Unraid.

Runs in a container with read-only bind mounts of the host's /proc, /sys, /mnt and
/var/local/emhttp (optionally /boot and /var/log) and reaches Docker only through a
restricted docker-socket-proxy. The one writable mount is the backup destination folder
(CENTRAL_BACKUP_DIR), used only by the allowlisted backup manager.
"""
import functools
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
import uuid
import zipfile
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
import requests
from docker.errors import DockerException
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

log = logging.getLogger("uvicorn.error")

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SHOW_FULL_SERIALS = os.environ.get("SHOW_FULL_SERIALS", "").lower() in ("1", "true", "yes")


def validate_config() -> None:
    """Refuse to start with unusable credentials instead of failing on every request."""
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_USER and ADMIN_PASSWORD must be set")
    # FastAPI's HTTPBasic decodes the Authorization header as ASCII, so a non-ASCII
    # credential could never log in.
    if not (ADMIN_USER.isascii() and ADMIN_PASSWORD.isascii()):
        raise RuntimeError("ADMIN_USER and ADMIN_PASSWORD must be ASCII-only")
    if len(ADMIN_PASSWORD) < 12:
        log.warning("ADMIN_PASSWORD is shorter than 12 characters")


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_config()
    yield


app = FastAPI(
    title="Skynet Remote Admin",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
basic = HTTPBasic(auto_error=False)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


HOST_PROC = Path("/host/proc")
HOST_SYS = Path("/host/sys")
HOST_MNT = Path("/host/mnt")
EMHTTP = Path("/host/emhttp")
SMART_DIR = EMHTTP / "smart"

# Optional extra volumes. They only appear if you add the read-only bind mounts, e.g.
#   -v /boot:/host/boot:ro   -v /var/log:/host/var/log:ro
OPTIONAL_VOLUMES = [
    ("User shares (/mnt/user)", "Shares", HOST_MNT / "user", "/mnt/user"),
    ("Flash (/boot)", "Flash", Path("/host/boot"), "/boot"),
    ("Logs (/var/log)", "RAM", Path("/host/var/log"), "/var/log"),
]

# Point these at /host/mnt/cache/... if the shares live on a cache pool: it avoids the
# /mnt/user FUSE layer, which can wake array disks.
APPDATA_ROOT = Path(os.environ.get("APPDATA_ROOT", "/host/mnt/user/appdata"))
# Where the backup manager writes its ZIP archives. This is the only writable mount, e.g.
#   -v /mnt/datastorage/backups/skynet:/host/backups
CENTRAL_BACKUP_DIR = Path(os.environ.get("CENTRAL_BACKUP_DIR", "/host/backups"))
# How that folder is shown in the UI (the path on the Unraid host).
BACKUP_DESTINATION_LABEL = os.environ.get("BACKUP_DESTINATION_LABEL", "/mnt/datastorage/backups/skynet")

# (name, folder, stale_after_days, optional)
BACKUP_SOURCES = [
    ("Radarr", APPDATA_ROOT / "binhex-radarr/Backups", 30, False),
    ("Sonarr", APPDATA_ROOT / "binhex-sonarr/Backups", 30, False),
    ("Sonarr legacy", APPDATA_ROOT / "sonarr/Backups", 30, True),
    ("Prowlarr", APPDATA_ROOT / "binhex-prowlarr/prowlarr/Backups", 30, False),
    ("Huntarr", APPDATA_ROOT / "Huntarr/backups", 30, False),
    ("Doge Node", APPDATA_ROOT / "doge-node/backups", 30, False),
]
MAX_SCAN_FILES = 20000
ZIP_TEST_MAX_BYTES = 512 * 1024 * 1024

CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_LOG_CHARS = 256 * 1024
MAX_LOG_LINE = 2000


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def ttl_cache(seconds: float):
    """Cache a zero-argument function's result for a short time."""
    def decorator(fn):
        lock = threading.Lock()
        state: dict[str, Any] = {"at": 0.0, "value": None}

        @functools.wraps(fn)
        def wrapper():
            with lock:
                now = time.monotonic()
                if state["value"] is None or now - state["at"] > seconds:
                    state["value"] = fn()
                    state["at"] = now
                return state["value"]

        wrapper.cache_clear = lambda: state.update(at=0.0, value=None)
        return wrapper
    return decorator


def public_path(path: Path | str) -> str:
    return str(path).replace("/host/mnt", "/mnt", 1)


def read_text(path: Path | str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def kib_to_bytes(value: Any) -> int | None:
    # Unraid's disks.ini reports size and filesystem figures in 1 KiB blocks.
    number = int_or_none(value)
    return number * 1024 if number is not None else None


def mask_serial(value: str | None) -> str | None:
    if not value:
        return None
    if SHOW_FULL_SERIALS or len(value) <= 4:
        return value
    return "\u2026" + value[-4:]


def parse_ini_sections(path: Path) -> dict[str, dict[str, str]]:
    """Parse Unraid's ["section"] key="value" format without assuming fixed slots."""
    text = read_text(path)
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.fullmatch(r'\["([^"]+)"\]', line)
        if match:
            current = {}
            sections[match.group(1)] = current
            continue
        if current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip().strip('"')
    return sections


def parse_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
    return values


# ---------------------------------------------------------------------------
# log redaction
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = (
    r"x-api-key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"token|passkey|password|passwd|pwd|secret|client[_-]?secret|authorization|"
    r"set-cookie|cookie|session[_-]?id|sid|key"
)

# Order matters: Bearer/Basic first so "Authorization: Bearer xyz" loses the token too.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@"), r"\1[REDACTED]@"),
    (
        re.compile(
            r"""(?ix)
            (\b(?:""" + _SENSITIVE_KEYS + r""")\b["']?\s*[:=]\s*["']?)
            (?!\[REDACTED\])
            ([^\s"'&;,]+)
            """
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    # *arr API keys and many tracker passkeys are 32 hex characters.
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "[REDACTED-HEX32]"),
]


def redact_secrets(text: str) -> tuple[str, int]:
    total = 0
    for pattern, replacement in _REDACTIONS:
        text, count = pattern.subn(replacement, text)
        total += count
    return text, total


def sanitize_logs(raw: str) -> dict[str, Any]:
    truncated = False
    if len(raw) > MAX_LOG_CHARS:
        raw = raw[-MAX_LOG_CHARS:]
        truncated = True
    lines = []
    for line in raw.splitlines():
        if len(line) > MAX_LOG_LINE:
            line = line[:MAX_LOG_LINE] + " ...[line truncated]"
            truncated = True
        lines.append(line)
    text, redactions = redact_secrets("\n".join(lines))
    return {
        "logs": text,
        "line_count": len(lines),
        "redactions": redactions,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# backups
# ---------------------------------------------------------------------------

def scan_backup_folder(folder: Path) -> dict[str, Any]:
    """Walk a folder without following symlinks, tracking the two newest files."""
    file_count = 0
    total_bytes = 0
    newest: tuple[float, int, str] | None = None
    previous: tuple[float, int, str] | None = None
    truncated = False
    stack = [str(folder)]
    while stack and not truncated:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            if file_count >= MAX_SCAN_FILES:
                                truncated = True
                                break
                            st = entry.stat(follow_symlinks=False)
                            file_count += 1
                            total_bytes += st.st_size
                            item = (st.st_mtime, st.st_size, entry.path)
                            if newest is None or item[0] > newest[0]:
                                previous, newest = newest, item
                            elif previous is None or item[0] > previous[0]:
                                previous = item
                    except OSError:
                        continue
        except OSError:
            continue
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "newest": newest,
        "previous": previous,
        "truncated": truncated,
    }


@functools.lru_cache(maxsize=64)
def zip_crc_ok(path: str, mtime: float, size: int) -> bool | None:
    """CRC-test a ZIP. mtime and size are only cache keys, so a changed file is retested."""
    if not path.lower().endswith(".zip") or size > ZIP_TEST_MAX_BYTES:
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.testzip() is None
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False


@ttl_cache(60)
def backup_inventory() -> dict[str, Any]:
    now = time.time()
    results = []
    for name, folder, stale_days, optional in BACKUP_SOURCES:
        exists = folder.is_dir()
        scan = scan_backup_folder(folder) if exists else None
        newest = scan["newest"] if scan else None
        previous = scan["previous"] if scan else None

        warnings: list[str] = []
        age_days = None
        zip_ok = None
        if newest:
            mtime, size, path = newest
            age_days = max(0, int((now - mtime) / 86400))
            if size == 0:
                warnings.append("Latest backup is 0 bytes")
            elif previous and previous[1] > 0 and size < previous[1] * 0.5:
                warnings.append(
                    f"Latest backup is under half the size of the previous one "
                    f"({size} vs {previous[1]} bytes)"
                )
            zip_ok = zip_crc_ok(path, mtime, size)
            if zip_ok is False:
                warnings.append("Latest ZIP failed its CRC test")
        if scan and scan["truncated"]:
            warnings.append(f"Scan stopped after {MAX_SCAN_FILES} files")

        if not exists:
            status = "Not present (optional)" if optional else "Missing folder"
        elif newest is None:
            status = "No backup files"
        elif age_days is not None and age_days > stale_days:
            status = "Stale"
        elif warnings:
            status = "Check"
        else:
            status = "Recent"

        results.append({
            "application": name,
            "folder": public_path(folder),
            "folder_exists": exists,
            "optional": optional,
            "file_count": scan["file_count"] if scan else 0,
            "total_bytes": scan["total_bytes"] if scan else 0,
            "latest_file": Path(newest[2]).name if newest else None,
            "latest_path": public_path(newest[2]) if newest else None,
            "latest_size_bytes": newest[1] if newest else None,
            "latest_timestamp": (
                datetime.fromtimestamp(newest[0], tz=timezone.utc)
                .astimezone().isoformat(timespec="seconds")
                if newest else None
            ),
            "age_days": age_days,
            "latest_zip_ok": zip_ok,
            "stale_after_days": stale_days,
            "warnings": warnings,
            "status": status,
        })

    return {
        "sources": results,
        "central_destination": BACKUP_DESTINATION_LABEL,
        "central_destination_exists": CENTRAL_BACKUP_DIR.is_dir(),
        "mode": "read-only inventory",
        "integrity_verified": False,
        "note": (
            "Latest ZIP archives are CRC-tested; other file types are not verified. "
            "Presence, size and timestamps do not prove a restore will succeed."
        ),
    }


# ---------------------------------------------------------------------------
# backup manager
# ---------------------------------------------------------------------------
# Creates CRC-verified ZIP snapshots of a fixed allowlist of configuration folders. Only the
# item IDs below can be selected; the browser never supplies a path. Applications are not
# stopped, so these are live snapshots and database consistency is not guaranteed. The only
# writable mount the app needs is the destination folder (CENTRAL_BACKUP_DIR).

MAX_KEPT_JOBS = 20
BACKUP_EXCLUDED_NAMES = {".env", ".envx"}
BACKUP_ITEMS: dict[str, dict[str, Any]] = {
    "npm": {
        "name": "Nginx Proxy Manager",
        "optional": False,
        "sources": [(APPDATA_ROOT / "Nginx-Proxy-Manager-Official", "Nginx-Proxy-Manager-Official")],
        "exclude_env": False,
    },
    "radarr": {
        "name": "Radarr",
        "optional": False,
        "sources": [(APPDATA_ROOT / "binhex-radarr", "binhex-radarr")],
        "exclude_env": False,
    },
    "sonarr": {
        "name": "Sonarr",
        "optional": False,
        "sources": [(APPDATA_ROOT / "binhex-sonarr", "binhex-sonarr")],
        "exclude_env": False,
    },
    "prowlarr": {
        "name": "Prowlarr",
        "optional": False,
        "sources": [(APPDATA_ROOT / "binhex-prowlarr", "binhex-prowlarr")],
        "exclude_env": False,
    },
    "qbittorrent": {
        "name": "qBittorrent",
        "optional": False,
        "sources": [
            (APPDATA_ROOT / "binhex-qbittorrent", "binhex-qbittorrent"),
            (APPDATA_ROOT / "qbittorrent", "qbittorrent"),
        ],
        "exclude_env": False,
    },
    "seerr": {
        "name": "Seerr",
        "optional": False,
        "sources": [(APPDATA_ROOT / "seerr", "seerr")],
        "exclude_env": False,
    },
    "skynet_mcp": {
        "name": "Skynet MCP Configuration",
        "optional": False,
        "sources": [(APPDATA_ROOT / "skynet-mcp", "skynet-mcp")],
        "exclude_env": True,
    },
    # Needs the read-only /boot:/host/boot mount. Unchecked by default in the UI because the
    # flash config holds secrets (licence key, share and user settings).
    "boot": {
        "name": "Unraid Boot Configuration",
        "optional": True,
        "sources": [(Path("/host/boot/config"), "boot/config")],
        "exclude_env": False,
    },
}

backup_state_lock = threading.Lock()
backup_jobs: dict[str, dict[str, Any]] = {}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def backup_options() -> list[dict[str, Any]]:
    options = []
    for item_id, item in BACKUP_ITEMS.items():
        existing = [str(path) for path, _ in item["sources"] if path.is_dir()]
        options.append({
            "id": item_id,
            "name": item["name"],
            "optional": item["optional"],
            "available": bool(existing),
            "source_count": len(existing),
        })
    return options


def backup_file_list(
    item: dict[str, Any],
) -> tuple[list[tuple[Path, str]], list[str], list[dict[str, str]]]:
    """Return (files to archive, missing source roots, entries that had to be skipped)."""
    files: list[tuple[Path, str]] = []
    missing: list[str] = []
    excluded: list[dict[str, str]] = []

    def record(path: Path, reason: str, kind: str = "file") -> None:
        excluded.append({"item": item["name"], "path": public_path(path), "reason": reason, "kind": kind})

    for root, archive_root in item["sources"]:
        if root.is_symlink():
            missing.append(public_path(root) + " (symlink skipped)")
            continue
        if not root.is_dir():
            missing.append(public_path(root))
            continue
        if not os.access(root, os.R_OK | os.X_OK):
            record(root, "Directory is not readable or searchable by the dashboard process", "directory")
            continue

        def walk_error(exc: OSError, root=root) -> None:
            record(Path(exc.filename or root), exc.strerror or str(exc), "directory")

        for current, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
            current_path = Path(current)
            kept_dirs = []
            for dirname in sorted(dirs):
                directory = current_path / dirname
                if directory.is_symlink():
                    continue
                if not os.access(directory, os.R_OK | os.X_OK):
                    record(directory, "Directory is not readable or searchable by the dashboard process", "directory")
                    continue
                kept_dirs.append(dirname)
            dirs[:] = kept_dirs

            for name in sorted(names):
                path = current_path / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    if item.get("exclude_env") and (name in BACKUP_EXCLUDED_NAMES or name.startswith(".env.")):
                        continue
                    if not os.access(path, os.R_OK):
                        record(path, "File is not readable by the dashboard process")
                        continue
                    arcname = str(Path(archive_root) / path.relative_to(root)).replace("\\", "/")
                    files.append((path, arcname))
                except (OSError, ValueError) as exc:
                    record(path, str(exc))
    return files, missing, excluded


def set_backup_job(job_id: str, **updates: Any) -> None:
    with backup_state_lock:
        if job_id in backup_jobs:
            backup_jobs[job_id].update(updates)
            backup_jobs[job_id]["updated_at"] = now_iso()


def run_backup_job(job_id: str, selected_ids: list[str]) -> None:
    partial_path: Path | None = None
    excluded_files: list[dict[str, str]] = []
    try:
        if not CENTRAL_BACKUP_DIR.is_dir():
            raise RuntimeError("Backup destination is not mounted or does not exist.")
        if not os.access(CENTRAL_BACKUP_DIR, os.W_OK):
            raise RuntimeError("Dashboard process cannot write to the backup destination.")

        timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        final_name = f"Skynet-backup-{timestamp}-{job_id[:8]}.zip"
        partial_path = CENTRAL_BACKUP_DIR / (final_name + ".partial")
        final_path = CENTRAL_BACKUP_DIR / final_name

        source_records = []
        all_files: list[tuple[str, Path, str]] = []
        missing_sources: list[str] = []
        for item_id in selected_ids:
            item = BACKUP_ITEMS[item_id]
            files, missing, excluded = backup_file_list(item)
            if not files and not excluded:
                raise RuntimeError(f"No files found for {item['name']}. Check that its source path is mounted.")
            excluded_files.extend(excluded)
            source_records.append({
                "id": item_id,
                "name": item["name"],
                "files": len(files),
                "discovered_files": len(files) + sum(1 for entry in excluded if entry["kind"] == "file"),
                "source_paths": [public_path(root) for root, _ in item["sources"] if root.is_dir()],
            })
            missing_sources.extend(missing)
            all_files.extend((item_id, path, arcname) for path, arcname in files)

        total_files = len(all_files)
        total_bytes = 0
        for _, path, _ in all_files:
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass

        free_bytes = shutil.disk_usage(CENTRAL_BACKUP_DIR).free
        if free_bytes < total_bytes:
            raise RuntimeError(
                f"Not enough free space at the destination: {total_bytes} bytes of source files, "
                f"{free_bytes} bytes free."
            )

        set_backup_job(
            job_id,
            status="Running",
            phase="Creating archive",
            total_files=total_files,
            files_done=0,
            total_bytes=total_bytes,
            bytes_done=0,
            archive=final_name,
            selected=[BACKUP_ITEMS[x]["name"] for x in selected_ids],
        )

        manifest = {
            "created_at": now_iso(),
            "host": "Skynet",
            "backup_type": "live configuration snapshot",
            "applications_paused": False,
            "database_consistency": "Not guaranteed. Running applications were not stopped.",
            "items": source_records,
            "missing_optional_sources": missing_sources,
            "excluded_files": excluded_files,
            "excluded": [
                "Media and downloads",
                "Immich database and photo libraries",
                "Plex",
                "Krusader",
                "Skynet MCP .env and .envx files",
                "Symlinks",
            ],
        }

        files_done = 0
        bytes_done = 0
        included_by_item = {item_id: 0 for item_id in selected_ids}
        with zipfile.ZipFile(partial_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=3, allowZip64=True) as archive:
            for item_id, path, arcname in all_files:
                info = None
                try:
                    info = path.stat()
                    source = path.open("rb")
                except OSError as exc:
                    excluded_files.append({
                        "item": BACKUP_ITEMS[item_id]["name"],
                        "path": public_path(path),
                        "reason": str(exc),
                        "kind": "file",
                    })
                    total_files = max(0, total_files - 1)
                    if info is not None:
                        total_bytes = max(0, total_bytes - info.st_size)
                    set_backup_job(
                        job_id,
                        phase="Skipping unreadable source file",
                        total_files=total_files,
                        total_bytes=total_bytes,
                        excluded_files=list(excluded_files),
                        excluded_count=len(excluded_files),
                    )
                    continue

                try:
                    with source:
                        # strict_timestamps=False clamps pre-1980 dates, which ZIP cannot store.
                        zip_info = zipfile.ZipInfo.from_file(path, arcname, strict_timestamps=False)
                        zip_info.compress_type = zipfile.ZIP_DEFLATED
                        with archive.open(zip_info, "w") as target:
                            shutil.copyfileobj(source, target, length=1024 * 1024)
                    bytes_done += info.st_size
                    files_done += 1
                    included_by_item[item_id] += 1
                    if files_done % 10 == 0 or files_done == total_files:
                        set_backup_job(job_id, phase="Writing files", files_done=files_done, bytes_done=bytes_done)
                except OSError as exc:
                    raise RuntimeError(
                        f"Read or archive error for {BACKUP_ITEMS[item_id]['name']}: {public_path(path)}"
                    ) from exc

            for record in source_records:
                record["files"] = included_by_item[record["id"]]
            manifest["excluded_files"] = excluded_files
            manifest["source_complete"] = not excluded_files and not missing_sources
            manifest["excluded_file_count"] = len(excluded_files)
            archive.writestr("BACKUP-MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True))

        os.chmod(partial_path, 0o600)
        set_backup_job(job_id, phase="Verifying archive", files_done=files_done, bytes_done=bytes_done)
        with zipfile.ZipFile(partial_path, "r") as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                raise RuntimeError(f"Archive verification failed at member: {bad_member}")

        os.replace(partial_path, final_path)
        partial_path = None
        complete = not excluded_files and not missing_sources
        set_backup_job(
            job_id,
            status="Completed",
            files_done=files_done,
            bytes_done=bytes_done,
            archive=final_name,
            archive_bytes=final_path.stat().st_size,
            integrity_verified=True,
            source_complete=complete,
            completeness_status="Complete" if complete else "Incomplete",
            excluded_count=len(excluded_files),
            excluded_files=list(excluded_files),
            missing_sources=missing_sources,
            phase="CRC passed, source complete" if complete else "CRC passed, source incomplete",
            destination=f"{BACKUP_DESTINATION_LABEL}/{final_name}",
            completed_at=now_iso(),
        )
    except Exception as exc:  # the job must always end in a visible state
        log.warning("backup job %s failed: %s", job_id[:8], exc)
        if partial_path is not None:
            try:
                partial_path.unlink(missing_ok=True)
            except OSError:
                pass
        set_backup_job(
            job_id,
            status="Failed",
            phase="Stopped",
            error=str(exc),
            integrity_verified=False,
            source_complete=False,
            completeness_status="Failed",
            excluded_count=len(excluded_files),
            excluded_files=list(excluded_files),
        )
    finally:
        backup_inventory.cache_clear()


def backup_job_snapshot() -> dict[str, Any]:
    with backup_state_lock:
        jobs = [dict(value) for value in backup_jobs.values()]
    archives = []
    if CENTRAL_BACKUP_DIR.is_dir():
        try:
            newest_first = sorted(
                CENTRAL_BACKUP_DIR.glob("Skynet-backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True
            )[:20]
        except OSError:
            newest_first = []
        for path in newest_first:
            try:
                stat = path.stat()
            except OSError:
                continue
            archives.append({
                "name": path.name,
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
            })
    return {
        "jobs": sorted(jobs, key=lambda x: x.get("created_at", ""), reverse=True),
        "archives": archives,
        "active": any(job.get("status") in ("Queued", "Running") for job in jobs),
    }


def launch_backup_worker(job_id: str, items: list[str]) -> None:
    threading.Thread(target=run_backup_job, args=(job_id, items), daemon=True).start()


def start_backup_job(items: list[str]) -> dict[str, Any]:
    with backup_state_lock:
        if any(job.get("status") in ("Queued", "Running") for job in backup_jobs.values()):
            raise HTTPException(409, "A backup job is already running.")
        job_id = uuid.uuid4().hex
        now = now_iso()
        selected = [BACKUP_ITEMS[item]["name"] for item in items]
        backup_jobs[job_id] = {
            "job_id": job_id,
            "status": "Queued",
            "phase": "Waiting to start",
            "created_at": now,
            "updated_at": now,
            "selected": selected,
            "files_done": 0,
            "total_files": 0,
            "bytes_done": 0,
            "total_bytes": 0,
            "integrity_verified": False,
            "source_complete": False,
            "completeness_status": "Pending",
            "excluded_count": 0,
            "excluded_files": [],
            "missing_sources": [],
        }
        # Keep the in-memory history bounded: drop the oldest finished jobs.
        finished = sorted(
            (j for j in backup_jobs.values() if j["status"] not in ("Queued", "Running")),
            key=lambda j: j["created_at"],
        )
        for old in finished[: max(0, len(backup_jobs) - MAX_KEPT_JOBS)]:
            del backup_jobs[old["job_id"]]
    launch_backup_worker(job_id, items)
    return {"job_id": job_id, "status": "Queued", "selected": selected}


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------

def require_auth(credentials: HTTPBasicCredentials = Depends(basic)):
    challenge = {"WWW-Authenticate": "Basic"}
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise HTTPException(503, "Admin credentials are not configured")
    if credentials is None:
        raise HTTPException(401, "Authentication required", headers=challenge)
    # Evaluate both comparisons so a wrong username takes as long as a wrong password.
    user_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"), ADMIN_USER.encode("utf-8")
    )
    pass_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")
    )
    if not (user_ok and pass_ok):
        raise HTTPException(401, "Invalid credentials", headers=challenge)
    return credentials.username


# ---------------------------------------------------------------------------
# docker
# ---------------------------------------------------------------------------

def get_docker_client():
    return docker.DockerClient(
        base_url=os.environ.get("DOCKER_HOST", "tcp://docker-socket-proxy:2375"),
        timeout=8,
    )


@contextmanager
def docker_session():
    client = None
    try:
        client = get_docker_client()
        yield client
    except (DockerException, requests.exceptions.RequestException) as exc:
        raise HTTPException(503, f"Docker API unavailable ({type(exc).__name__})") from exc
    finally:
        if client is not None:
            client.close()


# ---------------------------------------------------------------------------
# host health
# ---------------------------------------------------------------------------

def parse_meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    for line in read_text(HOST_PROC / "meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            unit = 1024 if len(parts) > 2 and parts[2].lower() == "kb" else 1
            out[parts[0].rstrip(":")] = int(parts[1]) * unit
    return out


def cpu_totals() -> tuple[int, int]:
    for line in read_text(HOST_PROC / "stat").splitlines():
        if line.startswith("cpu "):
            # user nice system idle iowait irq softirq steal; guest time is already in user.
            values = [int(x) for x in line.split()[1:9] if x.isdigit()]
            if len(values) >= 4:
                idle = values[3] + (values[4] if len(values) > 4 else 0)
                return sum(values), idle
    return 0, 0


def cpu_usage() -> float | None:
    first = cpu_totals()
    if not first[0]:
        return None
    time.sleep(0.5)
    second = cpu_totals()
    delta_total = second[0] - first[0]
    delta_idle = second[1] - first[1]
    if delta_total <= 0:
        return None
    return round(max(0.0, min(100.0, 100.0 * (delta_total - delta_idle) / delta_total)), 1)


def host_health_data() -> dict[str, Any]:
    memory = parse_meminfo()
    total = memory.get("MemTotal")
    available = memory.get("MemAvailable")
    used = max(0, total - available) if total is not None and available is not None else None

    uptime_parts = read_text(HOST_PROC / "uptime").split()
    uptime_seconds = int(float(uptime_parts[0])) if uptime_parts else None
    load_parts = read_text(HOST_PROC / "loadavg").split()
    cpu_root = HOST_SYS / "devices/system/cpu"
    cpu_cores = sum(
        1 for item in cpu_root.glob("cpu[0-9]*") if item.name[3:].isdigit()
    ) or os.cpu_count()

    return {
        "cpu_usage_percent": cpu_usage(),
        "load_average": " ".join(load_parts[:3]) if len(load_parts) >= 3 else None,
        "cpu_cores": cpu_cores,
        "memory_total_bytes": total,
        "memory_available_bytes": available,
        "memory_used_bytes": used,
        "memory_used_percent": round(100 * used / total, 1) if total and used is not None else None,
        "uptime_seconds": uptime_seconds,
        "uptime": (
            f"{uptime_seconds // 86400}d {(uptime_seconds % 86400) // 3600}h "
            f"{(uptime_seconds % 3600) // 60}m"
            if uptime_seconds is not None else None
        ),
        "source": "read-only host /proc and /sys mounts",
    }


def hardware_sensors() -> dict[str, Any]:
    readings: list[dict[str, Any]] = []
    for hwmon in sorted(HOST_SYS.glob("class/hwmon/hwmon*")):
        chip = read_text(hwmon / "name").strip() or hwmon.name
        for value_file in sorted(hwmon.glob("temp*_input")):
            raw = int_or_none(read_text(value_file).strip())
            if raw is None:
                continue
            index = value_file.name.removesuffix("_input")
            label = read_text(hwmon / f"{index}_label").strip() or index
            readings.append({
                "chip": chip,
                "sensor": label,
                "type": "temperature",
                "value_c": round(raw / 1000.0, 1),
            })
        for value_file in sorted(hwmon.glob("fan*_input")):
            raw = int_or_none(read_text(value_file).strip())
            if raw is None:
                continue
            index = value_file.name.removesuffix("_input")
            label = read_text(hwmon / f"{index}_label").strip() or index
            readings.append({
                "chip": chip,
                "sensor": label,
                "type": "fan",
                "value_rpm": raw,
            })
    return {
        "available": bool(readings),
        "readings": readings,
        "source": "host /sys/class/hwmon",
        "note": "A reported 0 RPM is shown as reported. It is not independently interpreted as fan failure.",
    }


# ---------------------------------------------------------------------------
# array, SMART and storage
# ---------------------------------------------------------------------------

def array_status() -> dict[str, Any]:
    values = parse_key_values(EMHTTP / "var.ini")
    allowed = {
        "mdState", "mdResync", "mdResyncPos", "mdResyncSize", "mdResyncAction",
        "mdNumDisks", "mdNumDisabled", "mdNumInvalid", "mdNumMissing",
        "mdResyncCorr", "mdResyncErr", "mdResyncDt", "mdResyncDb",
        "sbSyncErrs", "sbSyncExit",
    }
    selected = {key: value for key, value in values.items() if key in allowed}
    return {
        "available": bool(values),
        "status_source": "/var/local/emhttp/var.ini",
        "status": selected,
        "note": "Array summary counters are shown separately from the actual configured slot inventory.",
    }


SMART_ATTRIBUTES = {
    5: "reallocated_sectors",
    9: "power_on_hours",
    177: "wear_leveling_count",
    179: "used_reserved_blocks",
    181: "program_fail_count",
    182: "erase_fail_count",
    183: "runtime_bad_blocks",
    184: "end_to_end_error",
    187: "reported_uncorrectable",
    190: "airflow_temperature_c",
    194: "temperature_c",
    196: "reallocation_events",
    197: "pending_sectors",
    198: "offline_uncorrectable",
    199: "crc_errors",
    235: "por_recovery_count",
}
SMART_CRITICAL_KEYS = (
    "pending_sectors", "offline_uncorrectable", "runtime_bad_blocks",
    "reported_uncorrectable", "end_to_end_error",
)
SMART_ATTENTION_KEYS = (
    "reallocated_sectors", "reallocation_events", "crc_errors",
    "program_fail_count", "erase_fail_count",
)

# 190 airflow temperature, 194 temperature, 231 temperature (SSD): "In_the_past" only means it ran hot once.
SMART_TEMPERATURE_IDS = {190, 194, 231}

# smartctl -A rows: ID NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE
SMART_ROW = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+0x[0-9a-fA-F]+\s+(\d+)\s+(\d+)\s+(\d+)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$"
)
# NVMe health log: "Percentage Used:   1%"
NVME_ROW = re.compile(r"^\s*([A-Za-z][A-Za-z ]+?):\s+(\S.*?)\s*$")
NVME_FIELDS = {
    "critical warning": "critical_warning",
    "temperature": "temperature_c",
    "available spare": "available_spare_percent",
    "available spare threshold": "available_spare_threshold_percent",
    "percentage used": "percentage_used",
    "power on hours": "power_on_hours",
    "media and data integrity errors": "media_errors",
    "unsafe shutdowns": "unsafe_shutdowns",
}


def leading_int(raw: str) -> int | None:
    # Handles "36 (Min/Max 22/45)" and Seagate's "26485h+12m+10.1s".
    match = re.match(r"\s*(-?\d+)", raw)
    return int(match.group(1)) if match else None


def nvme_value(text: str) -> int | None:
    token = text.split()[0].replace(",", "").rstrip("%")
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return None


def parse_smart_report(section_name: str, spun_down: bool = False) -> dict[str, Any] | None:
    path = SMART_DIR / section_name
    if not path.is_file():
        return None
    try:
        stat = path.stat()
        age_seconds = max(0, int(time.time() - stat.st_mtime))
        checked_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).astimezone().isoformat(timespec="seconds")
    except OSError:
        age_seconds = None
        checked_at = None

    text = read_text(path)
    attributes: dict[str, int] = {}
    failing_now: list[str] = []
    failed_before: list[str] = []
    notes: list[str] = []
    for line in text.splitlines():
        row = SMART_ROW.match(line)
        if row:
            attribute_id = int(row.group(1))
            when_failed = row.group(8).lower()
            if when_failed.startswith("failing"):
                failing_now.append(row.group(2))
            elif when_failed not in ("-", ""):
                if attribute_id in SMART_TEMPERATURE_IDS:
                    notes.append(f"{row.group(2)} reached its threshold in the past (the drive ran hot at some point)")
                else:
                    failed_before.append(row.group(2))
            if attribute_id in SMART_ATTRIBUTES:
                value = leading_int(row.group(9))
                if value is not None:
                    if attribute_id in (190, 194) and value > 150:
                        value &= 0xFF  # some drives pack min/max into the raw value
                    attributes[SMART_ATTRIBUTES[attribute_id]] = value
            continue
        nvme = NVME_ROW.match(line)
        if nvme and nvme.group(1).strip().lower() in NVME_FIELDS:
            value = nvme_value(nvme.group(2))
            if value is not None:
                attributes[NVME_FIELDS[nvme.group(1).strip().lower()]] = value

    # These reports contain attribute tables, not the overall SMART self-assessment line.
    critical = [key for key in SMART_CRITICAL_KEYS if attributes.get(key, 0) > 0]
    attention = [key for key in SMART_ATTENTION_KEYS if attributes.get(key, 0) > 0]
    if attributes.get("critical_warning", 0):
        critical.append("critical_warning")
    if attributes.get("media_errors", 0) > 0:
        critical.append("media_errors")
    spare = attributes.get("available_spare_percent")
    spare_threshold = attributes.get("available_spare_threshold_percent")
    if spare is not None and spare_threshold is not None and spare < spare_threshold:
        critical.append("available_spare")
    if attributes.get("percentage_used", 0) >= 90:
        attention.append("percentage_used")
    critical += [f"failing_now:{name}" for name in failing_now]
    attention += [f"failed_in_past:{name}" for name in failed_before]

    if critical:
        assessment = "Attention required"
    elif attention:
        assessment = "Review attributes"
    elif attributes:
        assessment = "No flagged attributes"
    else:
        assessment = "No parsed attributes"

    return {
        "report": section_name,
        "available": bool(text),
        "checked_at": checked_at,
        "age_seconds": age_seconds,
        # A spun-down disk is not refreshed, so its old report is expected, not stale.
        "stale": (not spun_down) and age_seconds is not None and age_seconds > 86400,
        "assessment": assessment,
        "attention_attributes": attention,
        "critical_attributes": critical,
        "attributes": attributes,
        "notes": notes,
        "overall_smart_passed": None,
        "note": "Cached SMART attributes only. The report does not contain an overall SMART PASSED/FAILED result.",
    }


def disk_inventory() -> dict[str, Any]:
    sections = parse_ini_sections(EMHTTP / "disks.ini")
    inventory: list[dict[str, Any]] = []
    for section_name, fields in sections.items():
        device = fields.get("device", "")
        role = fields.get("type", "")
        mountpoint = fields.get("fsMountpoint", "")
        spun_down = fields.get("spundown") == "1"
        smart = parse_smart_report(section_name, spun_down)

        inventory.append({
            "slot": section_name,
            "index": int_or_none(fields.get("idx")),
            "name": fields.get("name", section_name),
            "role": role,
            "device": device or None,
            "serial": mask_serial(fields.get("id") or fields.get("idSb")),
            "size_bytes": kib_to_bytes(fields.get("size")),
            "status": fields.get("status") or "Unknown",
            "slot_state": classify_disk_status(
                fields.get("status") or "Unknown", bool(device), kib_to_bytes(fields.get("size"))
            ),
            "spun_down": spun_down,
            "temperature_c": int_or_none(fields.get("temp")) if fields.get("temp") not in ("", "*", None) else None,
            "read_errors": int_or_none(fields.get("numErrors")),
            "fs_type": fields.get("fsType") or None,
            "fs_status": fields.get("fsStatus") or None,
            "mountpoint": mountpoint or None,
            "fs_size_bytes": kib_to_bytes(fields.get("fsSize")),
            "fs_used_bytes": kib_to_bytes(fields.get("fsUsed")),
            "fs_free_bytes": kib_to_bytes(fields.get("fsFree")),
            "smart": smart,
        })

    role_order = {"Parity": 0, "Data": 1, "Cache": 2, "Boot": 3, "Flash": 3}
    inventory.sort(key=lambda item: (
        role_order.get(item["role"], 9),
        item["index"] if item["index"] is not None else 999,
        item["name"],
    ))
    return {
        "available": bool(sections),
        "source": "/var/local/emhttp/disks.ini",
        "count": len(inventory),
        "devices": inventory,
    }


def volume_usage(name: str, role: str, mount: str, host_path: Path) -> dict[str, Any]:
    try:
        stats = os.statvfs(host_path)
    except OSError as exc:
        return {"name": name, "role": role, "mount": mount, "error": str(exc)}
    total = stats.f_blocks * stats.f_frsize
    free = stats.f_bavail * stats.f_frsize
    used = max(0, total - stats.f_bfree * stats.f_frsize)
    return {
        "name": name,
        "role": role,
        "mount": mount,
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": free,
        "used_percent": round(100 * used / total, 1) if total else None,
    }


def storage() -> list[dict[str, Any]]:
    # Discover mounted array disks and pools from Unraid's inventory, not a fixed disk list.
    sections = parse_ini_sections(EMHTTP / "disks.ini")
    out: list[dict[str, Any]] = []
    seen_mounts: set[str] = set()

    for section_name, fields in sections.items():
        mountpoint = fields.get("fsMountpoint", "").strip()
        if not mountpoint or not re.fullmatch(r"/mnt/(?:disk\d+|[A-Za-z0-9_.-]+)", mountpoint):
            continue
        if fields.get("fsStatus", "Mounted") not in ("Mounted", ""):
            continue  # e.g. an unassigned slot (fsStatus "-")
        if mountpoint in seen_mounts:
            continue
        seen_mounts.add(mountpoint)
        out.append(volume_usage(
            fields.get("name", section_name),
            fields.get("type", ""),
            mountpoint,
            HOST_MNT / mountpoint.removeprefix("/mnt/"),
        ))

    for name, role, host_path, mount in OPTIONAL_VOLUMES:
        if mount not in seen_mounts and host_path.is_dir():
            out.append(volume_usage(name, role, mount, host_path))
    return out


def classify_disk_status(status: str, has_device: bool, size_bytes: int | None) -> str:
    s = (status or "").upper()
    if s == "DISK_OK":
        return "ok"
    # An empty slot (no device, no configured size) is not a failure, whatever its NP code.
    if not has_device and not size_bytes and (s.startswith("DISK_NP") or s in ("", "UNKNOWN")):
        return "unassigned"
    if "DSBL" in s:
        return "disabled"
    if "MISSING" in s or s.startswith("DISK_NP"):
        return "missing"
    if "INVALID" in s or "WRONG" in s:
        return "invalid"
    if s == "DISK_NEW":
        return "new"
    return "unknown"


def health_summary(array: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    values = array.get("status", {})
    devices = inventory.get("devices", [])
    array_state = values.get("mdState") or "Unknown"

    def counter(key: str) -> int:
        return int_or_none(values.get(key)) or 0

    issues: list[str] = []
    degraded = False
    attention = False
    data_needing_attention: list[str] = []
    unassigned_parity: list[str] = []
    parity_assigned = 0
    configured_data = 0
    unassigned_disabled = 0

    for disk in devices:
        role = disk["role"]
        if role not in ("Parity", "Data", "Cache", "Boot"):
            continue
        has_device = bool(disk["device"])
        kind = classify_disk_status(disk["status"], has_device, disk.get("size_bytes"))
        if role == "Parity":
            if has_device:
                parity_assigned += 1
            elif kind == "unassigned":
                unassigned_parity.append(disk["name"])
        if role == "Data" and has_device:
            configured_data += 1
        if kind == "unassigned":
            if "DSBL" in (disk["status"] or "").upper():
                unassigned_disabled += 1
            continue

        problem = False
        if kind in ("disabled", "missing", "invalid"):
            degraded = problem = True
            issues.append(f"{disk['name']}: {kind} ({disk['status']})")
        elif kind != "ok":
            attention = problem = True
            issues.append(f"{disk['name']}: status {disk['status']}")
        if (disk.get("read_errors") or 0) > 0:
            attention = problem = True
            issues.append(f"{disk['name']}: {disk['read_errors']} read errors")
        critical = (disk.get("smart") or {}).get("critical_attributes") or []
        if critical:
            attention = problem = True
            issues.append(f"{disk['name']}: SMART critical: {', '.join(critical)}")
        if problem and role == "Data":
            data_needing_attention.append(disk["name"])

    # Cross-check against the array's own counters in case the slot parse missed something.
    # An empty parity2 slot is reported as DISK_NP_DSBL, and Unraid counts it as one disabled and
    # one invalid device even on a healthy array. Only counts beyond those empty slots are a problem.
    flagged = {
        "mdNumDisabled": counter("mdNumDisabled") - unassigned_disabled,
        "mdNumInvalid": counter("mdNumInvalid") - unassigned_disabled,
        "mdNumMissing": counter("mdNumMissing"),
    }
    if not degraded and any(v > 0 for v in flagged.values()):
        degraded = True
        issues.append("Array reports unexplained " + ", ".join(
            f"{k[5:].lower()}: {v}" for k, v in flagged.items() if v > 0
        ))
    if configured_data and parity_assigned == 0:
        attention = True
        issues.append("No parity disk assigned")
    if counter("sbSyncErrs") > 0:
        attention = True
        issues.append(f"Last parity operation reported {counter('sbSyncErrs')} sync errors")

    resync_total = counter("mdResync")
    resync_size = counter("mdResyncSize")
    running = resync_total > 0
    parity_operation = {
        "running": running,
        "action": (values.get("mdResyncAction") or None) if running else None,
        "percent": (
            round(100 * counter("mdResyncPos") / resync_size, 1)
            if running and resync_size > 0 else None
        ),
    }

    if array_state == "STOPPED":
        state = "Stopped"
    elif array_state != "STARTED":
        state = "Unknown"
    elif degraded:
        state = "Degraded"
    elif attention:
        state = "Attention"
    else:
        state = "Healthy"

    return {
        "state": state,
        "array_state": array_state,
        "configured_data_disks": configured_data,
        "data_disks_needing_attention": data_needing_attention,
        "unassigned_parity_slots": unassigned_parity,
        "issues": issues if array_state == "STARTED" else [],
        "parity_operation": parity_operation,
        "note": (
            "Degraded means a data, parity or cache device is disabled, missing or invalid. "
            "Unassigned slots are reported separately and are not counted as failures."
        ),
    }


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Skynet Remote Admin</title>
<style nonce="__NONCE__">
body{font-family:system-ui,sans-serif;max-width:1500px;margin:2rem auto;padding:0 1rem;background:#101418;color:#edf2f7}
h1{font-size:1.7rem}h2{margin-top:0}button{padding:.65rem 1rem;margin:.2rem;border:0;border-radius:.4rem;cursor:pointer}
.panel{background:#1b232b;border:1px solid #34404b;border-radius:.6rem;padding:1rem;margin:1rem 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:28rem;overflow:auto;background:#0b0f12;padding:1rem;border-radius:.4rem}
table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{text-align:left;padding:.35rem;border-bottom:1px solid #34404b;white-space:normal;overflow-wrap:anywhere;font-size:.82rem}
.small{color:#aebbc8;font-size:.9rem}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.7rem}
.metric{background:#10171d;border:1px solid #34404b;border-radius:.5rem;padding:.8rem}.metric strong{display:block;font-size:1.15rem;margin-top:.25rem}
.good{color:#8ee0a1}.warn{color:#ffd27a}.bad{color:#ff9292}
.opt{display:block;margin:.45rem 0}
</style></head><body>
<h1>Skynet Remote Admin</h1><p class="small">Diagnostics and scoped configuration backups. No container or array changes can be made here.</p>
<div class="panel"><h2>Host health</h2><button data-action="loadHealth">Refresh host health</button> <label class="small"><input type="checkbox" id="autoRefresh" checked> Auto-refresh health and array every 60 s</label><div id="healthCards" class="cards">Loading...</div><div id="sensorTable"></div></div>
<div class="panel"><h2>Array and storage</h2><button data-action="loadArray">Refresh array and storage</button><div id="arraySummary"></div><div id="inventory"></div><h3>SMART attributes</h3><div id="smartDetails"></div><h3>Mounted storage</h3><div id="storage"></div></div>
<div class="panel"><h2>Docker</h2><button data-action="loadStatus">Refresh Docker status</button><button data-action="loadContainers">List containers</button><div id="status">Choose an action.</div><div id="containerTable"></div></div>
<div class="panel"><h2>Container logs</h2><label for="container">Exact container name</label> <input id="container" placeholder="e.g. binhex-qbittorrent" autocomplete="off"> <label for="tail">Log lines</label> <select id="tail"><option>50</option><option selected>100</option><option>200</option><option>300</option></select><button data-action="loadLogs">Read logs</button><div id="logStatus" class="small"></div></div>
<div class="panel"><h2>Details</h2><pre id="output">Results appear here.</pre></div>
<div class="panel"><h2>Backup manager</h2>
<p class="small">Select configuration items to archive. Running applications are not stopped. These are live snapshots, so database consistency is not guaranteed. Archives are CRC-verified before they are finalized. Archives can contain secrets such as keys, certificates and password hashes, so keep the destination folder private.</p>
<div id="backupOptions">Loading backup options...</div>
<button data-action="startBackup">Start selected backup</button><button data-action="loadBackups">Refresh backup status</button>
<div id="backupRunStatus" class="small"></div>
<h3>Backup health</h3>
<div id="backupSummary"></div><div id="backupTable"></div>
<h3>Recent backup jobs</h3><div id="backupJobs"></div>
<h3>Excluded source files</h3><div id="backupExclusions"></div>
<h3>Archives in destination</h3><div id="backupArchives"></div></div>
<script nonce="__NONCE__">
const $=id=>document.getElementById(id);
async function api(p){const r=await fetch(p,{cache:"no-store"}),b=await r.text();if(!r.ok)throw Error("HTTP "+r.status+": "+b);return JSON.parse(b)}
function show(v){$("output").textContent=typeof v==="string"?v:JSON.stringify(v,null,2)}
function ts(v){const d=new Date(v);return isNaN(d)?v:d.toLocaleString()}
function fmt(b){if(b==null)return"Unavailable";let u=["B","KiB","MiB","GiB","TiB"],i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(i?1:0)+" "+u[i]}
const TONES=[
 [/^(Healthy|Recent|DISK_OK|OK|No flagged attributes|running|healthy|Completed|Complete|Passed)$/,"good"],
 [/^(Degraded|Stale|Missing folder|No backup files|Attention required|FAILED|Failed|Incomplete|DISK_DSBL|DISK_INVALID|DISK_NP_DSBL|unhealthy|dead)/,"bad"],
 [/^(Check|Review attributes|Attention|Running|Queued|Not present \(optional\)|DISK_NEW|exited|restarting|paused|created|Stopped|Unknown|No parsed attributes)/,"warn"]
];
function tone(t){for(const [re,c] of TONES)if(re.test(t))return c;return""}
function table(target,headers,rows){const root=$(target);root.textContent="";if(!rows.length){root.textContent="No data available.";return}
 const t=document.createElement("table"),h=document.createElement("tr");
 for(const x of headers){const c=document.createElement("th");c.textContent=x;h.append(c)}
 t.append(h);
 for(const row of rows){const tr=document.createElement("tr");
  for(const value of row){const c=document.createElement("td"),s=value==null?"Unavailable":String(value);c.textContent=s;const k=tone(s);if(k)c.className=k;tr.append(c)}
  t.append(tr)}
 root.append(t)}
function summary(target,text,items,cls){const root=$(target);root.textContent="";const p=document.createElement("p");p.textContent=text;if(cls)p.className=cls;root.append(p);
 if(items&&items.length){const ul=document.createElement("ul");for(const i of items){const li=document.createElement("li");li.textContent=i;ul.append(li)}root.append(ul)}}
async function loadHealth(quiet){
 const e=$("healthCards");
 const [h,s]=await Promise.allSettled([api("/api/host-health"),api("/api/hardware")]);
 e.textContent="";
 if(h.status==="fulfilled"){const d=h.value;
  for(const [k,v] of [["CPU usage",d.cpu_usage_percent==null?"Unavailable":d.cpu_usage_percent+"%"],["Load average",d.load_average||"Unavailable"],["Memory used",fmt(d.memory_used_bytes)+" / "+fmt(d.memory_total_bytes)],["Memory use",d.memory_used_percent==null?"Unavailable":d.memory_used_percent+"%"],["Uptime",d.uptime||"Unavailable"],["CPU cores",d.cpu_cores??"Unavailable"]]){
   const c=document.createElement("div");c.className="metric";const l=document.createElement("span");l.className="small";l.textContent=k;const x=document.createElement("strong");x.textContent=v;c.append(l,x);e.append(c)}
 }else e.textContent=h.reason.message;
 if(s.status==="fulfilled")table("sensorTable",["Chip","Sensor","Reading"],s.value.readings.map(x=>[x.chip,x.sensor,x.type==="fan"?x.value_rpm+" RPM":x.value_c+" \u00b0C"]));
 else $("sensorTable").textContent=s.reason.message;
 if(!quiet)show({host:h.status==="fulfilled"?h.value:String(h.reason),hardware:s.status==="fulfilled"?s.value:String(s.reason)})}
async function loadArray(quiet){try{
 const d=await api("/api/array-storage"),a=d.health,p=a.parity_operation;
 let text="Array: "+a.state+" (Unraid state: "+a.array_state+"). Configured data disks: "+a.configured_data_disks+".";
 if(p&&p.running)text+=" Parity operation: "+(p.action||"running")+(p.percent!=null?" "+p.percent+"%":"")+".";
 summary("arraySummary",text,a.issues,tone(a.state));
 table("inventory",["Slot","Role","Device","Serial","Unraid status","Temp \u00b0C","Errors","SMART assessment","SMART checked"],d.inventory.devices.map(x=>[x.name,x.role,x.device,x.serial,x.slot_state==="unassigned"?"Empty slot ("+x.status+")":x.status,x.temperature_c,x.read_errors,x.smart?(x.smart.assessment+(x.smart.stale?" (stale)":"")):"No report",x.smart?(ts(x.smart.checked_at)+(x.spun_down?" (disk spun down)":"")):"Unavailable"]));
 table("smartDetails",["Disk","Assessment","Reallocated","Pending","Offline uncorrectable","Reported uncorrectable","CRC errors","Power-on hours"],d.inventory.devices.filter(x=>["Parity","Data","Cache"].includes(x.role)&&x.slot_state!=="unassigned").map(x=>{const s=x.smart||{},a=s.attributes||{};return [x.name,s.assessment||"No report",a.reallocated_sectors??"Unavailable",a.pending_sectors??"Unavailable",a.offline_uncorrectable??"Unavailable",a.reported_uncorrectable??"Unavailable",a.crc_errors??"Unavailable",a.power_on_hours??"Unavailable"]}));
 table("storage",["Volume","Role","Mount","Used","Available","Capacity","Used %"],d.storage.map(x=>[x.name,x.role,x.mount,x.used_bytes==null?"Unavailable":fmt(x.used_bytes),x.available_bytes==null?"Unavailable":fmt(x.available_bytes),x.total_bytes==null?"Unavailable":fmt(x.total_bytes),x.used_percent==null?"Unavailable":x.used_percent+"%"]));
 if(!quiet)show(d)}catch(x){$("arraySummary").textContent=x.message}}
async function loadBackupOptions(){try{
 const d=await api("/api/backups/options"),root=$("backupOptions");root.textContent="";
 for(const item of d.items){const label=document.createElement("label");label.className="opt";
  const input=document.createElement("input");input.type="checkbox";input.value=item.id;input.disabled=!item.available;input.checked=item.available&&!item.optional;
  label.append(input,document.createTextNode(" "+item.name+(item.optional?" (optional)":"")+(item.available?"":" (source unavailable)")));root.append(label)}
 }catch(e){$("backupOptions").textContent=e.message}}
async function startBackup(){
 const selected=[...document.querySelectorAll("#backupOptions input:checked")].map(x=>x.value),status=$("backupRunStatus");
 if(!selected.length){status.textContent="Select at least one available item.";return}
 status.textContent="Submitting backup job...";
 try{const r=await fetch("/api/backups/run",{method:"POST",headers:{"Content-Type":"application/json","X-Requested-With":"skynet-admin"},body:JSON.stringify({items:selected}),cache:"no-store"});
  const b=await r.text();if(!r.ok)throw Error("HTTP "+r.status+": "+b);
  status.textContent="Backup job started.";pollBackups()}catch(e){status.textContent=e.message}}
function pollBackups(){loadBackups(true).then(active=>{if(active)setTimeout(pollBackups,3000);else if($("backupRunStatus").textContent==="Backup job started.")$("backupRunStatus").textContent="Backup job finished. See Recent backup jobs."})}
async function loadBackups(quiet){try{
 const [d,j]=await Promise.all([api("/api/backups"),api("/api/backups/jobs")]);
 const count=d.sources.reduce((n,x)=>n+x.file_count,0),total=d.sources.reduce((n,x)=>n+x.total_bytes,0);
 const zipTested=d.sources.filter(x=>x.latest_zip_ok!=null).length,zipOk=d.sources.filter(x=>x.latest_zip_ok===true).length;
 summary("backupSummary","Known app-native backup files: "+count+". Total size: "+fmt(total)+". Central destination ("+d.central_destination+"): "+(d.central_destination_exists?"Present":"Unavailable")+". Latest ZIP archives passing CRC test: "+zipOk+" of "+zipTested+". A passing test does not prove a restore works.");
 table("backupTable",["Application","Status","Files","Total size","Latest backup","Age days","Latest size","ZIP CRC","Warnings"],d.sources.map(x=>[x.application,x.status,x.file_count,fmt(x.total_bytes),x.latest_timestamp||"None",x.age_days??"Unavailable",x.latest_size_bytes==null?"Unavailable":fmt(x.latest_size_bytes),x.latest_zip_ok===true?"OK":x.latest_zip_ok===false?"FAILED":"n/a",x.warnings.join("; ")||"None"]));
 table("backupJobs",["Status","Phase","Selected items","Progress","Archive","ZIP CRC","Source complete","Excluded","Error"],j.jobs.map(x=>[x.status,x.phase,(x.selected||[]).join(", "),x.total_files?(x.files_done+"/"+x.total_files):"Preparing",x.archive||"Not created",x.integrity_verified?"Passed":"No",x.source_complete?"Yes":(x.completeness_status||"Pending"),x.excluded_count||0,x.error||""]));
 table("backupExclusions",["Job","Application","Path","Reason"],j.jobs.flatMap(x=>(x.excluded_files||[]).map(e=>[x.archive||x.job_id,e.item,e.path,e.reason])));
 table("backupArchives",["Archive","Size","Modified"],j.archives.map(x=>[x.name,fmt(x.size_bytes),ts(x.modified)]));
 if(!quiet)show({inventory:d,jobs:j.jobs,archives:j.archives});
 return j.active}catch(e){$("backupSummary").textContent=e.message;return false}}
async function loadStatus(){try{$("status").textContent="Loading...";show(await api("/api/host"));$("status").textContent="Docker host reachable."}catch(e){$("status").textContent=e.message}}
async function loadContainers(){try{$("status").textContent="Loading...";
 const d=await api("/api/containers");
 const running=d.filter(x=>x.state==="running").length,unhealthy=d.filter(x=>x.health==="unhealthy").length,restarts=d.filter(x=>x.restart_count>0).length;
 $("status").textContent=d.length+" containers: "+running+" running, "+(d.length-running)+" not running, "+unhealthy+" unhealthy, "+restarts+" with restarts.";
 table("containerTable",["Name","State","Health","Restarts","Exit code","Started","Image"],d.map(x=>[x.name,x.state,x.health,x.restart_count,x.exit_code,x.started_at,x.image]));
 show(d)}catch(e){$("status").textContent=e.message}}
async function loadLogs(){const s=$("logStatus");try{
 const n=$("container").value.trim(),t=$("tail").value;if(!n)throw Error("Enter an exact container name.");
 s.textContent="Loading...";
 const d=await api("/api/logs?name="+encodeURIComponent(n)+"&tail="+encodeURIComponent(t));
 s.textContent=d.container+": "+d.line_count+" lines, "+d.redactions+" secret-like values redacted"+(d.truncated?", output truncated":"")+".";
 show(d.logs||"(no output)")}catch(e){s.textContent=e.message}}
const actions={loadHealth:()=>loadHealth(false),loadArray:()=>loadArray(false),loadBackups:()=>loadBackups(false),startBackup,loadStatus,loadContainers,loadLogs};
document.addEventListener("click",ev=>{const b=ev.target.closest("[data-action]");if(b&&actions[b.dataset.action])actions[b.dataset.action]()});
$("container").addEventListener("keydown",ev=>{if(ev.key==="Enter")loadLogs()});
setInterval(()=>{if($("autoRefresh").checked&&!document.hidden){loadHealth(true);loadArray(true)}},60000);
loadHealth(true);loadArray(true);loadBackupOptions();loadBackups(true);
</script></body></html>"""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(_: str = Depends(require_auth)):
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "connect-src 'self'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return HTMLResponse(
        DASHBOARD_HTML.replace("__NONCE__", nonce),
        headers={"Content-Security-Policy": csp},
    )


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/api/host")
def host(_: str = Depends(require_auth)) -> dict[str, Any]:
    with docker_session() as client:
        info = client.info()
        version = client.version()
        return {
            "name": info.get("Name"),
            "server_version": version.get("Version"),
            "operating_system": info.get("OperatingSystem"),
            "architecture": info.get("Architecture"),
            "cpus": info.get("NCPU"),
            "memory_bytes": info.get("MemTotal"),
            "containers_total": info.get("Containers"),
            "containers_running": info.get("ContainersRunning"),
            "containers_stopped": info.get("ContainersStopped"),
            "images": info.get("Images"),
        }


@app.get("/api/host-health")
def host_health(_: str = Depends(require_auth)) -> dict[str, Any]:
    return host_health_data()


@app.get("/api/hardware")
def hardware(_: str = Depends(require_auth)) -> dict[str, Any]:
    return hardware_sensors()


@app.get("/api/array-storage")
def array_storage(_: str = Depends(require_auth)) -> dict[str, Any]:
    array = array_status()
    inventory = disk_inventory()
    return {
        "array": array,
        "health": health_summary(array, inventory),
        "inventory": inventory,
        "storage": storage(),
    }


@app.get("/api/backups")
def backups(_: str = Depends(require_auth)) -> dict[str, Any]:
    return backup_inventory()


def require_custom_header(request: Request) -> None:
    """State-changing calls must carry a header that a page on another site cannot add.

    Browsers attach saved Basic credentials to cross-site requests automatically, so a
    malicious page could otherwise submit a POST. Setting a custom header needs a CORS
    preflight, which this app never grants.
    """
    if request.headers.get("x-requested-with") != "skynet-admin":
        raise HTTPException(403, "Missing X-Requested-With header")


@app.get("/api/backups/options")
def backups_options(_: str = Depends(require_auth)) -> dict[str, Any]:
    return {"items": backup_options(), "destination": BACKUP_DESTINATION_LABEL}


@app.get("/api/backups/jobs")
def backups_jobs(_: str = Depends(require_auth)) -> dict[str, Any]:
    return backup_job_snapshot()


@app.post("/api/backups/run")
def backups_run(
    items: list[str] = Body(..., embed=True),
    _: str = Depends(require_auth),
    __: None = Depends(require_custom_header),
) -> dict[str, Any]:
    if not items:
        raise HTTPException(400, "Select at least one backup item.")
    if len(items) > len(BACKUP_ITEMS) or len(set(items)) != len(items):
        raise HTTPException(400, "Invalid backup selection.")
    if any(item not in BACKUP_ITEMS for item in items):
        raise HTTPException(400, "Unknown backup item selection.")
    unavailable = [
        BACKUP_ITEMS[item]["name"] for item in items
        if not any(root.is_dir() for root, _arc in BACKUP_ITEMS[item]["sources"])
    ]
    if unavailable:
        raise HTTPException(400, "Source not available: " + ", ".join(unavailable))
    return start_backup_job(items)


@app.get("/api/containers")
def containers(_: str = Depends(require_auth)) -> list[dict[str, Any]]:
    with docker_session() as client:
        output = []
        for container in client.containers.list(all=True):
            attrs = container.attrs or {}
            state = attrs.get("State", {})
            output.append({
                "name": container.name,
                "id": container.short_id,
                "image": attrs.get("Config", {}).get("Image", ""),
                "status": container.status,
                "state": state.get("Status", ""),
                "started_at": state.get("StartedAt", ""),
                "health": state.get("Health", {}).get("Status", "not-reported"),
                "restart_count": attrs.get("RestartCount", 0),
                "exit_code": state.get("ExitCode"),
            })
        return sorted(output, key=lambda item: item["name"].lower())


@app.get("/api/logs")
def logs(name: str, tail: int = 100, _: str = Depends(require_auth)) -> dict[str, Any]:
    if not CONTAINER_NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid container name")
    if not 1 <= tail <= 300:
        raise HTTPException(400, "tail must be from 1 to 300")
    with docker_session() as client:
        # The name filter is a regex substring match, so narrow it and then require equality.
        candidates = client.containers.list(all=True, filters={"name": f"^/{re.escape(name)}$"})
        matches = [container for container in candidates if container.name == name]
        if not matches:
            raise HTTPException(404, "No exact container name match")
        raw = matches[0].logs(stdout=True, stderr=True, tail=tail, timestamps=True)
    result = sanitize_logs(raw.decode("utf-8", errors="replace"))
    return {"container": name, "tail": tail, **result}
