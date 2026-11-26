"""Tests for the backup manager: archive contents, safety rules, API guards."""
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

import server

SHIPPED_ITEMS = server.BACKUP_ITEMS  # captured at import, before any test patches it
AUTH = ("admin", "correct-horse-battery")
HEADERS = {"X-Requested-With": "skynet-admin"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Two fake applications, an unavailable one, and an empty destination folder."""
    seerr = tmp_path / "appdata" / "seerr"
    mcp = tmp_path / "appdata" / "skynet-mcp"
    (seerr / "db").mkdir(parents=True)
    mcp.mkdir(parents=True)
    (seerr / "settings.json").write_text('{"a": 1}')
    (seerr / "db" / "db.sqlite3").write_bytes(b"x" * 5000)
    (mcp / "docker-compose.yml").write_text("services: {}")
    (mcp / ".env").write_text("ADMIN_PASSWORD=secret")
    (mcp / ".envx").write_text("secret")
    (mcp / ".env.local").write_text("secret")
    dest = tmp_path / "dest"
    dest.mkdir()
    monkeypatch.setattr(server, "BACKUP_ITEMS", {
        "seerr": {"name": "Seerr", "optional": False, "sources": [(seerr, "seerr")], "exclude_env": False},
        "mcp": {"name": "MCP", "optional": False, "sources": [(mcp, "skynet-mcp")], "exclude_env": True},
        "gone": {"name": "Gone", "optional": True, "sources": [(tmp_path / "nope", "nope")], "exclude_env": False},
    })
    monkeypatch.setattr(server, "CENTRAL_BACKUP_DIR", dest)
    monkeypatch.setattr(server, "backup_jobs", {})
    monkeypatch.setattr(server, "ADMIN_USER", "admin")
    monkeypatch.setattr(server, "ADMIN_PASSWORD", "correct-horse-battery")
    server.backup_inventory.cache_clear()
    return {"seerr": seerr, "mcp": mcp, "dest": dest, "tmp": tmp_path}


def new_job(job_id="j" * 32):
    server.backup_jobs[job_id] = {"job_id": job_id, "status": "Queued", "created_at": "2026-01-01T00:00:00"}
    return job_id


def run(ids):
    job_id = new_job()
    server.run_backup_job(job_id, ids)
    return server.backup_jobs[job_id]


def test_backup_creates_a_verified_archive_with_a_manifest(env):
    job = run(["seerr", "mcp"])
    assert job["status"] == "Completed", job.get("error")
    assert job["integrity_verified"] is True and job["source_complete"] is True
    archive = env["dest"] / job["archive"]
    assert archive.is_file() and not list(env["dest"].glob("*.partial"))
    assert oct(archive.stat().st_mode & 0o777) == "0o600"
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        names = set(z.namelist())
    assert {"seerr/settings.json", "seerr/db/db.sqlite3", "skynet-mcp/docker-compose.yml",
            "BACKUP-MANIFEST.json"} <= names


def test_env_files_are_left_out_of_the_skynet_mcp_archive(env):
    job = run(["mcp"])
    with zipfile.ZipFile(env["dest"] / job["archive"]) as z:
        names = z.namelist()
    assert "skynet-mcp/docker-compose.yml" in names
    assert not any(n.rsplit("/", 1)[-1].startswith(".env") for n in names)


def test_symlinks_are_not_followed(env):
    outside = env["tmp"] / "outside-secret.txt"
    outside.write_text("do not archive")
    os.symlink(outside, env["seerr"] / "link.txt")
    os.symlink(env["tmp"], env["seerr"] / "dirlink")
    job = run(["seerr"])
    with zipfile.ZipFile(env["dest"] / job["archive"]) as z:
        names = z.namelist()
    assert not any("link" in n for n in names)
    with zipfile.ZipFile(env["dest"] / job["archive"]) as z:
        assert not any(b"do not archive" in z.read(n) for n in z.namelist())


def test_files_older_than_1980_do_not_break_the_job(env):
    old = env["seerr"] / "ancient.txt"
    old.write_text("old")
    os.utime(old, (0, 0))  # 1970: ZIP cannot store this date without clamping
    job = run(["seerr"])
    assert job["status"] == "Completed", job.get("error")
    with zipfile.ZipFile(env["dest"] / job["archive"]) as z:
        assert "seerr/ancient.txt" in z.namelist()


def test_missing_destination_fails_cleanly(env, monkeypatch):
    monkeypatch.setattr(server, "CENTRAL_BACKUP_DIR", env["tmp"] / "not-mounted")
    job = run(["seerr"])
    assert job["status"] == "Failed" and "not mounted" in job["error"]
    assert job["integrity_verified"] is False


def test_not_enough_free_space_fails_before_writing(env, monkeypatch):
    class Usage:
        total, used, free = 100, 100, 10
    monkeypatch.setattr(server.shutil, "disk_usage", lambda _path: Usage)
    job = run(["seerr"])
    assert job["status"] == "Failed" and "free space" in job["error"]
    assert list(env["dest"].iterdir()) == []


def test_empty_source_is_an_error_not_an_empty_archive(env):
    for path in env["seerr"].rglob("*"):
        if path.is_file():
            path.unlink()
    job = run(["seerr"])
    assert job["status"] == "Failed" and "No files could be archived" in job["error"]
    assert list(env["dest"].iterdir()) == []


def test_failed_verification_removes_the_partial_file(env, monkeypatch):
    monkeypatch.setattr(zipfile.ZipFile, "testzip", lambda self: "seerr/settings.json")
    job = run(["seerr"])
    assert job["status"] == "Failed" and "verification failed" in job["error"]
    assert list(env["dest"].iterdir()) == []


def test_job_snapshot_lists_newest_archives(env):
    run(["seerr"])
    snap = server.backup_job_snapshot()
    assert len(snap["archives"]) == 1 and snap["active"] is False
    assert snap["jobs"][0]["status"] == "Completed"


# ---- API -------------------------------------------------------------------

@pytest.fixture
def api(env, monkeypatch):
    # Run the worker inline so the test can inspect the finished job.
    monkeypatch.setattr(server, "launch_backup_worker", lambda job_id, items: server.run_backup_job(job_id, items))
    return TestClient(server.app)


def test_run_requires_login(api):
    assert api.post("/api/backups/run", json={"items": ["seerr"]}, headers=HEADERS).status_code == 401


def test_run_requires_the_custom_header(api):
    response = api.post("/api/backups/run", json={"items": ["seerr"]}, auth=AUTH)
    assert response.status_code == 403
    assert server.backup_jobs == {}


@pytest.mark.parametrize("body", [
    {"items": []},
    {"items": ["seerr", "seerr"]},
    {"items": ["../../etc"]},
    {"items": ["gone"]},  # source folder is not mounted
    {"path": "/etc"},
    {"items": "seerr"},
])
def test_run_rejects_bad_selections(api, body):
    response = api.post("/api/backups/run", json=body, auth=AUTH, headers=HEADERS)
    assert response.status_code in (400, 422)
    assert server.backup_jobs == {}


def test_run_creates_an_archive(api, env):
    response = api.post("/api/backups/run", json={"items": ["seerr"]}, auth=AUTH, headers=HEADERS)
    assert response.status_code == 200
    job = server.backup_jobs[response.json()["job_id"]]
    assert job["status"] == "Completed"
    listing = api.get("/api/backups/jobs", auth=AUTH).json()
    assert listing["archives"][0]["name"] == job["archive"]


def test_only_one_job_runs_at_a_time(env, monkeypatch):
    monkeypatch.setattr(server, "launch_backup_worker", lambda job_id, items: None)  # stays Queued
    client = TestClient(server.app)
    assert client.post("/api/backups/run", json={"items": ["seerr"]}, auth=AUTH, headers=HEADERS).status_code == 200
    second = client.post("/api/backups/run", json={"items": ["mcp"]}, auth=AUTH, headers=HEADERS)
    assert second.status_code == 409


def test_job_history_is_bounded(env, monkeypatch):
    monkeypatch.setattr(server, "launch_backup_worker", lambda job_id, items: None)
    for i in range(server.MAX_KEPT_JOBS + 8):
        for job in server.backup_jobs.values():
            job["status"] = "Completed"
        server.start_backup_job(["seerr"])
        # created_at has one-second resolution; make ordering deterministic
        list(server.backup_jobs.values())[-1]["created_at"] = f"2026-01-01T00:00:{i:02d}"
    assert len(server.backup_jobs) <= server.MAX_KEPT_JOBS + 1


def test_options_report_availability_and_optional_items(api):
    items = {i["id"]: i for i in api.get("/api/backups/options", auth=AUTH).json()["items"]}
    assert items["seerr"]["available"] is True
    assert items["gone"]["available"] is False and items["gone"]["optional"] is True


def test_shipped_item_list_has_the_boot_config_as_an_optional_item():
    assert SHIPPED_ITEMS["boot"]["optional"] is True
    assert [k for k, v in SHIPPED_ITEMS.items() if not v["optional"]] == [
        "npm", "radarr", "sonarr", "prowlarr", "qbittorrent", "seerr", "skynet_mcp"]
    assert SHIPPED_ITEMS["skynet_mcp"]["exclude_env"] is True


def test_dashboard_puts_the_backup_panel_last_and_posts_with_the_header():
    html = server.DASHBOARD_HTML
    panels = [h for h in html.split('<div class="panel"><h2>')[1:]]
    titles = [p.split("</h2>")[0] for p in panels]
    assert titles[-1] == "Backup manager" and "Backup health" not in titles
    assert '"X-Requested-With":"skynet-admin"' in html
    assert 'data-action="startBackup"' in html


# ---- a source the container user cannot reach (e.g. the root-only flash drive) ---------

@pytest.fixture
def locked_flash(env, monkeypatch):
    locked = env["tmp"] / "flash" / "config"
    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        if str(path) == str(locked):
            raise PermissionError(13, "Permission denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(server.os, "stat", fake_stat)
    server.BACKUP_ITEMS["boot"] = {
        "name": "Boot", "optional": True, "sources": [(locked, "boot/config")], "exclude_env": False,
    }
    return locked


def test_unreadable_source_does_not_break_the_options_endpoint(api, locked_flash):
    response = api.get("/api/backups/options", auth=AUTH)
    assert response.status_code == 200
    items = {i["id"]: i for i in response.json()["items"]}
    assert items["boot"]["available"] is False and items["boot"]["reason"] == "unreadable"
    assert items["gone"]["reason"] == "missing"
    assert items["seerr"]["available"] is True and items["seerr"]["reason"] is None


def test_unreadable_source_cannot_be_selected_and_cannot_fail_silently(api, locked_flash):
    response = api.post("/api/backups/run", json={"items": ["boot"]}, auth=AUTH, headers=HEADERS)
    assert response.status_code == 400 and "Source not available" in response.text
    job = run(["boot"])  # bypassing the API check: the job itself must end in a clear failure
    assert job["status"] == "Failed" and "No files could be archived" in job["error"]
    assert job["excluded_files"] and job["excluded_files"][0]["kind"] == "directory"
    assert list(os.listdir(server.CENTRAL_BACKUP_DIR)) == []


def test_unreadable_destination_or_folder_never_raises(env, locked_flash, monkeypatch):
    assert server.dir_state(locked_flash) == "unreadable"
    assert server.is_dir_safe(locked_flash) is False
    assert server.dir_state(env["tmp"] / "nope") == "missing"
    assert server.dir_state(env["seerr"] / "settings.json") == "missing"  # a file is not a directory
    server.backup_inventory.cache_clear()
    assert server.backup_inventory()["central_destination_exists"] is True
