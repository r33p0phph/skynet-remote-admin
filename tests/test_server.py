"""Run with:  pip install -r requirements-dev.txt && pytest -q"""
import base64
import os
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

import server

SATA_REPORT = """\
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Power_On_Hours          0x0032   070   070   000    Old_age   Always       -       26485h+12m+10.123s
187 Reported_Uncorrect      0x0032   100   100   000    Old_age   Always       -       0
194 Temperature_Celsius     0x0022   036   040   000    Old_age   Always       -       36 (Min/Max 22/45)
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0
199 UDMA_CRC_Error_Count    0x003e   200   200   000    Old_age   Always       -       0
"""

PENDING_REPORT = SATA_REPORT.replace(
    "197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0",
    "197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       8",
)

FAILING_REPORT = SATA_REPORT.replace(
    "  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0",
    "  5 Reallocated_Sector_Ct   0x0033   005   005   010    Pre-fail  Always   FAILING_NOW 0",
)

NVME_REPORT = """\
SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x00
Temperature:                        38 Celsius
Available Spare:                    100%
Available Spare Threshold:          10%
Percentage Used:                    3%
Power On Hours:                     1,234
Unsafe Shutdowns:                   12
Media and Data Integrity Errors:    0
"""


def disk(name, role, device="sdb", status="DISK_OK", size=1000, errors=0, smart=None):
    return {
        "name": name, "role": role, "device": device, "status": status,
        "size_bytes": size, "read_errors": errors, "smart": smart,
    }


def summary(devices, **var):
    var.setdefault("mdState", "STARTED")
    return server.health_summary({"status": var}, {"devices": devices})


# ---- redaction -------------------------------------------------------------

@pytest.mark.parametrize("line,secret", [
    ("GET /api/v3/x?apikey=0123456789abcdef0123456789abcdef", "0123456789abcdef"),
    ('{"apikey": "supersecretvalue"}', "supersecretvalue"),
    ("announce http://tracker.example/a?passkey=abc123def", "abc123def"),
    ("connecting to http://user:hunter2@host:8080/", "hunter2"),
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ("Cookie: SID=deadbeefcafe; theme=dark", "deadbeefcafe"),
    ("token eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl", "eyJhbGciOi"),
    ("key 0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
])
def test_redaction_removes_secrets(line, secret):
    text, count = server.redact_secrets(line)
    assert secret not in text
    assert count > 0


def test_redaction_leaves_normal_lines():
    line = "2026-10-31T10:00:00Z Starting import of 3 files from /downloads"
    assert server.redact_secrets(line) == (line, 0)


def test_sanitize_logs_caps_size_and_lines():
    result = server.sanitize_logs("x" * (server.MAX_LOG_LINE + 50) + "\nshort")
    assert result["truncated"] is True
    assert "line truncated" in result["logs"]
    assert result["line_count"] == 2


# ---- SMART -----------------------------------------------------------------

@pytest.fixture
def smart_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "SMART_DIR", tmp_path)
    return tmp_path


def test_smart_seagate_hours_and_temperature(smart_dir):
    (smart_dir / "disk1").write_text(SATA_REPORT)
    report = server.parse_smart_report("disk1")
    assert report["attributes"]["power_on_hours"] == 26485
    assert report["attributes"]["temperature_c"] == 36
    assert report["assessment"] == "No flagged attributes"


def test_smart_pending_sectors_is_critical(smart_dir):
    (smart_dir / "disk1").write_text(PENDING_REPORT)
    report = server.parse_smart_report("disk1")
    assert report["critical_attributes"] == ["pending_sectors"]
    assert report["assessment"] == "Attention required"


def test_smart_failing_now_is_critical(smart_dir):
    (smart_dir / "disk1").write_text(FAILING_REPORT)
    report = server.parse_smart_report("disk1")
    assert "failing_now:Reallocated_Sector_Ct" in report["critical_attributes"]


def test_smart_nvme(smart_dir):
    (smart_dir / "cache").write_text(NVME_REPORT)
    report = server.parse_smart_report("cache")
    assert report["attributes"]["power_on_hours"] == 1234
    assert report["attributes"]["percentage_used"] == 3
    assert report["assessment"] == "No flagged attributes"


def test_smart_spun_down_is_not_stale(smart_dir):
    path = smart_dir / "disk1"
    path.write_text(SATA_REPORT)
    old = time.time() - 3 * 86400
    os.utime(path, (old, old))
    assert server.parse_smart_report("disk1")["stale"] is True
    assert server.parse_smart_report("disk1", spun_down=True)["stale"] is False


# ---- array health ----------------------------------------------------------

def test_healthy_array_ignores_empty_slots():
    result = summary([
        disk("parity", "Parity"),
        disk("parity2", "Parity", device=None, status="DISK_NP_DSBL", size=0),
        disk("disk1", "Data"),
        disk("disk2", "Data", device=None, status="DISK_NP", size=0),
        disk("cache", "Cache"),
    ])
    assert result["state"] == "Healthy"
    assert result["unassigned_parity_slots"] == ["parity2"]
    assert result["configured_data_disks"] == 1


def test_disabled_parity_is_degraded():
    result = summary([disk("parity", "Parity", status="DISK_DSBL"), disk("disk1", "Data")])
    assert result["state"] == "Degraded"
    assert any("parity" in issue for issue in result["issues"])


def test_disabled_data_disk_is_degraded_and_listed():
    result = summary([
        disk("parity", "Parity"),
        disk("disk1", "Data", status="DISK_DSBL"),
        disk("disk2", "Data"),
    ])
    assert result["state"] == "Degraded"
    assert result["data_disks_needing_attention"] == ["disk1"]


def test_missing_configured_disk_is_degraded():
    result = summary([
        disk("parity", "Parity"),
        disk("disk1", "Data", device=None, status="DISK_NP_DSBL", size=4000),
    ])
    assert result["state"] == "Degraded"


def test_read_errors_and_smart_critical_need_attention():
    assert summary([disk("parity", "Parity"), disk("disk1", "Data", errors=4)])["state"] == "Attention"
    smart = {"critical_attributes": ["pending_sectors"]}
    assert summary([disk("parity", "Parity"), disk("disk1", "Data", smart=smart)])["state"] == "Attention"


def test_no_parity_needs_attention():
    assert summary([disk("disk1", "Data")])["state"] == "Attention"


def test_counters_cross_check():
    result = summary([disk("parity", "Parity"), disk("disk1", "Data")], mdNumDisabled="1")
    assert result["state"] == "Degraded"


def test_stopped_array():
    assert summary([disk("disk1", "Data")], mdState="STOPPED")["state"] == "Stopped"


def test_parity_progress():
    result = summary(
        [disk("parity", "Parity"), disk("disk1", "Data")],
        mdResync="1000", mdResyncSize="1000", mdResyncPos="250", mdResyncAction="check P",
    )
    assert result["parity_operation"] == {"running": True, "action": "check P", "percent": 25.0}


# ---- misc parsers ----------------------------------------------------------

def test_meminfo_only_scales_kb(tmp_path, monkeypatch):
    (tmp_path / "meminfo").write_text("MemTotal:  1000 kB\nHugePages_Total:  5\n")
    monkeypatch.setattr(server, "HOST_PROC", tmp_path)
    memory = server.parse_meminfo()
    assert memory["MemTotal"] == 1000 * 1024
    assert memory["HugePages_Total"] == 5


def test_disks_ini_sizes_are_kib(tmp_path, monkeypatch):
    (tmp_path / "disks.ini").write_text(
        '["disk1"]\nname="disk1"\ntype="Data"\ndevice="sdb"\nsize="1000"\nstatus="DISK_OK"\nid="WDC_WD40_ABCD1234"\n'
    )
    monkeypatch.setattr(server, "EMHTTP", tmp_path)
    disk_info = server.disk_inventory()["devices"][0]
    assert disk_info["size_bytes"] == 1000 * 1024
    assert disk_info["serial"] == "\u20261234"


# ---- backups ---------------------------------------------------------------

def make_zip(path, ok=True):
    if ok:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("db.sqlite", "x" * 2000)
    else:
        path.write_bytes(b"not a zip at all" * 20)


def test_backup_inventory_flags_problems(tmp_path, monkeypatch):
    good, bad, empty, optional = (tmp_path / n for n in ("good", "bad", "empty", "legacy"))
    for folder in (good, bad, empty):
        folder.mkdir()
    make_zip(good / "a.zip")
    make_zip(bad / "a.zip", ok=False)
    (empty / "a.zip").write_bytes(b"")
    monkeypatch.setattr(server, "BACKUP_SOURCES", [
        ("Good", good, 30, False), ("Bad", bad, 30, False),
        ("Empty", empty, 30, False), ("Legacy", optional, 30, True),
    ])
    monkeypatch.setattr(server, "CENTRAL_BACKUP_DIR", tmp_path / "central")
    server.backup_inventory.cache_clear()
    by_name = {s["application"]: s for s in server.backup_inventory()["sources"]}
    assert by_name["Good"]["status"] == "Recent" and by_name["Good"]["latest_zip_ok"] is True
    assert by_name["Bad"]["status"] == "Check" and by_name["Bad"]["latest_zip_ok"] is False
    assert by_name["Empty"]["status"] == "Check"
    assert by_name["Legacy"]["status"] == "Not present (optional)"
    server.backup_inventory.cache_clear()


def test_backup_stale(tmp_path, monkeypatch):
    folder = tmp_path / "old"
    folder.mkdir()
    make_zip(folder / "a.zip")
    old = time.time() - 40 * 86400
    os.utime(folder / "a.zip", (old, old))
    monkeypatch.setattr(server, "BACKUP_SOURCES", [("Old", folder, 30, False)])
    server.backup_inventory.cache_clear()
    assert server.backup_inventory()["sources"][0]["status"] == "Stale"
    server.backup_inventory.cache_clear()


# ---- auth and headers ------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "ADMIN_USER", "admin")
    monkeypatch.setattr(server, "ADMIN_PASSWORD", "correct-horse-battery")
    return TestClient(server.app)


def test_auth_challenges_and_rejects(client):
    for kwargs in ({}, {"auth": ("admin", "wrong")}, {"auth": ("nobody", "correct-horse-battery")}):
        response = client.get("/api/hardware", **kwargs)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Basic"


def test_non_ascii_credentials_give_401_not_500(client):
    token = base64.b64encode("us\u00e9r:p\u00e4ss".encode("utf-8")).decode()
    response = client.get("/api/hardware", headers={"Authorization": f"Basic {token}"})
    assert response.status_code == 401


def test_good_login_and_security_headers(client):
    response = client.get("/api/hardware", auth=("admin", "correct-horse-battery"))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_dashboard_has_nonce_csp_and_no_inline_handlers(client):
    response = client.get("/", auth=("admin", "correct-horse-battery"))
    csp = response.headers["content-security-policy"]
    nonce = csp.split("script-src 'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">' in response.text
    assert "__NONCE__" not in response.text
    assert "onclick=" not in response.text


def test_health_is_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_logs_validates_input(client):
    auth = ("admin", "correct-horse-battery")
    assert client.get("/api/logs?name=../etc", auth=auth).status_code == 400
    assert client.get("/api/logs?name=ok&tail=9999", auth=auth).status_code == 400


def test_docker_unreachable_is_503(client, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
    response = client.get("/api/containers", auth=("admin", "correct-horse-battery"))
    assert response.status_code == 503


def test_startup_validation(monkeypatch):
    monkeypatch.setattr(server, "ADMIN_USER", "")
    with pytest.raises(RuntimeError):
        server.validate_config()
    monkeypatch.setattr(server, "ADMIN_USER", "admin")
    monkeypatch.setattr(server, "ADMIN_PASSWORD", "p\u00e4ssword-long-enough")
    with pytest.raises(RuntimeError):
        server.validate_config()


# ---- docker lookup: exact filter, no inspect-everything ---------------------

class FakeContainer:
    def __init__(self, name, output=b"line one\nline two"):
        self.name = name
        self._output = output
        self.log_kwargs = None

    def logs(self, **kwargs):
        self.log_kwargs = kwargs
        return self._output


class FakeClient:
    """Stands in for docker.DockerClient: records how containers.list is called."""
    def __init__(self, found):
        self.containers = self
        self.found = found
        self.list_calls = []
        self.closed = False

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        return self.found

    def close(self):
        self.closed = True


def test_logs_uses_one_exact_filter_and_exact_match(client, monkeypatch):
    wanted = FakeContainer("binhex-radarr", b"apikey=0123456789abcdef0123456789abcdef ok")
    fake = FakeClient([FakeContainer("binhex-radarr-2"), wanted])
    monkeypatch.setattr(server, "get_docker_client", lambda: fake)
    response = client.get("/api/logs?name=binhex-radarr&tail=50", auth=("admin", "correct-horse-battery"))
    assert response.status_code == 200
    assert len(fake.list_calls) == 1  # one filtered query, not a scan of every container
    assert fake.list_calls[0] == {"all": True, "filters": {"name": r"^/binhex\-radarr$"}}
    assert wanted.log_kwargs == {"stdout": True, "stderr": True, "tail": 50, "timestamps": True}
    body = response.json()
    assert "0123456789abcdef" not in body["logs"]
    assert body["redactions"] >= 1
    assert fake.closed is True


def test_logs_substring_match_is_not_enough(client, monkeypatch):
    fake = FakeClient([FakeContainer("binhex-radarr-2")])
    monkeypatch.setattr(server, "get_docker_client", lambda: fake)
    response = client.get("/api/logs?name=binhex-radarr", auth=("admin", "correct-horse-battery"))
    assert response.status_code == 404


# ---- redaction: formats and known limits ------------------------------------

@pytest.mark.parametrize("text,secret", [
    ('{\n  "apikey":\n    "multilinevalue123"\n}', "multilinevalue123"),
    ("http://user:p%40ssw0rd%21@host/path", "p%40ssw0rd%21"),
    ("GET /hook?access_token=abc%2Fdef%3D&x=1", "abc%2Fdef%3D"),
    ("X-Api-Key: MixedCaseKey99", "MixedCaseKey99"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("api_key = 'quoted-secret-1'", "quoted-secret-1"),
    ("PASSWORD=Sup3r$ecret", "Sup3r$ecret"),
    ("line one\nclient_secret: abcdefghijkl\nline three", "abcdefghijkl"),
])
def test_redaction_extra_formats(text, secret):
    redacted, count = server.redact_secrets(text)
    assert secret not in redacted
    assert count > 0


def test_redaction_is_idempotent():
    once, _ = server.redact_secrets("token=abc123def456 and apikey=zzz999yyy888")
    twice, count = server.redact_secrets(once)
    assert twice == once and count == 0


@pytest.mark.xfail(reason="Redaction is pattern based. A secret wrapped mid-token across lines cannot be recognised.")
def test_secret_split_across_lines_is_not_caught():
    redacted, _ = server.redact_secrets("auth value 0123456789abcdef\n0123456789abcdef end")
    assert "0123456789abcdef" not in redacted


# ---- backups: limits, failures, cache ---------------------------------------

def test_scan_cap_truncates_and_warns(tmp_path, monkeypatch):
    folder = tmp_path / "many"
    folder.mkdir()
    for i in range(12):
        (folder / f"f{i}.bin").write_bytes(b"x")
    monkeypatch.setattr(server, "MAX_SCAN_FILES", 5)
    scan = server.scan_backup_folder(folder)
    assert scan["truncated"] is True and scan["file_count"] == 5
    monkeypatch.setattr(server, "BACKUP_SOURCES", [("Many", folder, 30, False)])
    server.backup_inventory.cache_clear()
    source = server.backup_inventory()["sources"][0]
    assert any("Scan stopped" in w for w in source["warnings"])
    server.backup_inventory.cache_clear()


def test_unreadable_subfolder_does_not_break_scan(tmp_path, monkeypatch):
    folder = tmp_path / "root"
    (folder / "locked").mkdir(parents=True)
    (folder / "ok.bin").write_bytes(b"data")
    real_scandir = os.scandir

    def flaky(path):
        if str(path).endswith("locked"):
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(server.os, "scandir", flaky)
    scan = server.scan_backup_folder(folder)
    assert scan["file_count"] == 1


def test_unreadable_zip_is_reported_not_raised(tmp_path, monkeypatch):
    path = tmp_path / "a.zip"
    make_zip(path)
    stat = path.stat()

    def deny(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(server.zipfile, "ZipFile", deny)
    server.zip_crc_ok.cache_clear()
    assert server.zip_crc_ok(str(path), stat.st_mtime, stat.st_size) is False
    server.zip_crc_ok.cache_clear()


def test_truncated_and_bit_flipped_zips_fail(tmp_path):
    good = tmp_path / "good.zip"
    make_zip(good)
    data = good.read_bytes()

    cut = tmp_path / "cut.zip"
    cut.write_bytes(data[: len(data) // 2])  # interrupted copy: central directory missing

    stored = tmp_path / "flip.zip"
    with zipfile.ZipFile(stored, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("db.sqlite", "A" * 4000)
    raw = bytearray(stored.read_bytes())
    raw[200] ^= 0xFF  # flip one byte of the stored payload
    stored.write_bytes(bytes(raw))

    for path, expected in ((good, True), (cut, False), (stored, False)):
        st = path.stat()
        assert server.zip_crc_ok(str(path), st.st_mtime, st.st_size) is expected


def test_oversized_zip_is_skipped_and_changed_file_is_retested(tmp_path, monkeypatch):
    path = tmp_path / "a.zip"
    make_zip(path)
    st = path.stat()
    monkeypatch.setattr(server, "ZIP_TEST_MAX_BYTES", 10)
    assert server.zip_crc_ok(str(path), st.st_mtime, st.st_size) is None
    monkeypatch.undo()
    server.zip_crc_ok.cache_clear()  # same key would otherwise return the cached "skipped" result
    assert server.zip_crc_ok(str(path), st.st_mtime, st.st_size) is True
    make_zip(path, ok=False)  # same path, new content: new mtime/size key
    st2 = path.stat()
    assert server.zip_crc_ok(str(path), st2.st_mtime + 1, st2.st_size) is False


def test_ttl_cache_expires(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(server.time, "monotonic", lambda: clock["t"])
    calls = []

    @server.ttl_cache(60)
    def compute():
        calls.append(1)
        return len(calls)

    assert compute() == 1 and compute() == 1
    clock["t"] += 61
    assert compute() == 2
