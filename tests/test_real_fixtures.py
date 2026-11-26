"""Checks the parsers against files copied from your own Unraid box.

Create the fixtures on the host with:  bash scripts/collect_fixtures.sh (from the repo root)
These tests are skipped until a ./fixtures/emhttp directory exists.
"""
from pathlib import Path

import pytest

import server

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EMHTTP = FIXTURES / "emhttp"

pytestmark = pytest.mark.skipif(not EMHTTP.is_dir(), reason="no real fixtures collected")


@pytest.fixture(autouse=True)
def real_files(monkeypatch):
    monkeypatch.setattr(server, "EMHTTP", EMHTTP)
    monkeypatch.setattr(server, "SMART_DIR", EMHTTP / "smart")


def test_every_slot_status_is_understood():
    """Fails (and names the slot) if a status code or empty-slot shape is not recognised."""
    for d in server.disk_inventory()["devices"]:
        if d["role"] not in ("Parity", "Data", "Cache"):
            continue
        kind = server.classify_disk_status(d["status"], bool(d["device"]), d["size_bytes"])
        print(f"{d['name']:10} {d['role']:7} status={d['status']!r:16} device={d['device']!r:8} -> {kind}")
        assert kind != "unknown", f"{d['name']}: unrecognised status {d['status']!r}"


def test_summary_matches_what_you_see_in_the_unraid_gui():
    array = server.array_status()
    summary = server.health_summary(array, server.disk_inventory())
    print(summary["state"], summary["issues"], summary["unassigned_parity_slots"])
    # Compare these printed values with the Unraid Main tab before trusting the dashboard.


def test_smart_reports_parse_for_every_assigned_disk():
    for d in server.disk_inventory()["devices"]:
        if d["role"] in ("Parity", "Data", "Cache") and d["device"] and d["smart"]:
            assert d["smart"]["attributes"], f"{d['name']}: no attributes parsed from its SMART report"


def test_disks_ini_units_match_df():
    df = FIXTURES / "df.txt"
    if not df.is_file():
        pytest.skip("no df.txt")
    real = {}
    for line in df.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            real[parts[0]] = int(parts[1]) * 1024
    checked = 0
    for d in server.disk_inventory()["devices"]:
        mount, size = d["mountpoint"], d["fs_size_bytes"]
        if mount in real and size:
            assert size == pytest.approx(real[mount], rel=0.02), f"{mount}: unit assumption is wrong"
            checked += 1
    assert checked, "no mount points could be compared"
