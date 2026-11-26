"""Runs the parsers against a sanitized sample from a real Unraid 7.x server.

tests/data/real-unraid holds disks.ini, var.ini, one SMART report and df output copied from the
author's server (drive IDs masked to their last 4 characters, filesystem UUIDs zeroed). Unlike
tests/test_real_fixtures.py, which needs a fixtures/ folder collected on your own host, these
tests always run, including in CI.

The server: parity + disks 1-4 (10 TB, XFS), an empty disk5 slot, an empty parity2 slot, a
two-SSD btrfs RAID1 cache pool, a single-disk pool that shares the boot device, and the flash.
"""
from pathlib import Path

import pytest

import server

DATA = Path(__file__).parent / "data" / "real-unraid"
EMHTTP = DATA / "emhttp"
MOUNTED = ("disk1", "disk2", "disk3", "disk4", "cache", "datastorage")


@pytest.fixture(autouse=True)
def sample(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "EMHTTP", EMHTTP)
    monkeypatch.setattr(server, "SMART_DIR", EMHTTP / "smart")
    mnt = tmp_path / "mnt"
    for name in MOUNTED:
        (mnt / name).mkdir(parents=True)
    monkeypatch.setattr(server, "HOST_MNT", mnt)


def summary():
    return server.health_summary(server.array_status(), server.disk_inventory())


def devices():
    return {d["name"]: d for d in server.disk_inventory()["devices"]}


def test_healthy_array_with_empty_parity2_is_not_degraded():
    # var.ini says mdNumDisabled=1 and mdNumInvalid=1: Unraid counts the empty parity2 slot.
    assert server.array_status()["status"]["mdNumDisabled"] == "1"
    result = summary()
    assert result["state"] == "Healthy"
    assert result["issues"] == []
    assert result["unassigned_parity_slots"] == ["parity2"]
    assert result["configured_data_disks"] == 4
    assert result["data_disks_needing_attention"] == []
    assert result["parity_operation"]["running"] is False


def test_disks_ini_sizes_are_kib_blocks_and_match_df():
    df = {}
    for line in (DATA / "df.txt").read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("/mnt/") and parts[1].isdigit():
            df[parts[0]] = int(parts[1]) * 1024
    checked = 0
    for disk in devices().values():
        if disk["mountpoint"] in df and disk["fs_size_bytes"]:
            assert disk["fs_size_bytes"] == df[disk["mountpoint"]], disk["name"]
            checked += 1
    assert checked == 6
    assert devices()["parity"]["size_bytes"] == 9766436812 * 1024  # a 10 TB drive


def test_serials_are_masked_and_empty_slots_have_none():
    found = devices()
    assert found["disk1"]["serial"] == "…WAGW"
    assert found["disk5"]["serial"] is None
    assert found["parity2"]["serial"] is None


def test_every_slot_status_is_understood():
    kinds = {}
    for disk in devices().values():
        if disk["role"] in ("Parity", "Data", "Cache", "Boot"):
            kinds[disk["name"]] = server.classify_disk_status(
                disk["status"], bool(disk["device"]), disk["size_bytes"]
            )
    assert kinds["disk5"] == "unassigned" and kinds["parity2"] == "unassigned"
    assert "unknown" not in kinds.values()
    assert kinds["flash"] == "ok"


def test_seagate_smart_report_for_disk1():
    report = server.parse_smart_report("disk1")
    assert report["attributes"]["power_on_hours"] == 52829  # raw is "52829 (45 89 0)"
    assert report["attributes"]["temperature_c"] == 41  # raw is "41 (0 23 0 0 0)"
    assert report["attributes"]["reallocated_sectors"] == 56
    assert report["critical_attributes"] == []
    assert report["attention_attributes"] == ["reallocated_sectors"]
    assert report["assessment"] == "Review attributes"
    assert any("Airflow_Temperature_Cel" in note for note in report["notes"])


def test_unmounted_slots_are_not_listed_as_storage():
    volumes = server.storage()
    assert [v["name"] for v in volumes] == list(MOUNTED)
    assert not any("error" in v for v in volumes)


def test_boot_device_is_sorted_after_the_pools():
    order = [d["name"] for d in server.disk_inventory()["devices"]]
    assert order[0] == "parity" and order[-1] == "flash"
