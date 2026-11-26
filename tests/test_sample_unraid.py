"""Runs the parsers against a sanitized sample from a real Unraid 7.x server.

tests/data/real-unraid holds disks.ini, var.ini, all eight SMART reports and df output copied
from the author's server (drive IDs masked to their last 4 characters, filesystem UUIDs
zeroed). Unlike tests/test_real_fixtures.py, which needs a fixtures/ folder collected on your
own host, these tests always run, including in CI.

The server: parity + disks 1-4 (10 TB, XFS), an empty disk5 slot, an empty parity2 slot, a
two-SSD btrfs RAID1 cache pool, a single-disk pool that shares the boot device, and the flash.
Two of the data disks (disk3, disk4) report uncorrectable read errors, so the correct verdict
for this array is "Attention", not "Healthy" and not "Degraded".
"""
import re
from pathlib import Path

import pytest

import server

DATA = Path(__file__).parent / "data" / "real-unraid"
EMHTTP = DATA / "emhttp"
MOUNTED = ("disk1", "disk2", "disk3", "disk4", "cache", "datastorage")
REPORTS = ("parity", "disk1", "disk2", "disk3", "disk4", "cache", "cache2", "datastorage")


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


def test_empty_parity2_does_not_make_the_array_degraded():
    # var.ini says mdNumDisabled=1 and mdNumInvalid=1: Unraid counts the empty parity2 slot.
    status = server.array_status()["status"]
    assert status["mdNumDisabled"] == "1" and status["mdNumInvalid"] == "1"
    result = summary()
    assert result["state"] != "Degraded"
    assert result["unassigned_parity_slots"] == ["parity2"]
    assert result["configured_data_disks"] == 4
    assert result["parity_operation"]["running"] is False


def test_array_needs_attention_because_of_disk3_and_disk4():
    result = summary()
    assert result["state"] == "Attention"
    assert result["data_disks_needing_attention"] == ["disk3", "disk4"]
    assert result["issues"] == [
        "disk3: SMART critical: reported_uncorrectable",
        "disk4: SMART critical: reported_uncorrectable",
    ]


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


def test_every_attribute_row_in_all_eight_reports_is_parsed():
    attribute_row = re.compile(r"^\s*\d+\s+\S+\s+0x")
    files = sorted((EMHTTP / "smart").iterdir())
    assert [f.name for f in files] == sorted(REPORTS)
    for path in files:
        rows = [line for line in path.read_text().splitlines() if attribute_row.match(line)]
        assert rows, path.name
        assert all(server.SMART_ROW.match(line) for line in rows), path.name
        assert server.parse_smart_report(path.name)["attributes"], path.name


def test_seagate_smart_report_for_disk1():
    report = server.parse_smart_report("disk1")
    assert report["attributes"]["power_on_hours"] == 52829  # raw is "52829 (45 89 0)"
    assert report["attributes"]["temperature_c"] == 41  # raw is "41 (0 23 0 0 0)"
    assert report["attributes"]["reallocated_sectors"] == 56
    assert report["critical_attributes"] == []
    assert report["attention_attributes"] == ["reallocated_sectors"]
    assert report["assessment"] == "Review attributes"
    assert any("Airflow_Temperature_Cel" in note for note in report["notes"])


def test_clean_and_failing_drives_are_told_apart():
    parity = server.parse_smart_report("parity")
    assert parity["assessment"] == "No flagged attributes"
    disk2 = server.parse_smart_report("disk2")
    assert disk2["assessment"] == "Review attributes"
    assert disk2["attributes"]["reallocated_sectors"] == 8
    for name, reallocated, uncorrectable in (("disk3", 7344, 13), ("disk4", 9392, 66)):
        report = server.parse_smart_report(name)
        assert report["assessment"] == "Attention required", name
        assert report["critical_attributes"] == ["reported_uncorrectable"], name
        assert report["attributes"]["reallocated_sectors"] == reallocated, name
        assert report["attributes"]["reported_uncorrectable"] == uncorrectable, name
        assert report["attributes"]["pending_sectors"] == 0, name


def test_sata_ssd_reports():
    for name, hours in (("cache", 21245), ("cache2", 21248)):
        report = server.parse_smart_report(name)
        assert report["assessment"] == "No flagged attributes", name
        assert report["attributes"]["power_on_hours"] == hours
        assert report["attributes"]["wear_leveling_count"] in (54, 55)
    datastorage = server.parse_smart_report("datastorage")
    assert datastorage["assessment"] == "No flagged attributes"
    assert datastorage["attributes"]["temperature_c"] == 27


def test_unmounted_slots_are_not_listed_as_storage():
    volumes = server.storage()
    assert [v["name"] for v in volumes] == list(MOUNTED)
    assert not any("error" in v for v in volumes)


def test_boot_device_is_sorted_after_the_pools():
    order = [d["name"] for d in server.disk_inventory()["devices"]]
    assert order[0] == "parity" and order[-1] == "flash"
