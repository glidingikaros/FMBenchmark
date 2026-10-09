import json
import os
from pathlib import Path

import pytest

from fmb.cli.app import main
from fmb.replication import host, run


def test_child_processes_find_the_private_dotnet_first(tmp_path, monkeypatch):
    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    (tmp_path / "dotnet").mkdir()
    env = host.environment()
    assert env["PATH"].split(os.pathsep)[0] == str(tmp_path / "dotnet")
    assert env["DOTNET_ROOT"] == str(tmp_path / "dotnet")
    assert env["FMB_QEMU_BASE_HOME"] == str(tmp_path / "qemu-bases")


def test_only_a_published_generation_counts_as_done(tmp_path):
    failed = tmp_path / "attempt-1" / "full_scale" / "a"
    failed.mkdir(parents=True)
    (failed / "full_scale.vmdk").write_bytes(b"")
    assert run.completed(tmp_path) is None
    published = tmp_path / "attempt-2" / "full_scale" / "b"
    published.mkdir(parents=True)
    (published / "full_scale.vmdk").write_bytes(b"")
    (published / "manifest.json").write_text("{}")
    assert run.completed(tmp_path) == published


def test_the_summary_reads_strict_admission_and_per_question_exactness(tmp_path):
    gate = tmp_path / "G5.json"
    questions = {f"BQ-{n}": {"exact": n != "LOG-01"} for n in ("DELETE-01", "LOG-01")}
    gate.write_text(json.dumps({"admission": {"status": "failed"},
                                "comparison": {"rules": {"f1": 0.9, "finding_counts": {"fn": 1},
                                                         "per_question": questions}}}))
    assert run.summary("I2", gate) == {"image": "I2", "admission": "failed", "f1": 0.9, "exact": 1, "questions": 2,
                                       "counts": {"fn": 1}, "not_exact": ["BQ-LOG-01"]}
    assert run.summary("I3", tmp_path / "missing.json") == {"image": "I3", "admission": "not reached"}


def test_a_failure_while_provisioning_is_retried_and_others_are_not():
    phase = '{"elapsed_seconds": 1.0, "error_type": "X", "outcome": "error", "phase": "%s"}'
    assert run.RETRYABLE.search(phase % "ansible_provisioning")
    assert run.RETRYABLE.search(phase % "qemu_boot")
    assert not run.RETRYABLE.search(phase % "disk_discovery_export")


def test_the_base_needs_an_iso_the_user_downloads_and_says_where_from(monkeypatch):
    from fmb.replication import setup

    monkeypatch.setattr(host, "base_guest_facts", lambda: None)
    with pytest.raises(SystemExit) as stopped:
        setup.base()
    pin = host.PINS["windows_iso"]
    assert pin["download"] in str(stopped.value) and "--iso" in str(stopped.value)
    assert pin["edition"] == "pro" and len(pin["sha256"]) == 64


def test_the_cli_offers_doctor_setup_and_run(capsys):
    for action in ("doctor", "setup", "run"):
        try:
            main(["replicate", action, "--help"])
        except SystemExit as exit:
            assert exit.code == 0
    out = capsys.readouterr().out
    assert "I1" in out and "--iso" in out and "--unpinned-iso" in out


@pytest.mark.skipif(os.name == "nt", reason="pip writes .exe launchers on Windows; fmb checks console scripts on POSIX only")
def test_a_console_script_in_a_long_environment_path_hashes_like_a_short_one(tmp_path):
    from fmb.index.scanners.logfile_runtime import portable_console_sha256

    body = b"\n# dfir_ntfs\nimport sys\n"
    short, long = tmp_path / "v", tmp_path / ("x" * 140) / "v"
    for root in (short, long):
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "python").write_bytes(b"")
    (short / "bin" / "ntfs_parser").write_bytes(b"#!" + str(short / "bin" / "python").encode() + b"\n" + body)
    (long / "bin" / "ntfs_parser").write_bytes(
        b"#!/bin/sh\n'''exec' '" + str(long / "bin" / "python").encode() + b"' \"$0\" \"$@\"\n' '''\n" + body)
    hashes = {portable_console_sha256(root / "bin" / "ntfs_parser", root / "bin" / "python") for root in (short, long)}
    assert len(hashes) == 1 and None not in hashes


def test_generation_waits_until_its_biased_clock_is_past_the_base_builds_last_events():
    from datetime import datetime, timezone

    from fmb.replication.run import base_clock_wait_seconds

    assert base_clock_wait_seconds("2026-10-08T20:06:00+00:00", 480,
                                   datetime(2026, 10, 8, 20, 30, tzinfo=timezone.utc)) == 46 * 60
    assert base_clock_wait_seconds("2026-12-08T20:06:00+00:00", 480,
                                   datetime(2026, 12, 8, 20, 10, tzinfo=timezone.utc)) == 6 * 60
    assert base_clock_wait_seconds("2026-10-08T18:00:00+00:00", 480,
                                   datetime(2026, 10, 8, 20, 30, tzinfo=timezone.utc)) == 0


def test_setup_builds_the_base_only_from_the_pinned_iso_unless_told_otherwise(tmp_path, monkeypatch):
    from fmb.replication import setup

    monkeypatch.setattr(host, "base_guest_facts", lambda: None)
    monkeypatch.setenv("FMB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "newer.iso").write_bytes(b"a newer build")
    with pytest.raises(SystemExit, match="--unpinned-iso"):
        setup.base(Path("~/Downloads/newer.iso"))
    with pytest.raises(SystemExit, match="no ISO at"):
        setup.base(tmp_path / "missing.iso")

    commands = []

    def install(command, **kwargs):
        commands.append([str(part) for part in command])
        work = host.cache() / "base-build"
        work.mkdir(parents=True)
        for name in ("base.qcow2", "base-vars.fd"):
            (work / name).write_bytes(b"")
        (work / "guest.json").write_text(json.dumps({"build": "26300", "ubr": 9999}))

    monkeypatch.setattr(setup, "run", install)
    assert setup.base(Path("~/Downloads/newer.iso"), unpinned_iso=True) == {"build": "26300", "ubr": 9999}
    command, = commands
    assert command[command.index("--iso-url") + 1] == str((tmp_path / "Downloads" / "newer.iso").resolve())
    assert command[command.index("--iso-sha256") + 1] == setup.file_sha256(tmp_path / "Downloads" / "newer.iso")


def test_every_summary_row_names_the_windows_base_and_whether_its_iso_is_the_pinned_one(tmp_path, monkeypatch):
    facts = {"build": "26300", "ubr": 9999, "iso_sha256": "ab" * 32}
    monkeypatch.setattr(host, "provider", lambda: "qemu")
    monkeypatch.setattr(host, "base_guest_facts", lambda: facts)
    run.write_summary(tmp_path, [{"image": "I1", "admission": "passed"}])
    row, = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert row == {"image": "I1", "admission": "passed",
                   "windows_base": {"build": "26300.9999", "iso_sha256": "ab" * 32, "iso_pinned": False}}
    facts["iso_sha256"] = host.PINS["windows_iso"]["sha256"]
    assert host.windows_base()["iso_pinned"] is True
    del facts["iso_sha256"]
    assert host.windows_base()["iso_pinned"] is None
    monkeypatch.setattr(host, "provider", lambda: "vmware_desktop")
    run.write_summary(tmp_path, [{"image": "I1", "admission": "passed"}])
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == [{"image": "I1", "admission": "passed"}]


def test_doctor_names_the_qemu_packages_of_the_linux_distribution(monkeypatch):
    monkeypatch.setattr(host, "WINDOWS", False)
    for release, manager in (({"ID": "ubuntu", "ID_LIKE": "debian"}, "apt-get"), ({"ID": "fedora"}, "dnf"),
                             ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "dnf"), ({"ID": "arch"}, "pacman"),
                             ({"ID": "manjaro", "ID_LIKE": "arch"}, "pacman"),
                             ({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}, "zypper"), ({"ID": "nixos"}, "OVMF")):
        monkeypatch.setattr(host.platform, "freedesktop_os_release", lambda release=release: release)
        assert manager in host.qemu_install()
