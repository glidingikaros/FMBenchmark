import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fmb.generation import backends, recipe
from fmb.generation.backends import QemuBackend


def test_the_qemu_vm_mirrors_the_frozen_vmware_definition(tmp_path, monkeypatch):
    monkeypatch.setattr(QemuBackend, "accelerator", staticmethod(lambda: "kvm"))
    backend = QemuBackend(pipeline=None)
    backend.winrm_port, backend.monitor_port = 55985, 55986
    hardware = recipe.resolved_hardware(2026091811)
    inputs = {"fmb_hardware": hardware, "fmb_vmware_boot_clock_bias_minutes": 480}
    media = [{"path": tmp_path / f"m{unit}.vmdk", "unit": unit, "port": port} for unit, port in ((8, 5), (9, 3), (10, 2))]
    command = backend.command(Path("qemu-system-x86_64"), tmp_path, inputs, rtc_bias=420)
    text = " ".join(command)
    assert "usb-bot" not in text and "qemu-xhci,id=xhci,p2=8,p3=8" in text
    plugged = "\n".join(backend.media_commands(hardware, media))

    assert command[command.index("-uuid") + 1] == hardware["uuid_bios"]
    assert f"mac={hardware['base_mac']}" in text
    assert command[command.index("-cpu") + 1].startswith("host,-vmx,-svm,")
    assert "net=192.168.56.0/24" in text
    assert command[command.index("-m") + 1] == "4096" and command[command.index("-smp") + 1] == "2"
    serials = re.findall(r"usb-bot,id=usb(\d+)bot,bus=xhci\.0,port=(\d+),serial=([0-9A-F]+)", plugged)
    assert [(int(port), int(unit)) for unit, port, _ in serials] == [(5, 8), (3, 9), (2, 10)]
    assert all(f"scsi-hd,bus=usb{unit}bot.0,scsi-id=0,lun=0,drive=usb{unit},serial={serial[:20]},removable=on" in plugged
               for unit, _, serial in serials)
    for unit, *_ in serials:
        lines = plugged.splitlines()
        assert (lines.index(f"qom-set /machine/peripheral/usb{unit}bot attached true")
                > next(i for i, line in enumerate(lines) if line.startswith(f"device_add scsi-hd,bus=usb{unit}bot.0")))
    assert all(len(serial) == 32 for *_, serial in serials) and len({serial for *_, serial in serials}) == 3
    rtc = datetime.strptime(command[command.index("-rtc") + 1].split(",")[0].removeprefix("base="),
                            "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    # A base built in summer reads the hardware clock with 420: the clock is set so the guest boots 2 minutes behind.
    assert abs(rtc - (datetime.now(timezone.utc) - timedelta(minutes=2 + 420))) < timedelta(seconds=60)
    assert "restrict=on" in text and "hostfwd=tcp:127.0.0.1:55985-:5985" in text


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is not installed")
def test_a_qemu_base_is_located_and_checked_like_a_box(tmp_path, monkeypatch):
    monkeypatch.setenv(backends.QEMU_BASE_HOME_ENV, str(tmp_path))
    directory = tmp_path / "fmb-VAGRANTSLASH-windows-11-x64" / "0" / "amd64" / "qemu"
    directory.mkdir(parents=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(directory / "base.qcow2"), "1M"], check=True)
    (directory / "base-vars.fd").write_bytes(b"\0" * 16)

    location = QemuBackend.base_location("fmb/windows-11-x64", "0")
    assert location == {"kind": "qemu_base", "box": "fmb/windows-11-x64", "version": "0",
                        "architecture": "amd64", "provider": "qemu"}
    files = QemuBackend.base_files(QemuBackend.base_directory(location))
    assert [path.name for path in files] == ["base-vars.fd", "base.qcow2"]
    rows = [{"path": path.name} for path in files]
    QemuBackend.check_base(directory, "base.qcow2", rows)

    overlay = tmp_path / "overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
                    str(directory / "base.qcow2"), str(overlay)], check=True)
    shutil.move(overlay, directory / "base.qcow2.overlay")
    (directory / "base.qcow2").unlink()
    shutil.move(directory / "base.qcow2.overlay", directory / "base.qcow2")
    with pytest.raises(ValueError, match="standalone"):
        QemuBackend.check_base(directory, "base.qcow2", rows)


def test_the_qemu_paper_config_differs_from_the_paper_only_in_provider_and_box():
    paper, qemu = recipe.paper_config("I1"), recipe.paper_config("I1", "qemu", "fmb/windows-11-x64")
    assert {key for key in paper if paper[key] != qemu[key]} == {"provider", "windows_box"}
    assert recipe.validate_paper_config(qemu) == "I1"
    with pytest.raises(ValueError):
        recipe.paper_config("I1", "virtualbox")


def test_an_adhoc_module_without_arguments_gets_no_raw_params(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: calls.append(command))
    backends.ansible_adhoc("ansible", 5985, "ansible.windows.win_ping", {}, timeout=10)
    backends.ansible_adhoc("ansible", 5985, "ansible.windows.win_powershell", {"script": "hostname"}, timeout=10)
    assert "-a" not in calls[0]
    assert calls[1][calls[1].index("-a") + 1] == '{"script": "hostname"}'


def test_parsers_run_in_the_appliance_on_macos_natively_on_windows_and_in_qemu_elsewhere(monkeypatch):
    from fmb.collection.tools.host import parser_appliance

    for host, expected in (("darwin", ("vmware_desktop", "fmb/windows-11-arm64")),
                           ("win32", ("native_windows", None)), ("linux", ("qemu", recipe.qemu_box()))):
        monkeypatch.setattr(parser_appliance.sys, "platform", host)
        assert parser_appliance.parser_runtime() == expected


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is not installed")
def test_the_windows_write_path_keeps_crlf_and_eof_bytes_and_the_neighbouring_sectors(tmp_path):
    from fmb.generation.ntfs_surface_injection import _write_window
    from fmb.generation.qemu_image import QemuImageReader

    image = tmp_path / "disk.vmdk"
    subprocess.run(["qemu-img", "create", "-q", "-f", "vmdk", str(image), "4M"], check=True)
    reader = QemuImageReader(image)
    _write_window(reader, 0, bytes(range(256)) * 16, tmp_path)
    before = reader.read_at(0, 8192)
    payload = b"line one\r\nline two\r\n\x1a\x00\xff end"
    _write_window(reader, 1000, payload, tmp_path)

    after = reader.read_at(0, 8192)
    assert after[1000:1000 + len(payload)] == payload
    assert after[:1000] == before[:1000] and after[1000 + len(payload):] == before[1000 + len(payload):]


def test_the_uefi_firmware_is_the_first_pair_present_beside_qemu_or_in_a_distribution_folder(tmp_path, monkeypatch):
    from fmb.generation import qemu_host

    qemu = tmp_path / "bin" / "qemu-system-x86_64"
    fedora = tmp_path / "usr" / "share" / "edk2" / "ovmf"
    distribution = (fedora / "OVMF_CODE.fd", fedora / "OVMF_VARS.fd")
    bundled = (tmp_path / "share" / "qemu" / "edk2-x86_64-code.fd", tmp_path / "share" / "qemu" / "edk2-i386-vars.fd")
    monkeypatch.setattr(qemu_host, "QEMU_FIRMWARE", (("../share/qemu/edk2-x86_64-code.fd", "../share/qemu/edk2-i386-vars.fd"),
                                                     (str(distribution[0]), str(distribution[1]))))
    with pytest.raises(FileNotFoundError, match="OVMF"):
        qemu_host.uefi_firmware(qemu)
    for path in (*distribution, bundled[0]):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    assert qemu_host.uefi_firmware(qemu) == tuple(path.resolve() for path in distribution)
    bundled[1].write_bytes(b"")
    assert qemu_host.uefi_firmware(qemu) == tuple(path.resolve() for path in bundled)


def test_the_qemu_rtc_bias_comes_from_the_base_build_date(tmp_path, monkeypatch):
    import json

    backend = QemuBackend(pipeline=None)
    base = tmp_path / "fmb-VAGRANTSLASH-windows-11-x64" / "0" / "amd64" / "qemu" / "base.qcow2"
    base.parent.mkdir(parents=True)
    monkeypatch.setattr(backend, "base_path", lambda: base)
    assert backend.base_rtc_bias() == 480
    facts = base.parents[2] / "guest.json"
    facts.write_text(json.dumps({"finished_utc": "2026-10-08T20:06:00+00:00"}))
    assert backend.base_rtc_bias() == 420
    facts.write_text(json.dumps({"finished_utc": "2026-12-08T20:06:00+00:00"}))
    assert backend.base_rtc_bias() == 480
    assert [recipe.base_clock_lag_minutes(bias, "qemu") for bias in (480, 482, 600)] == [2, 2, 120]
    assert [recipe.base_clock_lag_minutes(bias, "vmware_desktop") for bias in (422, 480, 600)] == [-58, 0, 120]
