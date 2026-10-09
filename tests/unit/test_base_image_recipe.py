from __future__ import annotations

import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "tools" / "base-image" / "windows11-arm64"
SCRIPTS = RECIPE / "scripts"
AUTOUNATTEND = RECIPE / "autounattend.xml.pkrtpl"
ISO_LANGUAGE = "en-GB"
TEMPLATE = RECIPE / "windows11-arm64.pkr.hcl"
VMWARE_TEMPLATE = RECIPE / "windows11-arm64-vmware.pkr.hcl"
VMWARE_BUILD = RECIPE / "build-vmware-box.sh"
PROTOCOL = ROOT / "src" / "fmb" / "contracts" / "paper" / "protocol.json"
VARFILE = RECIPE / "variables.pkrvars.json"
VAGRANTFILE = ROOT / "src" / "fmb" / "generation" / "Vagrantfile"

EXPECTED_TIMEZONE = "Pacific Standard Time"
EXPECTED_LOCALE = "en-US"
EXPECTED_EDITION = "Windows 11 Pro"
LABCONFIG_KEYS = ("BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck")
REQUIRED_SCRIPTS = (
    "enable-winrm.ps1",
    "set-network-private.ps1",
    "disable-sleep-hibernate.ps1",
    "disable-update-reboots.ps1",
    "disable-automatic-updates.ps1",
    "enable-autologon.ps1",
    "install-vmware-tools.ps1",
)
REQUIRED_VARIABLES = (
    "iso_path",
    "iso_sha256",
    "drivers_dir",
    "output_dir",
    "cpus",
    "memory",
    "disk_size",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _tree() -> ET.Element:
    return ET.fromstring(AUTOUNATTEND.read_text(encoding="utf-8").replace("${ui_language}", ISO_LANGUAGE))


def _find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [e for e in root.iter() if _local(e.tag) == name]


def _child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return None


def _template_text() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_recipe_files_present() -> None:
    for path in (AUTOUNATTEND, TEMPLATE, VARFILE):
        assert path.is_file(), f"missing recipe file: {path}"
    for name in REQUIRED_SCRIPTS + ("shutdown.ps1",):
        assert (SCRIPTS / name).is_file(), f"missing script: {name}"


def test_autounattend_is_wellformed_and_every_component_is_arm64() -> None:
    root = _tree()
    components = _find_all(root, "component")
    assert components, "autounattend.xml has no <component> elements"
    for component in components:
        arch = component.get("processorArchitecture")
        name = component.get("name")
        assert arch == "arm64", f"component {name!r} has processorArchitecture={arch!r}, expected arm64"


def test_local_account_matches_vagrantfile() -> None:
    vagrant_text = VAGRANTFILE.read_text(encoding="utf-8")
    match = re.search(r"winrm\.username\s*=\s*['\"]([^'\"]+)['\"]", vagrant_text)
    assert match, "could not read config.winrm.username from the Vagrantfile"
    expected_user = match.group(1)
    assert expected_user == "vagrant"

    root = _tree()
    accounts = _find_all(root, "LocalAccount")
    names = {_child_text(acct, "Name") for acct in accounts}
    assert expected_user in names, f"no LocalAccount named {expected_user!r}; found {names}"

    autologon = _find_all(root, "AutoLogon")
    assert len(autologon) == 1, "expected exactly one AutoLogon block"
    block = autologon[0]
    assert _child_text(block, "Username") == expected_user
    assert (_child_text(block, "Enabled") or "").lower() == "true"
    assert _child_text(block, "LogonCount") == "1", "the answer file's autologon covers one logon"
    script = (SCRIPTS / "enable-autologon.ps1").read_text(encoding="utf-8")
    assert "'AutoAdminLogon' -Type String -Value '1'" in script
    assert f"'DefaultUserName' -Type String -Value '{expected_user}'" in script
    assert "Remove-ItemProperty -Path $winlogon -Name 'AutoLogonCount'" in script


def test_timezone_and_locale_match_the_lock() -> None:
    root = _tree()

    timezones = {(e.text or "").strip() for e in _find_all(root, "TimeZone")}
    assert EXPECTED_TIMEZONE in timezones, f"TimeZone values {timezones} lack {EXPECTED_TIMEZONE!r}"

    assert {(e.text or "").strip() for e in _find_all(root, "UILanguage")} == {ISO_LANGUAGE}
    locale_tags = {"UserLocale", "SystemLocale", "UILanguageFallback", "InputLocale"}
    seen_userlocale = False
    for tag in locale_tags:
        for element in _find_all(root, tag):
            value = (element.text or "").strip()
            assert value == EXPECTED_LOCALE, f"{tag}={value!r}, expected {EXPECTED_LOCALE!r}"
            if tag == "UserLocale":
                seen_userlocale = True
    assert seen_userlocale, "no <UserLocale> element found"


def test_labconfig_bypass_keys_present() -> None:
    root = _tree()
    paths = " \n ".join((e.text or "") for e in _find_all(root, "Path"))
    for key in LABCONFIG_KEYS:
        assert key in paths, f"LabConfig key {key!r} not set via a RunSynchronous reg add"


def test_only_microsofts_public_setup_key_is_embedded_and_edition_selected_by_name() -> None:
    root = _tree()
    keys = [(_child_text(e, "Key"), _child_text(e, "WillShowUI")) for e in _find_all(root, "ProductKey")]
    assert keys == [("W269N-WFGWX-YVC9B-4J6C9-T83GX", "OnError")]

    metadata = _find_all(root, "MetaData")
    assert metadata, "edition must be selected via ImageInstall/.../MetaData"
    keys = {_child_text(m, "Key") for m in metadata}
    values = {_child_text(m, "Value") for m in metadata}
    assert "/IMAGE/NAME" in keys, f"MetaData Key values {keys} lack /IMAGE/NAME"
    assert EXPECTED_EDITION in values, f"MetaData Value {values} lack {EXPECTED_EDITION!r}"

def test_one_answer_file_serves_both_builders() -> None:
    assert not _find_all(_tree(), "DriverPaths")
    media = (RECIPE / "make-answer-media.sh").read_text(encoding="utf-8")
    assert "$WinPEDriver\\$/NetKVM/w11/ARM64" in media


def test_first_logon_order_keeps_winrm_last() -> None:
    lines = [(e.text or "") for e in _find_all(_find_all(_tree(), "FirstLogonCommands")[0], "CommandLine")]
    scripts = [m.group(1) for line in lines if (m := re.search(r"-File C:\\fmb\\scripts\\(\S+\.ps1)", line))]
    assert scripts == [
        "disable-sleep-hibernate.ps1",
        "install-vmware-tools.ps1",
        "set-network-private.ps1",
        "disable-update-reboots.ps1",
        "disable-automatic-updates.ps1",
        "enable-autologon.ps1",
        "enable-winrm.ps1",
    ]
    assert "first-logon-complete.txt" in lines[-1], "the completion marker is the last command"
    updates = (SCRIPTS / "disable-automatic-updates.ps1").read_text(encoding="utf-8")
    assert "'NoAutoUpdate' -Type DWord -Value 1" in updates, "no update is staged during a generation run"
    assert "New-Item -Path $au -Force" in updates and "if (-not (Test-Path $au))" in updates, \
        "the policy key keeps the reboot policy set before it"
    tools = (SCRIPTS / "install-vmware-tools.ps1").read_text(encoding="utf-8")
    assert "'vmxnet3'" in tools and "REBOOT=R" in tools, "Tools CD found by its vmxnet3 folder, installed silently"


def test_firstlogon_commands_reference_existing_scripts() -> None:
    root = _tree()
    blocks = _find_all(root, "FirstLogonCommands")
    assert len(blocks) == 1, "expected exactly one FirstLogonCommands block"
    command_lines = [(e.text or "") for e in _find_all(blocks[0], "CommandLine")]
    assert command_lines, "FirstLogonCommands has no CommandLine entries"

    referenced = set()
    for line in command_lines:
        referenced.update(re.findall(r"[A-Za-z0-9_.-]+\.ps1", line))
    assert referenced, "FirstLogonCommands reference no .ps1 scripts"
    for script in referenced:
        assert (SCRIPTS / Path(script).name).is_file(), f"FirstLogonCommands reference missing script {script!r}"
    for script in REQUIRED_SCRIPTS:
        assert script in referenced, f"FirstLogonCommands do not run {script!r}"


def test_template_references_existing_scripts() -> None:
    referenced = re.findall(r"[A-Za-z0-9_.-]+\.ps1", _template_text())
    assert "shutdown.ps1" in referenced, "template must shut the guest down via shutdown.ps1"
    for script in referenced:
        assert (SCRIPTS / Path(script).name).is_file(), f"template references missing script {script!r}"


def test_template_declares_required_variables() -> None:
    text = _template_text()
    for name in REQUIRED_VARIABLES:
        assert re.search(rf'variable\s+"{re.escape(name)}"', text), f"template does not declare variable {name!r}"


def test_template_expresses_required_qemu_devices_and_communicator() -> None:
    text = _template_text()
    required_fragments = [
        'accelerator  = "hvf"',
        "its=off",
        "gic-version=3",
        "highmem=on",
        'cpu_model    = "host"',
        "efi_boot          = true",
        "if=pflash",
        "nvme",
        "usb-storage",
        "qemu-xhci",
        "usb-kbd",
        "usb-tablet",
        "ramfb",
        "virtio-net-pci",
        'communicator   = "winrm"',
        'winrm_username = "vagrant"',
        'format    = "qcow2"',
    ]
    for fragment in required_fragments:
        assert fragment in text, f"template is missing required fragment: {fragment!r}"


def test_varfile_declares_required_variables() -> None:
    data = json.loads(VARFILE.read_text(encoding="utf-8"))
    keys = {k for k in data if not k.startswith("_")}
    missing = set(REQUIRED_VARIABLES) - keys
    assert not missing, f"var-file is missing required variables: {sorted(missing)}"


def _vmware_text() -> str:
    return VMWARE_TEMPLATE.read_text(encoding="utf-8")


def test_vmware_template_mirrors_the_study_base_and_makes_the_generators_box() -> None:
    text = _vmware_text()
    for fragment in (
        'source "vmware-iso" "win11arm64"',
        'guest_os_type = "arm-windows11-64"',
        'firmware      = "efi"',
        "version       = 20",
        'disk_adapter_type  = "nvme"',
        'disk_type_id       = "1"',
        'cdrom_adapter_type = "sata"',
        'network_adapter_type = "vmxnet3"',
        '"sata0:1.fileName"       = var.answer_iso',
        '"sata0:1.present"        = "FALSE"',
        '"sata0:2.fileName"       = var.tools_iso',
        '"sata0:2.present"        = "FALSE"',
        '"usb_xhci.present"      = "TRUE"',
        '"usb_xhci:4.deviceType" = "hid"',
        '"usb_xhci:6.deviceType" = "hub"',
        '"usb_xhci:7.deviceType" = "hub"',
        'vm_name          = "box"',
        'communicator   = "winrm"',
        'winrm_username = "vagrant"',
        'post-processor "vagrant"',
        "default     = 65536",
    ):
        assert fragment in text, f"VMware template is missing: {fragment!r}"
    assert 'winrm_timeout  = var.winrm_timeout' in text and 'default     = "6h"' in text
    provisioner = text.split('provisioner "powershell"')[1]
    assert "first-logon-complete.txt" in provisioner and "Start-Sleep" in provisioner, "waits for the marker"
    assert text.count('provisioner "windows-restart"') == 2, "restart once, then repair Tools and restart again"
    assert r'restart_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\fmb\\scripts\\repair-vmware-tools.ps1"' in text
    assert "'the VMware Tools service is not running'" in text, "the build checks that the Tools service runs"
    repair = (SCRIPTS / "repair-vmware-tools.ps1").read_text(encoding="utf-8")
    assert "'/fa'" in repair and "1641" in repair, "Windows Installer repair; 1641 means it restarted the guest itself"
    assert "cd_content" not in text.split("source ")[1].split("build {")[0].replace("cd_files/cd_content", "")
    for script in re.findall(r"[A-Za-z0-9_.-]+\.ps1", text):
        assert (SCRIPTS / script).is_file(), f"VMware template references missing script {script!r}"


def test_vmware_build_starts_the_guest_clock_like_the_generator() -> None:
    text = _vmware_text()
    assert '"rtc.startInUTC" = "TRUE"' in text
    assert '"rtc.startTime"  = var.rtc_start_time' in text
    script = VMWARE_BUILD.read_text(encoding="utf-8")
    bias = json.loads(PROTOCOL.read_text(encoding="utf-8"))["generation"]["vmware_boot_clock_bias_minutes"]
    assert f"rtc_bias_minutes={bias}" in script, "the build uses the generator's frozen boot clock bias"
    assert "rtc_start=$(( $(date +%s) - rtc_bias_minutes * 60 ))" in script
    assert '-var "rtc_start_time=$rtc_start"' in script
    vagrantfile = VAGRANTFILE.read_text(encoding="utf-8")
    assert "vmware.vmx['rtc.startInUTC'] = 'TRUE'" in vagrantfile
    assert "vmware.vmx['rtc.startTime'] = (Time.now.to_i - rtc_bias * 60).to_s" in vagrantfile


def test_vmware_build_ends_with_the_guest_offline_and_its_event_logs_uncompressed() -> None:
    text = _vmware_text()
    offline = text.index(r"C:\\fmb\\scripts\\offline-base.ps1")
    assert text.index("'the VMware Tools service is not running'") < offline < text.index('provisioner "file"')
    script = (SCRIPTS / "offline-base.ps1").read_text(encoding="utf-8")
    for fragment in ("-DestinationPrefix '0.0.0.0/0'", "-Direction Outbound -Action Block", "'2000::/3'",
                     "Test-Outbound '1.1.1.1' 443", "C:\\Windows\\SoftwareDistribution\\Download",
                     "Stop-Service -Name EventLog -Force", "& compact.exe /u $logs"):
        assert fragment in script, f"offline-base.ps1 is missing: {fragment!r}"


@pytest.mark.pwsh
@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell unavailable")
def test_the_offline_block_spares_exactly_the_nat_subnet(tmp_path) -> None:
    probe = tmp_path / "ranges.ps1"
    probe.write_text(f". '{SCRIPTS / 'offline-base.ps1'}'\n"
                     "(Get-OutsideRanges '192.168.77.129' 24) -join ' | '\n"
                     "(Get-OutsideRanges '10.0.2.15' 24) -join ' | '\n"
                     "try { Get-OutsideRanges '192.168.77.129' 16 } catch { 'refused' }\n", encoding="utf-8")
    result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)],
                            text=True, capture_output=True, check=True, timeout=60)
    assert result.stdout.splitlines() == [
        "1.0.0.0-126.255.255.255 | 128.0.0.0-169.253.255.255 | 169.255.0.0-192.168.76.255 | 192.168.78.0-223.255.255.255",
        "1.0.0.0-10.0.1.255 | 10.0.3.0-126.255.255.255 | 128.0.0.0-169.253.255.255 | 169.255.0.0-223.255.255.255",
        "refused",
    ]


def test_vmware_build_script_adds_the_box_the_generator_boots() -> None:
    script = VMWARE_BUILD.read_text(encoding="utf-8")
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))["generation"]
    assert f"box_name={protocol['windows_box']}" in script
    assert protocol["base_box_version"] == "0", "a box added from a file gets version 0"
    assert 'vagrant box add --name "$box_name" "$box_file"' in script
    default_box = re.search(r'box_path\s*=\s*"\$\{local.work_dir\}/([^"]+)"', _vmware_text())
    assert default_box and f'box_file="$work/{default_box.group(1)}"' in script
    assert '-var "work_dir=$work"' in script, "the build output goes where the script checked the free space"
    assert "shasum -a 256" in script, "the ISO's checksum is verified before the build"
    assert 'packer build -on-error=abort "$@" "$template"' in script, "a failed build keeps its VM for inspection"
    assert "--write-dependency-lock" in script and "--guest-windows-build $build" in script


def test_the_ui_language_comes_from_the_iso_in_both_builders() -> None:
    template = AUTOUNATTEND.read_text(encoding="utf-8")
    assert template.count("${") == template.count("${ui_language}") == 3, "only the three UILanguage values vary"
    build = VMWARE_BUILD.read_text(encoding="utf-8")
    assert "sources/lang.ini" in build
    assert 'FMB_UI_LANGUAGE=$ui_language "$here/make-answer-media.sh" "" "$work/build/answer.iso"' in build
    assert '-var "answer_iso=$work/build/answer.iso"' in build
    media = (RECIPE / "make-answer-media.sh").read_text(encoding="utf-8")
    assert 'sed "s/\\${ui_language}/$ui_language/g"' in media


def test_answer_media_carries_every_script_and_the_driver_only_when_given() -> None:
    media = (RECIPE / "make-answer-media.sh").read_text(encoding="utf-8")
    assert 'cp "$here/scripts/"*.ps1 "$stage/scripts/"' in media
    assert 'if [ -n "$drivers_dir" ]; then' in media, "a VMware build passes no NIC driver"
