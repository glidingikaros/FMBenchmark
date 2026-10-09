from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psutil
import pycdlib
import winrm

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[2] / "src")]
from guest_console import diagnose, wsman_status

from fmb.generation.qemu_host import QEMU_ACCELERATORS as ACCELERATORS
from fmb.generation.qemu_host import QEMU_CPU
from fmb.generation.qemu_host import uefi_firmware as firmware

PAPER_SCRIPTS = HERE.parent / "windows11-arm64" / "scripts"
BASE_SCRIPTS = ("disable-sleep-hibernate.ps1", "set-network-private.ps1", "disable-update-reboots.ps1",
                "disable-automatic-updates.ps1", "enable-autologon.ps1", "offline-base.ps1")
CI_SCRIPTS = ("enable-winrm-ntlm.ps1", "first-logon.ps1")
GUEST_ZONE = ZoneInfo("America/Los_Angeles")
READY = ("if (-not (Test-Path C:\\fmb\\first-logon-complete.txt)) { exit 3 };"
         "$o = Get-CimInstance Win32_OperatingSystem; $c = Get-Volume -DriveLetter C;"
         "'{0} | {1} | build {2} | {3} | user {4}' -f $o.Caption, $o.Version, $o.BuildNumber, $o.OSArchitecture, $env:USERNAME;"
         "'C: {0} {1:N1} GB used' -f $c.FileSystem, (($c.Size - $c.SizeRemaining) / 1GB)")
PRODUCT = ("$p = Get-CimInstance SoftwareLicensingProduct -Filter "
           "\"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL\";")
LICENSE = PRODUCT + ("ConvertTo-Json -Compress @{name = $p.Name; status = [int]$p.LicenseStatus;"
                     " grace_minutes = [int]$p.GracePeriodRemaining; evaluation_end = [string]$p.EvaluationEndDate}")
ACTIVATE = PRODUCT + "Invoke-CimMethod -InputObject $p -MethodName Activate | Out-Null"
PRO_IMAGE = ("<InstallFrom><MetaData wcm:action=\"add\"><Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>"
             "</MetaData></InstallFrom>")
PRO_KEY = "<ProductKey><Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key><WillShowUI>OnError</WillShowUI></ProductKey>"
PAPER_KEY = "W269N-WFGWX-YVC9B-4J6C9-T83GX"
FACTS = ("$o = Get-CimInstance Win32_OperatingSystem; $v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
         "ConvertTo-Json -Compress @{build = [string]$o.BuildNumber; ubr = [int]$v.UBR; display_version = [string]$v.DisplayVersion;"
         " timezone = (Get-TimeZone).Id; locale = (Get-Culture).Name; caption = $o.Caption}")
SETUP_STATE = ("$s = Get-ItemProperty HKLM:\\SYSTEM\\Setup; $w = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
               "ConvertTo-Json -Compress @{setup_in_progress = [int]$s.SystemSetupInProgress; oobe_in_progress = [int]$s.OOBEInProgress;"
               " setup_type = [int]$s.SetupType; autologon = [string]$w.AutoAdminLogon; autologon_user = [string]$w.DefaultUserName;"
               " autologon_count = [string]$w.AutoLogonCount}")
SETUP_DONE = {"setup_in_progress": 0, "oobe_in_progress": 0, "setup_type": 0, "autologon": "1",
              "autologon_user": "vagrant", "autologon_count": ""}


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def qemu_binary() -> Path:
    found = shutil.which("qemu-system-x86_64") or r"C:\Program Files\qemu\qemu-system-x86_64.exe"
    if not Path(found).is_file():
        raise SystemExit("qemu-system-x86_64 not found")
    return Path(found).resolve()


def qemu_tool(qemu: Path, name: str) -> str:
    return str(qemu.with_name(qemu.name.replace("qemu-system-x86_64", name)))


def iso_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 << 20):
            digest.update(chunk)
    log(f"iso: {path}, {path.stat().st_size} bytes, sha256 {digest.hexdigest()}")
    return digest.hexdigest()


def download(url: str, target: Path) -> str:
    started = time.monotonic()
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as out:
        log(f"iso: from {urllib.parse.urlsplit(response.url).netloc}")
        while chunk := response.read(8 << 20):
            out.write(chunk)
            digest.update(chunk)
    log(f"iso: {target.stat().st_size} bytes, sha256 {digest.hexdigest()}, {time.monotonic() - started:.0f}s")
    return digest.hexdigest()


def answer_iso(target: Path, edition: str) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=4, joliet=3)

    def add(data: bytes, name: str, folder: str = "") -> None:
        iso.add_fp(io.BytesIO(data), len(data), f"{folder}/{name};1", joliet_path=f"{folder}/{name}")

    answers = (HERE / "autounattend.xml").read_text(encoding="utf-8")
    if edition == "pro":
        index = ("<InstallFrom><MetaData wcm:action=\"add\"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData>"
                 "</InstallFrom>")
        assert index in answers and "<Organization>FMB</Organization>" in answers
        answers = answers.replace(index, PRO_IMAGE).replace("<Organization>FMB</Organization>",
                                                            "<Organization>FMB</Organization>" + PRO_KEY)
    add(answers.encode("utf-8"), "autounattend.xml")
    iso.add_directory("/scripts", joliet_path="/scripts")
    for name in BASE_SCRIPTS:
        add((PAPER_SCRIPTS / name).read_bytes(), name, "/scripts")
    for name in CI_SCRIPTS:
        add((HERE / "scripts" / name).read_bytes(), name, "/scripts")
    iso.write(str(target))
    iso.close()


def monitor(port: int, command: str) -> None:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.recv(4096)
            connection.sendall(command.encode() + b"\n")
            time.sleep(0.3)
    except OSError:
        pass


def monitor_query(port: int, command: str) -> str:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.settimeout(30)
            def read(done) -> bytes:
                data, deadline = b"", time.monotonic() + 60
                while not done(data) and time.monotonic() < deadline and (chunk := connection.recv(65536)):
                    data += chunk
                return data

            read(lambda data: data.endswith(b"(qemu) "))
            connection.sendall(command.encode() + b"\n")
            return read(lambda data: b"\r\n" in data and data.endswith(b"(qemu) ")).decode(errors="replace")
    except OSError:
        return ""


def disk_writes(port: int) -> int | None:
    for line in monitor_query(port, "info blockstats").splitlines():
        if line.startswith("disk:"):
            for field in line.split():
                if field.startswith("wr_bytes="):
                    return int(field.removeprefix("wr_bytes="))
    return None


CD_BOOT = re.compile(rb'starting Boot[0-9A-F]{4} "UEFI QEMU DVD-ROM')


def boot_from_cd(monitor_port: int, serial: Path, wait: float = 120, presses: int = 8) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and not CD_BOOT.search(serial.read_bytes() if serial.exists() else b""):
        time.sleep(0.2)
    started = CD_BOOT.search(serial.read_bytes() if serial.exists() else b"") is not None
    log("firmware started the CD: answering its key prompt" if started
        else "no CD start in the serial log: pressing keys as before")
    for _ in range(presses if started else 40):
        monitor(monitor_port, "sendkey spc")
        time.sleep(0.5)
    return started


def watch_console(monitor_port: int, label: str, seconds: int = 360, every: float = 3) -> None:
    def take() -> None:
        for index in range(int(seconds / every)):
            monitor(monitor_port, f"screendump shots/{label}-early-{index:03d}.png -f png")
            time.sleep(every)

    threading.Thread(target=take, daemon=True).start()


class Machine:
    def __init__(self, command: list[str], work: Path, relaunch_on_exit: bool):
        self.command, self.work, self.relaunch_on_exit, self.relaunches = command, work, relaunch_on_exit, 0
        self.process = self.launch("w")

    def launch(self, mode: str) -> subprocess.Popen:
        with (self.work / "qemu.log").open(mode) as qemu_log:
            return subprocess.Popen(self.command, cwd=self.work, stdout=qemu_log, stderr=subprocess.STDOUT)

    @property
    def pid(self) -> int:
        return self.process.pid

    def poll(self) -> int | None:
        return self.process.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self.process.wait(timeout)

    def kill(self) -> None:
        self.process.kill()

    def relaunched_after_guest_restart(self) -> bool:
        if not self.relaunch_on_exit or self.process.poll() != 0 or self.relaunches >= 12:
            return False
        self.relaunches += 1
        log(f"the guest restarted, which ends QEMU under -no-reboot: starting it again ({self.relaunches})")
        self.process = self.launch("a")
        return True


class Stalled(Exception):
    pass


def session(port: int) -> winrm.Session:
    return winrm.Session(f"http://127.0.0.1:{port}/wsman", auth=("vagrant", "vagrant"),
                         transport="ntlm", message_encryption="always",
                         read_timeout_sec=150, operation_timeout_sec=120)


def ready(port: int) -> str | None:
    try:
        result = session(port).run_ps(READY)
    except Exception:
        return None
    return result.std_out.decode(errors="replace").strip() if result.status_code == 0 else None


def retried(call, attempts: int = 5):
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except Exception as error:
            if attempt == attempts:
                raise
            log(f"WinRM call failed ({type(error).__name__}: {str(error)[:200]}); retry {attempt}")
            time.sleep(20)


def guest(port: int, script: str) -> str:
    result = retried(lambda: session(port).run_ps(script))
    output = result.std_out.decode(errors="replace").strip()
    if result.status_code != 0:
        raise RuntimeError(f"guest command failed ({result.status_code}): {output} "
                           f"{result.std_err.decode(errors='replace')[-1500:]}")
    return output


SERIAL_SEEN = [0]
GUEST_SPOKE = [False]


def serial_news(work: Path) -> None:
    lines = (work / "serial.log").read_bytes().decode(errors="replace").splitlines()
    for line in lines[SERIAL_SEEN[0]:]:
        if "FMB" in line:
            GUEST_SPOKE[0] = True
            log("guest: " + line[line.index("FMB"):].strip())
    SERIAL_SEEN[0] = len(lines)


def wait_ready(vm: Machine | subprocess.Popen, work: Path, winrm_port: int, monitor_port: int, deadline: float,
               label: str, stall_seconds: int | None = None) -> str:
    usage = psutil.Process(vm.pid)
    usage.cpu_percent()
    tick = 0
    written, writing_since = None, time.monotonic()
    while (facts := ready(winrm_port)) is None:
        serial_news(work)
        if stall_seconds and not GUEST_SPOKE[0]:
            now = disk_writes(monitor_port)
            if now is not None and now != written:
                written, writing_since = now, time.monotonic()
            elif now is not None and time.monotonic() - writing_since > stall_seconds:
                raise Stalled(f"no disk writes for {stall_seconds // 60} minutes at {written} bytes")
        if vm.poll() is not None:
            if not (isinstance(vm, Machine) and vm.relaunched_after_guest_restart()):
                raise SystemExit("QEMU exited before WinRM answered:\n"
                                 + (work / "qemu.log").read_text(errors="replace")[-2000:])
            usage = psutil.Process(vm.pid)
            usage.cpu_percent()
        if time.monotonic() > deadline:
            raise SystemExit(f"no WinRM ({label})")
        monitor(monitor_port, f"screendump shots/{label}-{tick:03d}.png -f png")
        log(f"{label} {tick}: qemu cpu {usage.cpu_percent():.0f}%")
        tick += 1
        time.sleep(30)
    serial_news(work)
    return facts


def interactive(winrm_port: int) -> None:
    check = ("$e = Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue |"
             " Where-Object { $_.UserName -like '*\\vagrant' }; if (-not $e) { exit 4 }; 'vagrant desktop session up'")
    for _ in range(20):
        try:
            log(guest(winrm_port, check))
            return
        except RuntimeError:
            time.sleep(15)
    raise RuntimeError("vagrant has no interactive session after the restart: autologon is not working")


def power(winrm_port: int, flag: str) -> None:
    try:
        session(winrm_port).run_cmd("shutdown", [flag, "/t", "5", "/f"])
    except Exception as error:
        log(f"shutdown {flag}: the connection ended ({type(error).__name__}), as Windows went down")


def activate(winrm_port: int) -> dict:
    for attempt in range(6):
        facts = json.loads(guest(winrm_port, LICENSE))
        if facts["status"] == 1:
            return facts
        log(f"licence not active ({facts}); activating, attempt {attempt + 1}")
        try:
            guest(winrm_port, ACTIVATE)
        except RuntimeError as error:
            log(str(error)[:800])
        time.sleep(20)
    raise SystemExit(f"the evaluation licence did not activate: {facts}")


def licensed(facts: dict) -> bool:
    return facts["status"] == 1 or "Eval" not in facts["name"]


def base_script(winrm_port: int, name: str) -> str:
    result = retried(lambda: session(winrm_port).run_cmd(
        "powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f"C:\\fmb\\scripts\\{name}"]))
    output = result.std_out.decode(errors="replace").strip() + result.std_err.decode(errors="replace")[-1500:]
    if result.status_code != 0:
        raise RuntimeError(f"{name} exited with {result.status_code}: {output}")
    return output


def finish(vm: Machine, work: Path, winrm_port: int, monitor_port: int, edition: str) -> None:
    if edition == "pro":
        log(guest(winrm_port, f"cscript //nologo C:\\Windows\\System32\\slmgr.vbs /ipk {PAPER_KEY}"))
    license_facts = activate(winrm_port) if edition == "eval" else json.loads(guest(winrm_port, LICENSE))
    log(f"licence: {license_facts}")
    log(f"after first logon: {guest(winrm_port, SETUP_STATE)}")
    log(base_script(winrm_port, "enable-autologon.ps1"))

    power(winrm_port, "/r")
    time.sleep(90)
    log(wait_ready(vm, work, winrm_port, monitor_port, time.monotonic() + 1800, "restart"))
    interactive(winrm_port)
    license_now = json.loads(guest(winrm_port, LICENSE))
    log(f"licence after the restart: {license_now}")
    if not licensed(license_now):
        raise RuntimeError(f"the evaluation licence did not survive the restart: {license_now}")
    time.sleep(180)
    guest(winrm_port, "Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
                      " -Name OpenFolderInNewTab -Type DWord -Value 0")
    facts = json.loads(guest(winrm_port, FACTS)) | {"license": license_facts}
    (work / "guest.json").write_text(json.dumps(facts, indent=2))
    log(f"guest facts: {facts}")
    log(base_script(winrm_port, "offline-base.ps1"))
    log("first-logon log:\n" + guest(winrm_port, "Get-Content C:\\fmb\\first-logon.log"))
    state = json.loads(guest(winrm_port, SETUP_STATE))
    log(f"setup and autologon: {state}")
    if state != SETUP_DONE:
        raise RuntimeError(f"Windows Setup is unfinished or autologon will not last: {state}")


def verify(qemu: Path, accelerator: str, cpu: str, work: Path) -> None:
    subprocess.run([qemu_tool(qemu, "qemu-img"), "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", "win.qcow2",
                    "verify.qcow2"], cwd=work, check=True)
    shutil.copyfile(work / "vars.fd", work / "verify-vars.fd")
    winrm_port, monitor_port = free_port(), free_port()
    rtc = (datetime.now(timezone.utc) - timedelta(minutes=480)).strftime("%Y-%m-%dT%H:%M:%S")
    command = [
        str(qemu), "-machine", f"q35,accel={accelerator}", "-cpu", cpu, "-smp", "2", "-m", "4096",
        "-rtc", f"base={rtc},clock=host",
        "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
        "-drive", "if=pflash,format=raw,file=verify-vars.fd",
        "-drive", "id=disk,if=none,format=qcow2,file=verify.qcow2",
        "-device", "ide-hd,drive=disk,bus=ide.0,bootindex=0",
        "-device", "qemu-xhci,id=xhci,p2=8,p3=8",
        "-netdev", f"user,id=nat,restrict=on,hostfwd=tcp:127.0.0.1:{winrm_port}-:5985",
        "-device", "e1000e,netdev=nat,mac=00:50:56:00:fd:01",
        "-netdev", "user,id=hostonly,restrict=on,net=192.168.56.0/24",
        "-device", "e1000e,netdev=hostonly,mac=00:50:56:00:fd:02",
        "-vga", "std", "-display", "none",
        "-monitor", f"tcp:127.0.0.1:{monitor_port},server,nowait",
        "-serial", "file:verify-serial.log",
    ]
    log(" ".join(command))
    with (work / "qemu.log").open("a") as qemu_log:
        vm = subprocess.Popen(command, cwd=work, stdout=qemu_log, stderr=subprocess.STDOUT)
    try:
        log(wait_ready(vm, work, winrm_port, monitor_port, time.monotonic() + 900, "verify"))
        interactive(winrm_port)
        state = json.loads(guest(winrm_port, SETUP_STATE))
        license_now = json.loads(guest(winrm_port, LICENSE))
        log(f"verify: setup and autologon {state}; licence {license_now}")
        if state != SETUP_DONE or not licensed(license_now):
            raise SystemExit(f"the base does not boot finished and licensed: {state}, {license_now}")
    except (Exception, SystemExit):
        log(f"verify failed; WinRM listener from the host: {wsman_status(winrm_port)}; console diagnostic in shots/")
        try:
            diagnose(monitor_port, work / "shots")
        except OSError as error:
            log(f"console diagnostic: {error}")
        raise
    finally:
        monitor(monitor_port, "screendump shots/verify-last.png -f png")
        time.sleep(3)
        vm.kill()
        vm.wait()
        (work / "verify.qcow2").unlink(missing_ok=True)
        (work / "verify-vars.fd").unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso-url", required=True, help="a link to the ISO, or the ISO file itself")
    parser.add_argument("--iso-sha256", help="the ISO's expected SHA-256, checked before the install")
    parser.add_argument("--edition", choices=("eval", "pro"), default="eval")
    parser.add_argument("--work", type=Path, default=Path("win-work"))
    parser.add_argument("--cpu", help="QEMU -cpu value; default: generation's (fmb.generation.qemu_host)")
    parser.add_argument("--deadline-min", type=int, default=75)
    args = parser.parse_args()

    accelerator = ACCELERATORS[platform.system()]
    cpu = args.cpu or QEMU_CPU[accelerator]
    qemu = qemu_binary()
    code, variables = firmware(qemu)
    work = args.work.resolve()
    (work / "shots").mkdir(parents=True, exist_ok=True)
    log(f"host {platform.system()} {platform.machine()} {cpu_model()}, accelerator {accelerator}, cpu {cpu}")
    log(subprocess.run([str(qemu), "--version"], capture_output=True, text=True).stdout.splitlines()[0])

    iso = Path(args.iso_url)
    if iso.is_file():
        iso = iso.resolve()
        iso_sha256 = iso_digest(iso)
    else:
        iso = work / "win.iso"
        iso_sha256 = download(args.iso_url, iso)
    if args.iso_sha256 and iso_sha256 != args.iso_sha256.lower():
        raise SystemExit(f"the ISO's sha256 is {iso_sha256}, not the expected {args.iso_sha256.lower()}")
    answer_iso(work / "answer.iso", args.edition)
    shutil.copyfile(code, work / "code.fd")
    shutil.copyfile(variables, work / "vars.fd")
    winrm_port, monitor_port = free_port(), free_port()

    def start() -> Machine:
        shutil.copyfile(variables, work / "vars.fd")
        (work / "win.qcow2").unlink(missing_ok=True)
        (work / "serial.log").unlink(missing_ok=True)
        subprocess.run([qemu_tool(qemu, "qemu-img"), "create", "-q", "-f", "qcow2", "win.qcow2", "64G"], cwd=work,
                       check=True)
        rtc = datetime.now(GUEST_ZONE).strftime("%Y-%m-%dT%H:%M:%S")
        command = [
            str(qemu), "-machine", f"q35,accel={accelerator}", "-cpu", cpu, "-smp", "2", "-m", "4096",
            "-rtc", f"base={rtc}",
            "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
            "-drive", "if=pflash,format=raw,file=vars.fd",
            "-drive", "id=disk,if=none,format=qcow2,file=win.qcow2,cache=unsafe",
            "-device", "ide-hd,drive=disk,bus=ide.0,bootindex=0",
            "-drive", f"id=winiso,if=none,media=cdrom,readonly=on,file={str(iso).replace(',', ',,')}",
            "-device", "ide-cd,drive=winiso,bus=ide.1,bootindex=1",
            "-drive", "id=answer,if=none,media=cdrom,readonly=on,file=answer.iso",
            "-device", "ide-cd,drive=answer,bus=ide.2",
            "-device", "qemu-xhci,id=xhci",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{winrm_port}-:5985",
            "-device", "e1000e,netdev=net0",
            "-vga", "std", "-display", "none",
            "-monitor", f"tcp:127.0.0.1:{monitor_port},server,nowait",
            "-chardev", "file,id=serial0,path=serial.log,append=on", "-serial", "chardev:serial0",
            *(["-no-reboot"] if accelerator == "whpx" else []),
        ]
        log(" ".join(command))
        SERIAL_SEEN[0], GUEST_SPOKE[0] = 0, False
        started = Machine(command, work, relaunch_on_exit=accelerator == "whpx")
        boot_from_cd(monitor_port, work / "serial.log")
        return started

    for install_try in (1, 2):
        vm = start()
        watch_console(monitor_port, f"install{install_try}")
        booted = time.monotonic()
        try:
            log(wait_ready(vm, work, winrm_port, monitor_port, booted + args.deadline_min * 60, f"install{install_try}",
                           stall_seconds=600))
            break
        except Stalled as stall:
            vm.kill()
            vm.wait()
            if install_try == 2:
                raise SystemExit(f"Windows Setup stalled twice: {stall}") from stall
            log(f"install {install_try} stalled ({stall}); installing again on a fresh disk")
        except BaseException:
            vm.kill()
            vm.wait()
            raise
    try:
        log(f"windows ready {time.monotonic() - booted:.0f}s after boot")
        for round_number in range(1, 4):
            try:
                finish(vm, work, winrm_port, monitor_port, args.edition)
                break
            except Exception as error:
                if round_number == 3:
                    raise
                log(f"finishing round {round_number} failed ({type(error).__name__}: {str(error)[:300]}); "
                    "resetting the guest and finishing again")
                monitor(monitor_port, "system_reset")
                time.sleep(60)
                log(wait_ready(vm, work, winrm_port, monitor_port, time.monotonic() + 1800, f"reset{round_number}"))
        power(winrm_port, "/s")
        vm.wait(timeout=300)
    finally:
        if vm.poll() is None:
            vm.kill()
            vm.wait()
    facts = json.loads((work / "guest.json").read_text())
    facts.update(finished_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"), clock_zone=str(GUEST_ZONE),
                 iso_sha256=iso_sha256)
    (work / "guest.json").write_text(json.dumps(facts, indent=2))

    if iso == work / "win.iso":
        iso.unlink()
    verify(qemu, accelerator, cpu, work)
    started = time.monotonic()
    subprocess.run([qemu_tool(qemu, "qemu-img"), "convert", "-c", "-O", "qcow2", "-o", "compression_type=zstd",
                    "win.qcow2", "base.qcow2"], cwd=work, check=True)
    (work / "win.qcow2").unlink()
    shutil.copyfile(work / "vars.fd", work / "base-vars.fd")
    log(f"base: {(work / 'base.qcow2').stat().st_size / 2**30:.1f} GiB compressed in {time.monotonic() - started:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
