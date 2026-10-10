from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PINS = json.loads((Path(__file__).with_name("pins.json")).read_text(encoding="utf-8"))
QEMU_WINDOWS_DIR = Path(r"C:\Program Files\qemu")
WINDOWS = sys.platform == "win32"
MACOS = sys.platform == "darwin"
LINUX_QEMU = {
    "debian": "sudo apt-get update && sudo apt-get install qemu-system-x86 qemu-utils ovmf",
    "fedora": "sudo dnf install qemu-system-x86-core qemu-img edk2-ovmf",
    "arch": "sudo pacman -S qemu-system-x86 qemu-img edk2-ovmf",
    "suse": "sudo zypper install qemu-x86 qemu-tools qemu-ovmf-x86_64",
}
VMRUN = Path("/Applications/VMware Fusion.app/Contents/Public/vmrun")
RESERVE_GIB = 8
RESULT_GIB = 2
LONG_PATHS = ("admin PowerShell: New-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem "
              "-Name LongPathsEnabled -Value 1 -PropertyType DWord -Force")


def cache() -> Path:
    return Path(os.environ.get("FMB_CACHE") or Path.home() / ".cache" / "fmb").expanduser()


def provider() -> str:
    return "vmware_desktop" if MACOS else "qemu"


def base_home() -> Path:
    return Path(os.environ.get("FMB_QEMU_BASE_HOME") or cache() / "qemu-bases").expanduser()


def base_guest_facts() -> dict | None:
    from fmb.generation.recipe import qemu_box

    path = base_home() / qemu_box().replace("/", "-VAGRANTSLASH-") / "0" / "guest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def box_guest_facts() -> dict | None:
    path = vagrant_boxes() / "fmb-VAGRANTSLASH-windows-11-arm64" / "0" / "guest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def guest_facts(name: str | None = None) -> dict | None:
    return base_guest_facts() if (name or provider()) == "qemu" else box_guest_facts()


def windows_base() -> dict | None:
    facts = guest_facts()
    if facts is None:
        return None
    sha256 = facts.get("iso_sha256")
    return {"build": ".".join(str(part) for part in (facts["build"], facts.get("ubr")) if part is not None),
            "iso_sha256": sha256,
            "iso_pinned": None if sha256 is None else sha256 == PINS["windows_iso"]["sha256"]}


def dotnet_home() -> Path:
    return cache() / "dotnet"


def uv_tool_bin() -> Path | None:
    uv = shutil.which("uv")
    if not uv:
        return None
    completed = subprocess.run([uv, "tool", "dir", "--bin"], capture_output=True, text=True, check=False)
    return Path(completed.stdout.strip()) if completed.returncode == 0 and completed.stdout.strip() else None


def environment() -> dict[str, str]:
    env = dict(os.environ)
    front = [str(path) for path in (dotnet_home(), uv_tool_bin(), QEMU_WINDOWS_DIR if WINDOWS else None)
             if path and Path(path).is_dir()]
    env["PATH"] = os.pathsep.join(front + [env.get("PATH", "")])
    if dotnet_home().is_dir():
        env["DOTNET_ROOT"] = str(dotnet_home())
    env.setdefault("FMB_QEMU_BASE_HOME", str(base_home()))
    env.setdefault("FMB_HOST_TOOLCHAIN_ROOT", str(cache() / "eztools" / "net9"))
    env.setdefault("FMB_DFIR_NTFS_ENV", str(cache() / "dfir-ntfs" / "venv"))
    env.setdefault("PYTHONUTF8", "1")
    return env


def toolchain_root() -> Path:
    return Path(environment()["FMB_HOST_TOOLCHAIN_ROOT"])


def which(name: str) -> str | None:
    return shutil.which(name, path=environment()["PATH"])


def free_gib(path: Path) -> float:
    path.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(path).free / 2**30


def vagrant_boxes() -> Path:
    return Path(os.environ.get("VAGRANT_HOME") or Path.home() / ".vagrant.d").expanduser() / "boxes"


def allocated_gib(folder: Path) -> float:
    total = 0
    for path in folder.rglob("*"):
        if path.is_file():
            stat = path.stat()
            total += getattr(stat, "st_blocks", 0) * 512 or stat.st_size
    return total / 2**30


def image_need_gib() -> float:
    if MACOS:
        box = vagrant_boxes() / "fmb-VAGRANTSLASH-windows-11-arm64"
        size = max((allocated_gib(version) for version in box.glob("*") if version.is_dir()), default=26)
        return size + 2 * RESERVE_GIB + 1 + RESULT_GIB
    from fmb.generation.recipe import qemu_box

    base = base_home() / qemu_box().replace("/", "-VAGRANTSLASH-") / "0"
    return 2 * (allocated_gib(base) if base.is_dir() else 10) + RESERVE_GIB + RESULT_GIB


def generation_running() -> bool:
    listing = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,args="], capture_output=True, text=True, check=False).stdout
    return any("fmb.replication.steps generate" in line and line.split(None, 1)[0] != str(os.getpid())
               for line in listing.splitlines())


def leftovers() -> list[tuple[str, str]]:
    if WINDOWS or generation_running():
        return []
    found = []
    work = cache() / "vm-work"
    if MACOS and work.is_dir():
        found += [("clone", str(folder)) for folder in sorted(work.iterdir()) if folder.is_dir()]
    if not MACOS:
        listing = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,args="], capture_output=True, text=True, check=False).stdout
        found += [("qemu", line.split(None, 1)[0]) for line in listing.splitlines()
                  if "qemu-system" in line and "/.vagrant/system.qcow2" in line]
        found += [("overlay", str(disk.parent)) for disk in
                  sorted(Path.cwd().glob("generated/*/generation/attempt-*/full_scale/*/.vagrant/system.qcow2"))]
    return found


def accelerates(qemu: str, accelerator: str) -> bool:
    process = subprocess.Popen([qemu, "-machine", f"q35,accel={accelerator}", "-cpu", "max", "-m", "64", "-S",
                                "-display", "none", "-nodefaults"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        process.wait(timeout=8)
        return False
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return True


def qemu_install() -> str:
    if WINDOWS:
        return "winget install SoftwareFreedomConservancy.QEMU"
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        release = {}
    for name in (release.get("ID", ""), *release.get("ID_LIKE", "").split()):
        if name in LINUX_QEMU:
            return LINUX_QEMU[name]
    return "install QEMU (qemu-system-x86_64, qemu-img, qemu-io) and its x86-64 UEFI firmware (OVMF)"


def long_paths() -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as key:
            return winreg.QueryValueEx(key, "LongPathsEnabled")[0] == 1
    except OSError:
        return False


def check(rows: list, name: str, found, fix: str) -> None:
    rows.append((name, bool(found), str(found) if found and found is not True else ("found" if found else fix)))


def checks() -> list[tuple[str, bool, str]]:
    rows: list[tuple[str, bool, str]] = []
    system = platform.system()
    need, free = image_need_gib(), free_gib(Path.cwd())
    rows.append((f"free disk for one image ({need:.0f} GiB while it is generated and analysed)", free >= need,
                 f"{free:.0f} GiB free at {Path.cwd()}"))
    stale = leftovers()
    rows.append(("no VMs left by an interrupted generation", not stale,
                 "none" if not stale else "fmb generate stops and removes them before it starts: "
                 + ", ".join(target for _, target in stale)))
    runtimes = subprocess.run([which("dotnet"), "--list-runtimes"], capture_output=True, text=True,
                              check=False).stdout if which("dotnet") else ""
    wanted = f"Microsoft.NETCore.App {PINS['dotnet_runtime']['version']}"
    check(rows, f".NET runtime {PINS['dotnet_runtime']['version']}", wanted in runtimes,
          "run: fmb setup (installs it under the cache)")
    if MACOS:
        check(rows, "VMware Fusion (vmrun)", VMRUN.exists() and VMRUN, "install VMware Fusion 13")
        check(rows, "Vagrant", which("vagrant"), "install Vagrant and the vagrant-vmware-desktop plugin")
        check(rows, "Ansible", which("ansible-playbook"), "brew install ansible")
        box = vagrant_boxes() / "fmb-VAGRANTSLASH-windows-11-arm64"
        check(rows, "the paper's Windows box (fmb/windows-11-arm64)", box.is_dir() and box,
              "build it: tools/base-image/windows11-arm64/build-vmware-box.sh (or set VAGRANT_HOME to where it is)")
        return rows
    from fmb.generation.qemu_host import uefi_firmware

    qemu = which("qemu-system-x86_64")
    check(rows, "QEMU", qemu and which("qemu-img") and which("qemu-io") and qemu, qemu_install())
    try:
        firmware = uefi_firmware(Path(qemu))[0] if qemu else None
    except FileNotFoundError:
        firmware = None
    check(rows, "UEFI firmware for QEMU (OVMF)", firmware, qemu_install())
    if system == "Linux":
        check(rows, "KVM (/dev/kvm read-write)", os.access("/dev/kvm", os.R_OK | os.W_OK),
              "sudo usermod -aG kvm $USER, then log in again")
    else:
        check(rows, "Windows Hypervisor Platform (QEMU starts with WHPX)", qemu and accelerates(qemu, "whpx"),
              "admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform; reboot")
        listed = subprocess.run(["wsl.exe", "--list", "--quiet"], capture_output=True, check=False).stdout
        distro = PINS["wsl_distribution"]
        check(rows, f"WSL distribution {distro}", distro in listed.decode("utf-16-le", "replace"),
              f"wsl --install -d {distro} --no-launch; wsl --set-version {distro} 1")
        check(rows, "long paths (collection writes paths over 260 characters)", long_paths(), LONG_PATHS)
    check(rows, "Ansible with WinRM", which("ansible-playbook"), "run: fmb setup")
    base = windows_base()
    built = base and f"build {base['build']}, " + {True: "from the pinned ISO", None: "ISO not recorded",
                                                    False: f"from an unpinned ISO (SHA-256 {base['iso_sha256']})"}[base["iso_pinned"]]
    iso = PINS["windows_iso"]
    check(rows, "Windows base image", built,
          f"download {iso['file']} from {iso['download']}, then run: fmb setup --iso <that file> (~30 min)")
    return rows
