from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

from fmb.replication import host

AGENT = {"User-Agent": "Mozilla/5.0"}
RETRY_SECONDS = (5, 30)


def log(message: str) -> None:
    print(f"[fmb] {message}", flush=True)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    log(" ".join(str(part) for part in command))
    return subprocess.run([str(part) for part in command], check=True, env=host.environment(), **kwargs)


def fetch(url: str) -> bytes:
    for wait in (*RETRY_SECONDS, None):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=AGENT), timeout=300) as response:
                return response.read()
        except (OSError, http.client.HTTPException) as error:
            if wait is None:
                raise SystemExit(f"downloading {url} failed {len(RETRY_SECONDS) + 1} times; the last time: "
                                 f"{error}") from error
            log(f"downloading {url} failed ({error}); trying again in {wait} s")
            time.sleep(wait)


def dotnet_runtime() -> None:
    version = host.PINS["dotnet_runtime"]["version"]
    dotnet = host.which("dotnet")
    listed = subprocess.run([dotnet, "--list-runtimes"], capture_output=True, text=True, check=False,
                            env=host.environment()).stdout if dotnet else ""
    if f"Microsoft.NETCore.App {version} " in listed:
        return
    target = host.dotnet_home()
    with tempfile.TemporaryDirectory() as temporary:
        if host.WINDOWS:
            script = Path(temporary) / "dotnet-install.ps1"
            script.write_bytes(fetch("https://dot.net/v1/dotnet-install.ps1"))
            run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
                 "-Runtime", "dotnet", "-Version", version, "-InstallDir", target, "-NoPath"])
        else:
            script = Path(temporary) / "dotnet-install.sh"
            script.write_bytes(fetch("https://dot.net/v1/dotnet-install.sh"))
            run(["bash", script, "--runtime", "dotnet", "--version", version, "--install-dir", target, "--no-path"])


def ansible() -> None:
    pins = host.PINS["ansible"]
    if host.MACOS:
        return
    if host.WINDOWS:
        distro, venv = host.PINS["wsl_distribution"], "/mnt/c/fmb-ansible"
        run(["wsl.exe", "-d", distro, "-u", "root", "--exec", "bash", "-c",
             "dpkg -s python3-venv > /dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq python3-venv)"])
        run(["wsl.exe", "-d", distro, "--exec", "bash", "-c",
             f"test -x {venv}/bin/ansible || python3 -m venv {venv} && "
             f"{venv}/bin/pip install -q ansible-core=={pins['ansible-core']} pywinrm=={pins['pywinrm']} && "
             f"{venv}/bin/ansible-galaxy collection install ansible.windows:=={pins['ansible.windows']} -p {venv}/collections"])
        run(["uv", "tool", "install", "--force", "--python", platform.python_version(), host.REPO / "tools" / "wsl-ansible"])
        return
    run(["uv", "tool", "install", "--force", "--python", platform.python_version(), f"ansible-core=={pins['ansible-core']}",
         "--with", f"pywinrm=={pins['pywinrm']}"])
    run([host.which("ansible-galaxy"), "collection", "install", f"ansible.windows:=={pins['ansible.windows']}"])


def toolchain() -> Path:
    root = host.toolchain_root()
    pins = host.PINS["eztools"]
    if not root.exists():
        data = (host.REPO / pins["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != pins["sha256"]:
            raise SystemExit("the EZ tools archive does not match its pinned sha256")
        root.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root.parent) as temporary, tarfile.open(fileobj=io.BytesIO(data)) as tar:
            tar.extractall(temporary, filter="data")
            (Path(temporary) / "net9").rename(root)
    run([sys.executable, host.REPO / "scripts" / "bootstrap_eztools.py", "--verify-only", "--root", root])
    dfir = [sys.executable, host.REPO / "scripts" / "bootstrap_dfir_ntfs.py"]
    if not Path(host.environment()["FMB_DFIR_NTFS_ENV"]).exists():
        run(dfir)
    elif subprocess.run([str(part) for part in [*dfir, "--verify-only"]], env=host.environment(), check=False).returncode:
        run([*dfir, "--recreate"])
    return root


def windows_parsers() -> Path:
    return host.cache() / "windows-parsers"


def parser_build(path: Path) -> str | None:
    """The validated build a Windows parser is; None when it is missing, damaged or not validated."""
    from fmb.collection.tools.host.parser_appliance import validated_builds

    return validated_builds(path.name).get(file_sha256(path)) if path.is_file() else None


def parsers() -> None:
    """PECmd.exe and SBECmd.exe as builds fmb run accepts; their URLs serve upstream's newest build."""
    from fmb.collection.tools.host.parser_appliance import validated_builds

    for name, url in host.PINS["windows_parsers"].items():
        path = windows_parsers() / name
        if parser_build(path):
            continue
        try:
            data = zipfile.ZipFile(io.BytesIO(fetch(url))).read(name)
        except (zipfile.BadZipFile, KeyError) as error:
            raise SystemExit(f"{url} gave no {name}: {error}") from error
        digest, builds = hashlib.sha256(data).hexdigest(), validated_builds(name)
        if digest not in builds:
            raise SystemExit(f"{url} now serves a {name} that fmb has not validated (SHA-256 {digest}); fmb run accepts "
                             "only the validated builds: " + "; ".join(f"{sha} ({label})" for sha, label in builds.items())
                             + f". Put a validated {name} at {path} by hand, such as a copy from a machine set up "
                             "earlier, then run fmb setup again.")
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_name(name + ".part")
        part.write_bytes(data)
        os.replace(part, path)
        log(f"{name}: {builds[digest]}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def checked_iso(iso: Path | None, pin: dict, unpinned_iso: bool) -> tuple[Path, str]:
    if iso is None:
        raise SystemExit(f"the Windows base is built from Microsoft's ISO: download {pin['choose']} from "
                         f"{pin['download']} ({pin['file']}), then run: fmb setup --iso <that file>")
    iso = Path(iso).expanduser().resolve()
    if not iso.is_file():
        raise SystemExit(f"no ISO at {iso}")
    log(f"checking {iso.name} against the pinned SHA-256")
    sha256 = file_sha256(iso)
    if sha256 != pin["sha256"] and not unpinned_iso:
        raise SystemExit(f"{iso.name} is not the pinned ISO ({pin['file']}): its SHA-256 is {sha256}, the pin is "
                         f"{pin['sha256']}. Microsoft offers only its current build. To build the base from this ISO "
                         "anyway, add --unpinned-iso: every result then records the base's build and this SHA-256.")
    return iso, sha256


def box(iso: Path | None = None, *, unpinned_iso: bool = False) -> dict | None:
    """The Mac's Windows 11 ARM64 Vagrant box, built from Microsoft's ARM64 ISO by the box script."""
    if (host.vagrant_boxes() / "fmb-VAGRANTSLASH-windows-11-arm64").is_dir():
        return host.box_guest_facts()
    iso, sha256 = checked_iso(iso, host.PINS["windows_iso_arm64"], unpinned_iso)
    try:
        run(["sh", host.REPO / "tools" / "base-image" / "windows11-arm64" / "build-vmware-box.sh", iso, sha256])
    except subprocess.CalledProcessError as error:
        raise SystemExit("building the Windows box failed; the box script says why above") from error
    return host.box_guest_facts()


def base(iso: Path | None = None, *, unpinned_iso: bool = False) -> dict:
    from fmb.generation.recipe import qemu_box

    facts = host.base_guest_facts()
    if facts is not None:
        return facts
    iso, sha256 = checked_iso(iso, host.PINS["windows_iso"], unpinned_iso)
    pin = host.PINS["windows_iso"]
    work = host.cache() / "base-build"
    pins = host.PINS["base_builder"]
    run(["uv", "run", "--no-project", "--python", platform.python_version(), "--with", f"pycdlib=={pins['pycdlib']}",
         "--with", f"pywinrm=={pins['pywinrm']}", "--with", f"psutil=={pins['psutil']}", "--with", "tzdata",
         "python", host.REPO / "tools" / "base-image" / "windows11-x64" / "install.py",
         "--iso-url", iso, "--iso-sha256", sha256, "--edition", pin["edition"], "--work", work])
    box = host.base_home() / qemu_box().replace("/", "-VAGRANTSLASH-") / "0"
    target = box / "amd64" / "qemu"
    target.mkdir(parents=True, exist_ok=True)
    for name in ("base.qcow2", "base-vars.fd"):
        shutil.move(work / name, target / name)
    shutil.move(work / "guest.json", box / "guest.json")
    log(f"base placed in {target}")
    return json.loads((box / "guest.json").read_text(encoding="utf-8"))


def all_steps(*, build_base: bool = True, iso: Path | None = None, unpinned_iso: bool = False) -> None:
    dotnet_runtime()
    ansible()
    toolchain()
    if build_base and host.provider() == "qemu":
        log(f"base guest: {base(iso, unpinned_iso=unpinned_iso)}")
    elif build_base:
        log(f"Windows box: {box(iso, unpinned_iso=unpinned_iso)}")
    parsers()
