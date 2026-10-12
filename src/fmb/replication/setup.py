from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path

from fmb.replication import host

AGENT = {"User-Agent": "Mozilla/5.0"}
RETRY_SECONDS = (5, 30)
# The base build's peak in the cache on CI: its installed disk (about 24 GiB) beside the compressed base (10 GiB).
BASE_BUILD_GIB = 40
BASE_GIB = 11
BUILD_HOURS = 8


def log(message: str) -> None:
    print(f"[fmb] {message}", flush=True)


def run(command: list[str], env: dict[str, str] | None = None, **kwargs) -> subprocess.CompletedProcess:
    log(" ".join(str(part) for part in command))
    return subprocess.run([str(part) for part in command], check=True, env={**host.environment(), **(env or {})},
                          **kwargs)


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
    """Installs fmb's Ansible under the cache, apart from the user's own Ansible and collections."""
    pins = host.PINS["ansible"]
    if host.MACOS:
        return
    home = host.ansible_home()
    private = {"UV_TOOL_DIR": str(home / "tools"), "UV_TOOL_BIN_DIR": str(home / "bin")}
    if host.WINDOWS:
        distro, venv = host.wsl_distribution(), "/mnt/c/fmb-ansible"
        run(["wsl.exe", "-d", distro, "-u", "root", "--exec", "bash", "-c",
             "dpkg -s python3-venv > /dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq python3-venv)"])
        run(["wsl.exe", "-d", distro, "--exec", "bash", "-c",
             f"test -x {venv}/bin/ansible || python3 -m venv {venv} && "
             f"{venv}/bin/pip install -q ansible-core=={pins['ansible-core']} pywinrm=={pins['pywinrm']} && "
             f"{venv}/bin/ansible-galaxy collection install ansible.windows:=={pins['ansible.windows']} -p {venv}/collections"])
        run(["uv", "tool", "install", "--force", "--python", platform.python_version(), host.REPO / "tools" / "wsl-ansible"],
            env=private)
        return
    run(["uv", "tool", "install", "--force", "--python", platform.python_version(), f"ansible-core=={pins['ansible-core']}",
         "--with", f"pywinrm=={pins['pywinrm']}"], env=private)
    # ansible-galaxy creates its -p folder before it downloads, and fmb's Ansible runs use <home>/collections alone
    # once it exists, so the folder appears only with the collection in it.
    staging = home / "collections.partial"
    shutil.rmtree(staging, ignore_errors=True)
    run([home / "bin" / "ansible-galaxy", "collection", "install", f"ansible.windows:=={pins['ansible.windows']}",
         "-p", staging], env={"ANSIBLE_COLLECTIONS_PATH": str(staging)})
    shutil.rmtree(home / "collections", ignore_errors=True)
    staging.rename(home / "collections")


def toolchain() -> Path:
    root = eztools()
    dfir = [sys.executable, host.REPO / "scripts" / "bootstrap_dfir_ntfs.py"]
    if not Path(host.environment()["FMB_DFIR_NTFS_ENV"]).exists():
        run(dfir)
    elif subprocess.run([str(part) for part in [*dfir, "--verify-only"]], env=host.environment(), check=False).returncode:
        run([*dfir, "--recreate"])
    return root


def eztools() -> Path:
    """The pinned EZ tools, extracted again when they do not verify (a new pin, a quarantined or damaged file)."""
    root = host.toolchain_root()
    verify = [sys.executable, host.REPO / "scripts" / "bootstrap_eztools.py", "--verify-only", "--root", root]
    if root.exists():
        if passes(verify):
            return root
        if not root.resolve().is_relative_to(host.cache().resolve()):
            raise SystemExit(f"{root} does not hold the pinned EZ tools, and fmb replaces only its own copy under "
                             f"{host.cache()}: unset FMB_HOST_TOOLCHAIN_ROOT, or put the pinned tools there")
        log(f"{root} does not hold the pinned EZ tools; extracting them again")
    extract_eztools(root)
    if not passes(verify):
        raise SystemExit(f"the EZ tools in {root} do not verify even after a fresh extraction; bootstrap_eztools.py "
                         "says why above")
    return root


def extract_eztools(root: Path) -> None:
    pins = host.PINS["eztools"]
    data = (host.REPO / pins["file"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != pins["sha256"]:
        raise SystemExit("the EZ tools archive does not match its pinned sha256")
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root.parent) as temporary, tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(temporary, filter="data")
        if root.exists():
            root.rename(Path(temporary) / "replaced")
        (Path(temporary) / "net9").rename(root)


def passes(command: list) -> bool:
    log(" ".join(str(part) for part in command))
    return subprocess.run([str(part) for part in command], env=host.environment(), check=False).returncode == 0


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

    work = host.cache() / "base-build"
    with exclusive(work / "build.lock"):
        facts = host.base_guest_facts()
        if facts is not None:
            return facts
        iso, sha256 = checked_iso(iso, host.PINS["windows_iso"], unpinned_iso)
        room(work)
        pin, pins = host.PINS["windows_iso"], host.PINS["base_builder"]
        build(["uv", "run", "--no-project", "--python", platform.python_version(), "--with",
               f"pycdlib=={pins['pycdlib']}", "--with", f"pywinrm=={pins['pywinrm']}", "--with",
               f"psutil=={pins['psutil']}", "--with", "tzdata",
               "python", host.REPO / "tools" / "base-image" / "windows11-x64" / "install.py",
               "--iso-url", iso, "--iso-sha256", sha256, "--edition", pin["edition"], "--work", work], work)
        box = host.base_home() / qemu_box().replace("/", "-VAGRANTSLASH-") / "0"
        target = box / "amd64" / "qemu"
        target.mkdir(parents=True, exist_ok=True)
        for name in ("base.qcow2", "base-vars.fd"):
            shutil.move(work / name, target / name)
        shutil.move(work / "guest.json", box / "guest.json")
    log(f"base placed in {target}")
    return json.loads((box / "guest.json").read_text(encoding="utf-8"))


@contextmanager
def exclusive(path: Path):
    """An OS lock, which ends with its process: a second base build cannot share the build folder."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit(f"another fmb setup is building the Windows base in {path.parent}; wait for it to end, "
                             "then run fmb setup again") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def room(work: Path) -> None:
    """Refuses a base build that would fill the disk: QEMU then pauses the install, which only looks stalled."""
    free, kept = host.free_gib(work), host.allocated_gib(work)  # the build replaces what an earlier one kept there
    if free + kept < BASE_BUILD_GIB:
        raise SystemExit(f"building the Windows base needs about {BASE_BUILD_GIB} GiB free at {work}, and it has "
                         f"{free:.0f} GiB" + (f" plus {kept:.0f} GiB that an earlier build left there" if kept >= 1
                                              else "") + ". Free some, or set FMB_CACHE to a folder on a larger "
                         "disk, then run fmb setup again.")
    home = host.base_home()
    if not home.resolve().is_relative_to(work.parent.resolve()) and host.free_gib(home) < BASE_GIB:
        raise SystemExit(f"the Windows base (about {BASE_GIB} GiB) moves to {home} once built, and it has "
                         f"{host.free_gib(home):.0f} GiB free. Free some there, or unset FMB_QEMU_BASE_HOME, then run "
                         "fmb setup again.")


def build(command: list, work: Path) -> None:
    """Runs the base build in its own process group, which Ctrl-C or a kill of fmb ends whole, QEMU included; its
    output goes to the terminal and to install.log, and a failure ends in an error that names its last line."""
    from fmb.core.owned_process import run_owned

    log(" ".join(str(part) for part in command))
    work.mkdir(parents=True, exist_ok=True)
    last = [""]
    with (work / "install.log").open("w", encoding="utf-8") as stream, interruptible():
        def show(line: str) -> None:
            line = line.rstrip("\r\n")
            stream.write(line + "\n")
            stream.flush()
            print(line, flush=True)
            last[0] = line.strip() or last[0]

        try:
            run_owned([str(part) for part in command], env=host.environment(), timeout=BUILD_HOURS * 3600,
                      on_line=show)
        except KeyboardInterrupt as error:
            raise KeyboardInterrupt(f"the base build was stopped ({error}) and its processes ended. "
                                    + left_behind(work)) from None
        except subprocess.SubprocessError as error:
            ending = (f"exit {error.returncode}" if isinstance(error, subprocess.CalledProcessError)
                      else f"still running after {BUILD_HOURS} hours")
            raise SystemExit(f"the Windows base build failed ({ending}): {last[0] or 'it printed nothing'}. Its whole "
                             f"output is in {work / 'install.log'}; QEMU's log (qemu.log), the guest's serial log "
                             f"(serial.log) and screenshots (shots/) are beside it. {left_behind(work)}") from None


def left_behind(work: Path) -> str:
    return (f"{work} holds {host.allocated_gib(work):.1f} GiB: the next fmb setup --iso starts over there, and "
            "deleting it is safe.")


@contextmanager
def interruptible():
    """A kill of fmb or a closed terminal (SIGTERM, SIGHUP) stops it as Ctrl-C does; later signals wait for the
    cleanup that follows."""
    # A signal the caller already ignores stays ignored: under nohup the build must outlive a closed terminal.
    names = [name for name in ("SIGINT", "SIGTERM", "SIGHUP")
             if hasattr(signal, name) and signal.getsignal(getattr(signal, name)) is not signal.SIG_IGN]

    def interrupt(number, frame):
        for name in names:
            signal.signal(getattr(signal, name), signal.SIG_IGN)
        raise KeyboardInterrupt(signal.Signals(number).name)

    previous = {name: signal.signal(getattr(signal, name), interrupt) for name in names}
    try:
        yield
    finally:
        for name, handler in previous.items():
            signal.signal(getattr(signal, name), handler)


def all_steps(*, build_base: bool = True, iso: Path | None = None, unpinned_iso: bool = False) -> None:
    dotnet_runtime()
    ansible()
    toolchain()
    if build_base and host.provider() == "qemu":
        log(f"base guest: {base(iso, unpinned_iso=unpinned_iso)}")
    elif build_base:
        log(f"Windows box: {box(iso, unpinned_iso=unpinned_iso)}")
    parsers()
