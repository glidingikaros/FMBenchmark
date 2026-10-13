import hashlib
import importlib.util
import io
import os
import re
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from fmb.cli.commands import SET_UP_BY_FMB
from fmb.replication import host, setup


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_a_download_is_tried_again_with_backoff_and_a_failure_names_its_url(monkeypatch):
    waited, answers = [], [urllib.error.URLError("Tunnel connection failed: 403 Forbidden"), ConnectionResetError(104)]

    def urlopen(request, timeout):
        if answers:
            raise answers.pop(0)
        return Response(b"payload")

    monkeypatch.setattr(setup.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(setup.time, "sleep", waited.append)
    assert setup.fetch("https://example.invalid/tool.zip") == b"payload"
    assert waited == list(setup.RETRY_SECONDS)

    def unavailable(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(setup.urllib.request, "urlopen", unavailable)
    with pytest.raises(SystemExit, match=r"downloading https://example\.invalid/tool\.zip failed 3 times; .*404"):
        setup.fetch("https://example.invalid/tool.zip")


def zipped(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def validated_only(monkeypatch, tmp_path, good: bytes):
    from fmb.collection.tools.host import parser_appliance

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    builds = {hashlib.sha256(good).hexdigest(): "the validated build"}
    monkeypatch.setattr(parser_appliance, "validated_builds", lambda name: dict(builds))


def test_setup_installs_only_validated_parser_builds_and_names_an_unvalidated_download(tmp_path, monkeypatch):
    good, newer = b"MZ validated", b"MZ upstream's newer build"
    validated_only(monkeypatch, tmp_path, good)
    served = {"PECmd.exe": newer, "SBECmd.exe": good}
    fetched = []

    def fetch(url):
        fetched.append(url)
        name = url.rsplit("/", 1)[1].replace(".zip", ".exe")
        return zipped(name, served[name])

    monkeypatch.setattr(setup, "fetch", fetch)
    folder = tmp_path / "windows-parsers"
    with pytest.raises(SystemExit) as failure:
        setup.parsers()
    message = str(failure.value)
    assert host.PINS["windows_parsers"]["PECmd.exe"] in message
    assert hashlib.sha256(newer).hexdigest() in message and hashlib.sha256(good).hexdigest() in message
    assert f"at {folder / 'PECmd.exe'} by hand" in message
    assert not (folder / "PECmd.exe").exists() and not (folder / "PECmd.exe.part").exists()

    served["PECmd.exe"] = good
    (folder / "PECmd.exe").parent.mkdir(parents=True, exist_ok=True)
    (folder / "PECmd.exe").write_bytes(good[:3])  # an interrupted earlier write
    fetched.clear()
    setup.parsers()
    assert (folder / "PECmd.exe").read_bytes() == good and (folder / "SBECmd.exe").read_bytes() == good
    assert len(fetched) == 2 and not list(folder.glob("*.part"))
    setup.parsers()
    assert len(fetched) == 2


def test_setup_check_reports_whether_the_parsers_are_validated_builds(tmp_path, monkeypatch):
    good = b"MZ validated"
    validated_only(monkeypatch, tmp_path, good)
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0)
    monkeypatch.setattr(host, "leftovers", lambda: [])
    monkeypatch.setattr(host, "which", lambda name: None)
    folder = tmp_path / "windows-parsers"
    folder.mkdir()
    (folder / "PECmd.exe").write_bytes(good)
    (folder / "SBECmd.exe").write_bytes(b"MZ unvalidated")

    def row():
        return next(row for row in host.checks() if row[0].startswith("Windows parsers"))

    name, ok, detail = row()
    assert not ok and detail == f"run: fmb setup (SBECmd.exe in {folder}: missing or not a validated build)"
    assert name.startswith(SET_UP_BY_FMB)
    (folder / "SBECmd.exe").write_bytes(good)
    assert row()[1:] == (True, "the validated build; the validated build")


def test_setup_checks_the_parsers_before_the_long_steps(monkeypatch):
    done = []
    for name in ("dotnet_runtime", "ansible", "toolchain", "base", "box"):
        monkeypatch.setattr(setup, name, lambda *_, name=name, **__: done.append(name))
    monkeypatch.setattr(host, "provider", lambda: "qemu")

    def unvalidated():
        raise SystemExit("https://example.invalid/PECmd.zip now serves a PECmd.exe that fmb has not validated")

    monkeypatch.setattr(setup, "parsers", unvalidated)
    with pytest.raises(SystemExit, match="has not validated"):
        setup.all_steps()
    assert done == []
    monkeypatch.setattr(setup, "parsers", lambda: done.append("parsers"))
    setup.all_steps()
    assert done == ["parsers", "dotnet_runtime", "ansible", "toolchain", "base"]


def test_fmb_run_checks_the_parsers_before_it_generates_anything(tmp_path, monkeypatch):
    from fmb.replication import run

    good = b"MZ validated"
    validated_only(monkeypatch, tmp_path, good)
    monkeypatch.setattr(run, "implementation", lambda paper: {})
    monkeypatch.setattr(run, "prepare", lambda images, where: pytest.fail("went on to generate"))
    folder = tmp_path / "windows-parsers"
    folder.mkdir()
    (folder / "PECmd.exe").write_bytes(good)
    with pytest.raises(SystemExit, match=rf"^SBECmd\.exe in {re.escape(str(folder))}: missing or not a validated "
                                         r"build, and S2 needs both, so fmb run stops before generating I1, I2; "
                                         r"run: fmb setup$"):
        run.run_images(["I1", "I2"], None, tmp_path / "generated", tmp_path / "results")

    def reached(images, where):
        raise SystemExit("reached the generation")

    (folder / "SBECmd.exe").write_bytes(good)
    monkeypatch.setattr(run, "prepare", reached)
    with pytest.raises(SystemExit, match="reached the generation"):
        run.run_images(["I1", "I2"], None, tmp_path / "generated", tmp_path / "results")


def pinned_eztools(monkeypatch, tmp_path, content: bytes):
    archive = tmp_path / "eztools.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("net9/RECmd.dll")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    monkeypatch.setitem(host.PINS, "eztools", {"file": str(archive),
                                               "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()})
    monkeypatch.setattr(setup, "passes", lambda command: (Path(command[-1]) / "RECmd.dll").read_bytes() == b"pinned")


def test_ez_tools_that_fail_verification_are_extracted_again(tmp_path, monkeypatch):
    monkeypatch.setenv("FMB_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("FMB_HOST_TOOLCHAIN_ROOT", raising=False)
    pinned_eztools(monkeypatch, tmp_path, b"pinned")
    root = setup.eztools()
    assert root == tmp_path / "cache" / "eztools" / "net9"
    (root / "RECmd.dll").write_bytes(b"damaged")
    (root / "added by hand.txt").write_text("x")
    assert setup.eztools() == root
    assert (root / "RECmd.dll").read_bytes() == b"pinned" and not (root / "added by hand.txt").exists()
    assert [path.name for path in root.parent.iterdir()] == ["net9"]

    (root / "RECmd.dll").write_bytes(b"damaged")
    pinned_eztools(monkeypatch, tmp_path, b"a pin that does not verify")
    with pytest.raises(SystemExit, match=f"the EZ tools in {re.escape(str(root))} do not verify even after"):
        setup.eztools()


def test_ez_tools_outside_fmbs_cache_are_never_replaced(tmp_path, monkeypatch):
    own = tmp_path / "mine"
    own.mkdir()
    (own / "RECmd.dll").write_bytes(b"my build")
    monkeypatch.setenv("FMB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FMB_HOST_TOOLCHAIN_ROOT", str(own))
    pinned_eztools(monkeypatch, tmp_path, b"pinned")
    with pytest.raises(SystemExit, match="unset FMB_HOST_TOOLCHAIN_ROOT"):
        setup.eztools()
    assert (own / "RECmd.dll").read_bytes() == b"my build"


def test_a_second_base_build_is_refused_while_one_runs(tmp_path):
    lock = tmp_path / "base-build" / "build.lock"
    with setup.exclusive(lock):
        with pytest.raises(SystemExit, match=f"another fmb setup is building the Windows base in "
                                             f"{re.escape(str(lock.parent))}"):
            with setup.exclusive(lock):
                pass
    with setup.exclusive(lock):
        pass


def test_a_failed_base_build_names_its_exit_code_last_line_logs_and_what_it_left(tmp_path, capsys):
    work = tmp_path / "base-build"
    work.mkdir()
    (work / "win.qcow2").write_bytes(b"\0" * 4096)
    script = ("print('[04:30:00] install2 20: qemu cpu 200%', flush=True); import sys; "
              "sys.exit('Windows Setup stalled twice: no disk writes for 10 minutes at 20971520000 bytes')")
    with pytest.raises(SystemExit) as failure:
        setup.build([sys.executable, "-c", script], work)
    message = str(failure.value)
    assert message.startswith("the Windows base build failed (exit 1): Windows Setup stalled twice: no disk writes")
    assert f"in {work / 'install.log'};" in message and "qemu.log" in message and "shots/" in message
    assert f"{work} holds " in message and "deleting it is safe" in message
    log = (work / "install.log").read_text(encoding="utf-8")
    assert "install2 20: qemu cpu 200%" in log and "Windows Setup stalled twice" in log
    assert "install2 20: qemu cpu 200%" in capsys.readouterr().out


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().split(") ", 1)[1].startswith("Z"))


@pytest.mark.skipif(os.name != "posix", reason="a kill of fmb is a POSIX signal")
def test_a_kill_of_setup_stops_the_whole_base_build_and_says_what_is_left(tmp_path):
    work, started = tmp_path / "base-build", tmp_path / "qemu.pid"
    qemu = ("import pathlib, subprocess, sys, time; pid = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)']).pid; part = pathlib.Path(sys.argv[1] + '.part'); "
            "part.write_text(str(pid)); part.replace(sys.argv[1]); time.sleep(60)")
    before, done = signal.getsignal(signal.SIGTERM), threading.Event()

    def kill_when_qemu_runs():
        while not done.wait(0.05):
            if started.exists() and signal.getsignal(signal.SIGTERM) != before:
                os.kill(os.getpid(), signal.SIGTERM)
                return

    threading.Thread(target=kill_when_qemu_runs, daemon=True).start()
    try:
        with pytest.raises(KeyboardInterrupt, match=r"the base build was stopped \(SIGTERM\) and its processes "
                                                    f"ended\\. {re.escape(str(work))} holds"):
            setup.build([sys.executable, "-c", qemu, started], work)
    finally:
        done.set()
    pid = int(started.read_text())
    deadline = time.monotonic() + 20
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not alive(pid)
    assert signal.getsignal(signal.SIGTERM) == before


def test_the_base_build_needs_room_for_its_disk_and_the_compressed_base(tmp_path, monkeypatch):
    work = tmp_path / "cache" / "base-build"
    work.mkdir(parents=True)
    monkeypatch.setenv("FMB_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("FMB_QEMU_BASE_HOME", raising=False)
    free = {work: 30.0}
    monkeypatch.setattr(host, "free_gib", lambda path: free[path])
    monkeypatch.setattr(host, "allocated_gib", lambda path: 0.0)
    with pytest.raises(SystemExit, match=f"needs about 40 GiB free at {re.escape(str(work))}, and it has 30 GiB"):
        setup.room(work)
    monkeypatch.setattr(host, "allocated_gib", lambda path: 8.0)  # an earlier build's disk, which this one replaces
    with pytest.raises(SystemExit, match="it has 30 GiB plus 8 GiB that an earlier build left there"):
        setup.room(work)
    monkeypatch.setattr(host, "allocated_gib", lambda path: 24.0)
    setup.room(work)
    elsewhere = tmp_path / "bases"
    monkeypatch.setenv("FMB_QEMU_BASE_HOME", str(elsewhere))
    free[elsewhere] = 5.0
    with pytest.raises(SystemExit, match=f"moves to {re.escape(str(elsewhere))} once built, and it has 5 GiB free"):
        setup.room(work)


def load_builder(monkeypatch):
    builder = Path(__file__).resolve().parents[2] / "tools" / "base-image" / "windows11-x64"
    for name in ("psutil", "pycdlib", "winrm"):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    console = ModuleType("guest_console")
    console.diagnose = console.wsman_status = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "guest_console", console)
    monkeypatch.syspath_prepend(str(builder))
    spec = importlib.util.spec_from_file_location("fmb_base_install_robustness", builder / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("stall_seconds", [600, None])
def test_a_base_install_paused_on_a_full_host_disk_says_the_disk_is_full(tmp_path, monkeypatch, stall_seconds):
    install = load_builder(monkeypatch)
    (tmp_path / "serial.log").write_bytes(b"")
    clock = [1000.0]
    status = ["VM status: paused (io-error)\r\n(qemu) "]
    monkeypatch.setattr(install, "ready", lambda port: None)
    monkeypatch.setattr(install, "disk_writes", lambda port: 20_971_520_000)
    monkeypatch.setattr(install, "monitor", lambda port, command: None)
    monkeypatch.setattr(install, "monitor_query", lambda port, command: status[0] if command == "info status" else "")
    monkeypatch.setattr(install.psutil, "Process", lambda pid: SimpleNamespace(cpu_percent=lambda: 0.0), raising=False)
    monkeypatch.setattr(install.psutil, "Error", Exception, raising=False)
    monkeypatch.setattr(install, "time", SimpleNamespace(
        monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))
    monkeypatch.setattr(install, "log", lambda message: None)
    vm = SimpleNamespace(pid=1, poll=lambda: None)
    install.GUEST_SPOKE[0], install.SERIAL_SEEN[0] = False, 0
    deadline = clock[0] + 75 * 60

    def wait():
        install.wait_ready(vm, tmp_path, 5985, 4444, deadline, "install1", stall_seconds=stall_seconds)

    with pytest.raises(SystemExit, match=f"the host disk under {re.escape(str(tmp_path))} is full"):
        wait()
    clock[0], status[0] = 1000.0, "VM status: running\r\n(qemu) "
    with pytest.raises(install.Stalled if stall_seconds else SystemExit,
                       match="no disk writes for 10 minutes" if stall_seconds else r"no WinRM \(install1\)"):
        wait()


WSL_LIST = ("  NAME              STATE           VERSION\r\n"
            "* Ubuntu-24.04      Stopped         1\r\n"
            "  docker-desktop    Running         2\r\n"
            "  Ubuntu-22.04      Stopped         2\r\n")


def windows_rows(monkeypatch, tmp_path, listing: bytes):
    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    monkeypatch.setattr(host.platform, "system", lambda: "Windows")
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0)
    monkeypatch.setattr(host, "leftovers", lambda: [])
    monkeypatch.setattr(host, "which", lambda name: None)
    monkeypatch.setattr(host, "long_paths", lambda: True)
    monkeypatch.setattr(host.subprocess, "run", lambda command, **kwargs: SimpleNamespace(
        stdout=listing if command[:3] == ["wsl.exe", "--list", "--verbose"] else b"", returncode=0))
    return {name: (ok, detail) for name, ok, detail in host.checks() if "WSL" in name}


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-8"])
def test_setup_check_reads_wsl_in_either_encoding_and_requires_wsl_1(tmp_path, monkeypatch, encoding):
    monkeypatch.delenv("FMB_WSL_DISTRO", raising=False)
    rows = windows_rows(monkeypatch, tmp_path, WSL_LIST.encode(encoding))
    assert rows == {"WSL distribution Ubuntu-24.04": (True, "found"),
                    "WSL 1 for Ubuntu-24.04 (Ansible there reaches the guest at Windows' 127.0.0.1)": (True, "found")}
    monkeypatch.setenv("FMB_WSL_DISTRO", "Ubuntu-22.04")
    rows = windows_rows(monkeypatch, tmp_path, WSL_LIST.encode(encoding))
    assert rows["WSL 1 for Ubuntu-22.04 (Ansible there reaches the guest at Windows' 127.0.0.1)"] == (
        False, "wsl --set-version Ubuntu-22.04 1 (it runs under WSL 2)")
    monkeypatch.setenv("FMB_WSL_DISTRO", "Debian")
    assert windows_rows(monkeypatch, tmp_path, WSL_LIST.encode(encoding)) == {
        "WSL distribution Debian": (False, "wsl --install -d Debian --no-launch; wsl --set-version Debian 1")}


def test_a_failed_collection_install_leaves_no_empty_collections_folder_for_fmbs_ansible(tmp_path, monkeypatch):
    from fmb.generation.backends import ansible_settings

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(host, "WINDOWS", False)
    answers = []

    def run(command, env=None, **_):
        command = [str(part) for part in command]
        if command[:3] == ["uv", "tool", "install"]:
            return
        # As ansible-galaxy does: it creates its -p folder before it downloads anything.
        installed = Path(command[command.index("-p") + 1]) / "ansible_collections"
        installed.mkdir(parents=True, exist_ok=True)
        if not answers:
            raise subprocess.CalledProcessError(1, command, "ERROR! Unknown error when attempting to call Galaxy")
        (installed / "ansible" / "windows").mkdir(parents=True)

    monkeypatch.setattr(setup, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        setup.ansible()
    monkeypatch.setenv("FMB_ANSIBLE_COLLECTIONS", str(host.ansible_home() / "collections"))
    assert not (host.ansible_home() / "collections").exists()
    assert "ANSIBLE_COLLECTIONS_PATH" not in ansible_settings()
    answers.append("Galaxy answers")
    setup.ansible()
    assert (host.ansible_home() / "collections" / "ansible_collections" / "ansible" / "windows").is_dir()
    assert ansible_settings()["ANSIBLE_COLLECTIONS_PATH"] == str(host.ansible_home() / "collections")


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="nohup ignores SIGHUP, a POSIX signal")
def test_a_base_build_started_under_nohup_outlives_a_closed_terminal(tmp_path):
    before = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        with setup.interruptible():
            assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
            os.kill(os.getpid(), signal.SIGHUP)
            assert signal.getsignal(signal.SIGTERM) is not signal.SIG_IGN
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, before)
