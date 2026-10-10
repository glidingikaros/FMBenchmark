import importlib.util
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools" / "base-image" / "windows11-x64"


def load_builder(monkeypatch):
    for name in ("psutil", "pycdlib", "winrm"):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    console = ModuleType("guest_console")
    console.diagnose = console.wsman_status = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "guest_console", console)
    monkeypatch.syspath_prepend(str(BUILDER))
    spec = importlib.util.spec_from_file_location("fmb_base_install", BUILDER / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_relaunch_after_a_guest_restart_starts_the_guest_clock_from_now(monkeypatch, tmp_path):
    install = load_builder(monkeypatch)
    launched = []

    class Process(SimpleNamespace):
        def poll(self):
            return 0

    def popen(command, **kwargs):
        launched.append(list(command))
        return Process()

    clock = [datetime(2026, 10, 10, 7, 34, 58, tzinfo=install.GUEST_ZONE)]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]

    monkeypatch.setattr(install.subprocess, "Popen", popen)
    monkeypatch.setattr(install, "datetime", Clock)
    monkeypatch.setattr(install, "log", lambda message: None)
    machine = install.Machine(["qemu", "-rtc", "base=2026-10-10T07:34:58", "-no-reboot"], tmp_path, True)
    clock[0] = datetime(2026, 10, 10, 7, 44, 4, tzinfo=install.GUEST_ZONE)
    assert machine.relaunched_after_guest_restart()
    clock[0] = datetime(2026, 10, 10, 7, 58, 14, tzinfo=install.GUEST_ZONE)
    assert machine.relaunched_after_guest_restart()
    assert [command[2] for command in launched] == [
        "base=2026-10-10T07:34:58", "base=2026-10-10T07:44:04", "base=2026-10-10T07:58:14"]
