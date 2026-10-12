"""Keeps the computer awake while fmb generates or runs, and notices when it slept anyway (a closed lid)."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import time
from contextlib import contextmanager

from fmb.replication import host, terminal

ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
# Time the host spent asleep, or its clock was set by, beyond which a failed generation says so.
SLEPT_SECONDS = 10


def _hold():
    """Takes this system's sleep assertion and returns what releases it; without one, fmb runs as before."""
    try:
        if host.WINDOWS:
            kernel = ctypes.windll.kernel32
            if kernel.SetThreadExecutionState(ctypes.c_uint32(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)):
                return lambda: kernel.SetThreadExecutionState(ctypes.c_uint32(ES_CONTINUOUS))
            return lambda: None
        if host.MACOS:
            command = ["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())]
        elif inhibit := shutil.which("systemd-inhibit"):
            # cat holds the lock until fmb closes its input, or exits, whichever comes first.
            command = [inhibit, "--what=sleep:idle", "--who=fmb", "--why=generating or analysing a disk image",
                       "--mode=block", "cat"]
        else:
            return lambda: None
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
    except Exception:
        return lambda: None
    return lambda: _release(process)


def _release(process: subprocess.Popen) -> None:
    try:
        process.stdin.close()
        process.terminate()
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass


@contextmanager
def kept_awake():
    """Holds a sleep assertion for the whole of fmb generate or fmb run; closing a laptop's lid still sleeps it."""
    release = _hold()
    try:
        yield
    finally:
        release()


def _clocks() -> tuple[float, float]:
    """A clock that counts time asleep and one that does not, in seconds."""
    if host.WINDOWS:
        kernel, unbiased = ctypes.windll.kernel32, ctypes.c_ulonglong()
        kernel.GetTickCount64.restype = ctypes.c_ulonglong
        kernel.QueryUnbiasedInterruptTime(ctypes.byref(unbiased))
        return kernel.GetTickCount64() / 1000, unbiased.value / 10**7
    return time.time(), time.monotonic()


def asleep() -> float:
    """How far the two clocks have drifted apart; the change between two readings is the time asleep."""
    try:
        counting, not_counting = _clocks()
    except Exception:
        return 0.0
    return counting - not_counting


def slept(since: float) -> str:
    """A note for a failed generation when the host slept after asleep() returned since; empty otherwise."""
    gap = abs(asleep() - since)
    if gap < SLEPT_SECONDS:
        return ""
    return (f". The computer slept, or its clock was set, for about {terminal.duration(gap)} during the generation, "
            "which needs the guest's clock within 2 s of the host's: keep the computer awake, on power and with its "
            "lid open while fmb generates")
