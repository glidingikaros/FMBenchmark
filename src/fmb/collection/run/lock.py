from __future__ import annotations

import errno
import json
import os
import socket
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.core.paths import RUNS_DIR_NAME
from fmb.core.provenance import record_timestamp


LOCK_SCHEMA_VERSION = "fmb_evidence_image_run_lock.v1"
LOCK_KIND = "evidence_image_run"
# Windows locks a byte past the owner record, so that other runs can still read who holds the lock.
_WINDOWS_LOCK_OFFSET = 1 << 20


class EvidenceImageRunGuardError(RuntimeError):
    pass


class ActiveEvidenceImageRunError(EvidenceImageRunGuardError):

    def __init__(self, lock_path: Path, payload: dict[str, Any], reason: str) -> None:
        self.lock_path = lock_path
        self.payload = payload
        self.reason = reason
        run_id = payload.get("run_id") or payload.get("requested_run_id") or "unknown"
        output_root = payload.get("output_root") or payload.get("current_root") or "unknown output root"
        pid = payload.get("pid") or "unknown pid"
        host = payload.get("host") or "unknown host"
        super().__init__(
            "evidence-image run already active: "
            f"{run_id} at {output_root} "
            f"(pid {pid} on {host}; lock {lock_path}; {reason})"
        )


@dataclass
class EvidenceImageRunGuard:
    lock_path: Path
    token: str
    payload: dict[str, Any]
    fd: int = -1

    def release(self) -> None:
        # The operating system also drops the lock when the process dies, so a crash leaves no stale lock.
        if self.fd < 0:
            return
        fd, self.fd = self.fd, -1
        try:
            with suppress(OSError):
                os.ftruncate(fd, 0)
                _unlock(fd)
        finally:
            os.close(fd)


def evidence_image_run_lock_path(current_root: Path) -> Path:
    return current_root / RUNS_DIR_NAME / ".locks" / "evidence-image-run.lock"


def current_host() -> str:
    return socket.gethostname()


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_process_is_running(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _windows_process_is_running(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 5
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == 259
    finally:
        kernel32.CloseHandle(handle)


def read_lock_payload(lock_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _try_lock(fd: int) -> bool:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in {errno.EACCES, getattr(errno, "EDEADLOCK", errno.EDEADLK)}:
                return False
            raise
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def build_run_guard_payload(
    *,
    current_root: Path,
    requested_run_id: str,
    command: Sequence[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": LOCK_SCHEMA_VERSION,
        "kind": LOCK_KIND,
        "token": uuid.uuid4().hex,
        "owner": "cli",
        "pid": os.getpid(),
        "host": current_host(),
        "started_at": record_timestamp(),
        "current_root": str(current_root),
        "requested_run_id": requested_run_id,
        "command": list(command) if command else None,
    }


def _create_run_guard(lock_path: Path, payload: dict[str, Any]) -> EvidenceImageRunGuard:
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    try:
        if not _try_lock(fd):
            raise ActiveEvidenceImageRunError(lock_path, read_lock_payload(lock_path), "its process is still running")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    except BaseException:
        os.close(fd)
        raise
    return EvidenceImageRunGuard(lock_path=lock_path, token=str(payload["token"]), payload=payload, fd=fd)


@contextmanager
def acquire_evidence_image_run_lock(
    *,
    current_root: Path,
    requested_run_id: str,
    command: Sequence[str] | None = None,
) -> Iterator[EvidenceImageRunGuard]:
    lock_path = evidence_image_run_lock_path(current_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock = _create_run_guard(lock_path, build_run_guard_payload(
        current_root=current_root,
        requested_run_id=requested_run_id,
        command=command,
    ))
    try:
        yield lock
    finally:
        lock.release()
