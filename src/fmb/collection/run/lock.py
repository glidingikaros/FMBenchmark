from __future__ import annotations

import json
import os
import socket
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.core.paths import RUNS_DIR_NAME
from fmb.core.provenance import record_timestamp


LOCK_SCHEMA_VERSION = "fmb_evidence_image_run_lock.v1"
LOCK_KIND = "evidence_image_run"
ACCEPTED_LOCK_SCHEMA_VERSIONS = frozenset({LOCK_SCHEMA_VERSION})
ACCEPTED_LOCK_KINDS = frozenset({LOCK_KIND})


class EvidenceImageRunGuardError(RuntimeError):
    pass


class ActiveEvidenceImageRunError(EvidenceImageRunGuardError):

    def __init__(self, lock_path: Path, payload: dict[str, Any], reason: str) -> None:
        self.lock_path = lock_path
        self.payload = payload
        self.reason = reason
        run_id = payload.get("run_id") or payload.get("requested_run_id") or "unknown"
        output_root = payload.get("output_root") or "unknown output root"
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

    def release(self) -> None:
        try:
            payload = read_lock_payload(self.lock_path)
        except EvidenceImageRunGuardError:
            return
        if payload.get("token") != self.token:
            return
        try:
            self.lock_path.unlink()
        except FileNotFoundError:
            pass


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
    except FileNotFoundError as error:
        raise EvidenceImageRunGuardError(
            f"evidence-image run lock disappeared: {lock_path}"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise ActiveEvidenceImageRunError(
            lock_path, {}, f"could not read lock metadata: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise ActiveEvidenceImageRunError(lock_path, {}, "lock metadata is not an object")
    return payload


def can_reclaim_run_lock(payload: dict[str, Any]) -> tuple[bool, str]:
    if payload.get("schema_version") not in ACCEPTED_LOCK_SCHEMA_VERSIONS:
        return False, "lock schema is unknown"
    if payload.get("kind") not in ACCEPTED_LOCK_KINDS:
        return False, "lock kind is unknown"
    if payload.get("owner") != "cli":
        return False, "lock owner is unknown"
    host = str(payload.get("host") or "")
    if host and host != current_host():
        return False, f"lock belongs to another host: {host}"
    pid_value = payload.get("pid")
    try:
        pid = int(pid_value)
    except (TypeError, ValueError):
        return True, "lock has no valid owner pid"
    if process_is_running(pid):
        return False, "owner process is still running"
    return True, "owner process is no longer running"


def same_lock_owner(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left.get(key) == right.get(key)
        for key in ("token", "pid", "host", "started_at")
    )


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
    fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return EvidenceImageRunGuard(
        lock_path=lock_path,
        token=str(payload["token"]),
        payload=payload,
    )


def _reclaim_run_lock_if_still_owned(
    lock_path: Path, existing: dict[str, Any]
) -> None:
    current = read_lock_payload(lock_path)
    if not same_lock_owner(existing, current):
        return
    lock_path.unlink()


@contextmanager
def acquire_evidence_image_run_lock(
    *,
    current_root: Path,
    requested_run_id: str,
    command: Sequence[str] | None = None,
) -> Iterator[EvidenceImageRunGuard]:
    lock_path = evidence_image_run_lock_path(current_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_run_guard_payload(
        current_root=current_root,
        requested_run_id=requested_run_id,
        command=command,
    )

    while True:
        try:
            lock = _create_run_guard(lock_path, payload)
        except FileExistsError:
            existing = read_lock_payload(lock_path)
            reclaimable, reason = can_reclaim_run_lock(existing)
            if not reclaimable:
                raise ActiveEvidenceImageRunError(lock_path, existing, reason)
            try:
                _reclaim_run_lock_if_still_owned(lock_path, existing)
            except FileNotFoundError:
                pass
            continue
        try:
            yield lock
        finally:
            lock.release()
        return
