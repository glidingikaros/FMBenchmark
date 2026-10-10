from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import time

RECEIPT_NAME = "vmware-clone-receipt.json"
COPY_METHOD = "independent_apfs_clonefiles_no_fallback"
MAX_SOURCE_ENTRIES = 4096
MAX_SOURCE_DEPTH = 16
CLONE_TIMEOUT_SECONDS = 600


def source_entries(root):
    root = Path(root)
    pending = [(root, 0)]
    entries = []
    deadline = time.monotonic() + 30
    while pending:
        directory, depth = pending.pop()
        if depth > MAX_SOURCE_DEPTH or time.monotonic() >= deadline:
            raise ValueError("VMware source inventory exceeded its traversal budget")
        with os.scandir(directory) as scan:
            for entry in scan:
                if len(entries) >= MAX_SOURCE_ENTRIES or time.monotonic() >= deadline:
                    raise ValueError("VMware source inventory exceeded its traversal budget")
                path = Path(entry.path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError("VMware source closure contains a link or non-file")
                entries.append(path)
                if stat.S_ISDIR(mode):
                    pending.append((path, depth + 1))
    return sorted(entries)


def _digest(path, deadline):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            if time.monotonic() >= deadline:
                raise TimeoutError("APFS clone verification exceeded its deadline")
            digest.update(block)
    return digest.hexdigest()


def _member(root, raw):
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts or "\\" in raw:
        raise ValueError("VMware disk path escapes the independent clone")
    result = root / path
    if not result.resolve(strict=True).is_relative_to(root) or result.is_symlink():
        raise ValueError("VMware disk path escapes the independent clone")
    return result


def validate_disks(vmx):
    root = vmx.parent
    descriptors = []
    for line in vmx.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"')
        if key.strip().casefold().endswith(".filename") and value.casefold().endswith(".vmdk"):
            descriptors.append(_member(root, value))
    if not descriptors:
        raise ValueError("VMware clone has no disk descriptor")
    for descriptor in descriptors:
        text = descriptor.read_text(encoding="utf-8")
        parent = re.search(r'(?im)^\s*parentCID\s*=\s*"?([0-9a-f]+)"?\s*$', text)
        if (re.search(r"(?im)^\s*parentFileNameHint\s*=", text)
                or (parent and parent.group(1).casefold() != "ffffffff")
                or re.search(r"-\d{6}\.vmdk$", descriptor.name, re.IGNORECASE)):
            raise ValueError("VMware clone must have flat disks without backing parents")
        extents = re.findall(r'(?m)^\s*(?:RW|RDONLY|NOACCESS)\s+\d+\s+\S+\s+"([^"]+)"', text)
        if not extents:
            raise ValueError("VMware disk descriptor has no file extent")
        for raw in extents:
            extent = _member(descriptor.parent, raw)
            if not extent.is_file() or not extent.resolve().is_relative_to(root):
                raise ValueError("VMware disk extent escapes the independent clone")
    for path in root.glob("*.vmsd"):
        text = path.read_text(encoding="utf-8")
        count = re.search(r'(?im)^\s*snapshot\.numSnapshots\s*=\s*"?(\d+)', text)
        if (count and int(count.group(1))) or (not count and re.search(r"(?im)^\s*snapshot\d+\.", text)):
            raise ValueError("VMware clone source contains snapshots")


def clone_files(source_vmx, destination_vmx):
    if sys.platform != "darwin":
        raise ValueError("APFS generation cloning requires macOS")
    source_vmx = Path(source_vmx)
    if source_vmx.is_symlink():
        raise ValueError("VMware source VMX must not be a symbolic link")
    source_vmx = source_vmx.resolve(strict=True)
    destination_vmx = Path(destination_vmx)
    source, destination = source_vmx.parent, destination_vmx.parent
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("APFS clone destination already exists")
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("APFS clone destination overlaps its protected source")
    validate_disks(source_vmx)
    entries = source_entries(source)
    destination.mkdir(parents=True, exist_ok=False)
    if source.stat().st_dev != destination.stat().st_dev:
        raise ValueError("APFS source and generation VM must share a filesystem")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    library.clonefile.restype = ctypes.c_int
    started = time.monotonic()
    deadline = started + CLONE_TIMEOUT_SECONDS
    files = []
    for path in entries:
        if time.monotonic() >= deadline:
            raise TimeoutError("APFS clone verification exceeded its deadline")
        target = destination / path.relative_to(source)
        before = path.lstat()
        if stat.S_ISDIR(before.st_mode):
            target.mkdir(exist_ok=False)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("VMware source changed to a link or non-file")
        if library.clonefile(os.fsencode(path), os.fsencode(target), 0):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(target))
        copied = target.lstat()
        if not stat.S_ISREG(copied.st_mode) or (before.st_dev, before.st_ino) == (copied.st_dev, copied.st_ino):
            raise ValueError("APFS clone shares a writable file identity with its source")
        digest = _digest(target, deadline)
        if copied.st_size != before.st_size or digest != _digest(path, deadline):
            raise ValueError("APFS clone read-back hash mismatch")
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("VMware source changed during APFS clone verification")
        files.append({"path": path.relative_to(source).as_posix(), "sha256": digest,
                      "size_bytes": before.st_size})
    cloned_vmx = destination / source_vmx.name
    if cloned_vmx != destination_vmx:
        cloned_vmx.rename(destination_vmx)
    validate_disks(destination_vmx)
    text = destination_vmx.read_text(encoding="utf-8")
    keys = {"uuid.action": "create", "msg.autoanswer": "TRUE"}
    lines = [line for line in text.splitlines()
             if line.split("=", 1)[0].strip().casefold() not in keys]
    lines.extend(f'{key} = "{value}"' for key, value in keys.items())
    destination_vmx.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"schema_version": "generation_vmware_clone.v1", "copy_method": COPY_METHOD,
            "status": "verified", "source_vmx": str(source_vmx), "working_vmx": str(destination_vmx),
            "elapsed_seconds": round(time.monotonic() - started, 6), "files": files}


def validate_receipt(receipt, bundle):
    from fmb.generation import recipe as recipe_support

    frozen, lock = bundle["recipe"], bundle["lock"]
    source_vmx = recipe_support.base_vmx_path(lock)
    expected = recipe_support.base_file_rows(lock)
    if (not isinstance(receipt, dict)
            or receipt.get("schema_version") != "generation_vmware_clone.v1"
            or receipt.get("status") != "verified" or receipt.get("copy_method") != COPY_METHOD
            or receipt.get("recipe_id") != frozen["recipe_id"]
            or receipt.get("dependency_lock_sha256") != frozen["dependency_lock_sha256"]
            or receipt.get("source_vmx") != str(source_vmx)
            or receipt.get("files") != expected):
        raise ValueError("VMware clone receipt differs from the frozen source binding")
