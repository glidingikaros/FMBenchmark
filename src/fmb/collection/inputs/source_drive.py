from __future__ import annotations

import re
from typing import Any


WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:(?:[\\/])?$")
WINDOWS_BOOT_DRIVE = "C:"


def normalize_source_drive(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not WINDOWS_DRIVE_PATTERN.fullmatch(text):
        return None
    return text[:2].upper()


def is_non_boot_source_drive(source_drive: Any) -> bool:
    drive = normalize_source_drive(source_drive)
    return drive is not None and drive != WINDOWS_BOOT_DRIVE


IMAGE_FILE_MOUNT_MODES = frozenset({"host_sleuthkit_read_only"})


def has_explicit_non_boot_source_drive(
    source_drive: Any,
    source_drive_not_boot_drive: Any,
    *,
    mount_mode: Any = None,
) -> bool:
    if mount_mode in IMAGE_FILE_MOUNT_MODES:
        return normalize_source_drive(source_drive) is not None and source_drive_not_boot_drive is True
    return (
        is_non_boot_source_drive(source_drive)
        and source_drive_not_boot_drive is True
    )
