from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath


PORTABLE_PATH_FORBIDDEN_CHARS = frozenset('<>:"|?*')
WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


def is_portable_relative_path(value: str) -> bool:
    if not value or value.startswith("~") or "\\" in value:
        return False
    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        return False
    for part in posix_path.parts:
        if part in {"", ".", ".."}:
            return False
        if part.endswith((" ", ".")):
            return False
        if any(char in PORTABLE_PATH_FORBIDDEN_CHARS for char in part):
            return False
        if any(ord(char) < 32 or ord(char) == 127 for char in part):
            return False
        if part.split(".", maxsplit=1)[0].upper() in WINDOWS_RESERVED_BASENAMES:
            return False
    return True
