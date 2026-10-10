from __future__ import annotations

from fmb.index.support.windows_artifacts import parse_int, row_first

NTFS_FILE_REFERENCE_ENTRY_MASK = (1 << 48) - 1


REMOTE_PATH_VOLUME = "<remote>"


DEFAULT_SYSTEM_VOLUME = "c"


def split_ntfs_file_reference(value: int | None) -> tuple[int, int] | None:
    if value is None or isinstance(value, bool) or not 0 <= value < (1 << 64):
        return None
    return int(value) & NTFS_FILE_REFERENCE_ENTRY_MASK, int(value) >> 48


def ntfs_reference_from_row(
    row: dict[str, str],
    *,
    entry_keys: tuple[str, ...],
    sequence_keys: tuple[str, ...],
) -> tuple[int, int] | None:
    entry = parse_int(row_first(row, *entry_keys))
    sequence = parse_int(row_first(row, *sequence_keys))
    if entry is None or sequence is None:
        return None
    if not (0 <= entry <= NTFS_FILE_REFERENCE_ENTRY_MASK and 0 <= sequence <= 0xFFFF):
        return None
    return entry, sequence


def ntfs_reference_fields(
    *,
    file_reference: tuple[int, int] | None,
    parent_reference: tuple[int, int] | None,
) -> dict[str, int | None]:
    return {
        "file_reference_entry": file_reference[0] if file_reference else None,
        "file_reference_sequence": file_reference[1] if file_reference else None,
        "parent_reference_entry": parent_reference[0] if parent_reference else None,
        "parent_reference_sequence": parent_reference[1] if parent_reference else None,
    }


def normalize_windows_compare_path(value: str | None) -> str:
    return windows_compare_path_parts(value)[1]


def windows_compare_path_parts(value: str | None) -> tuple[str | None, str]:
    raw = str(value or "").strip().replace("/", "\\")
    if raw.startswith(".\\"):
        raw = raw[2:]
    remote = raw.startswith("\\\\") and not raw.casefold().startswith(
        ("\\\\?\\", "\\\\.\\")
    )
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if raw.casefold().startswith(prefix.casefold()):
            raw = raw[len(prefix) :]
            break
    raw = raw.lstrip("\\")
    volume: str | None = None
    head, separator, tail = raw.partition("\\")
    if separator and head.casefold().startswith("volume{"):
        volume = head.casefold()
        raw = tail
    if len(raw) >= 2 and raw[1] == ":":
        volume = raw[0].casefold()
        raw = raw[2:].lstrip("\\")
    if remote:
        volume = REMOTE_PATH_VOLUME
    return volume, raw.strip("\\").casefold()


def volume_is_comparable(subject_volume: str | None, indexed_volumes: set[str]) -> bool:
    if subject_volume is None:
        return True
    if subject_volume == REMOTE_PATH_VOLUME:
        return False
    if subject_volume.startswith("volume{"):
        return subject_volume in indexed_volumes
    if indexed_volumes:
        return subject_volume in indexed_volumes
    return subject_volume == DEFAULT_SYSTEM_VOLUME


def is_absolute_local_windows_path(value: str | None) -> bool:
    path = str(value or "").strip().replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if path.casefold().startswith(prefix.casefold()):
            return False
    return bool(
        len(path) >= 3
        and path[0].casefold() in "abcdefghijklmnopqrstuvwxyz"
        and path[1:3] == ":\\"
    )
