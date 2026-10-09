from __future__ import annotations

from datetime import datetime, timedelta, timezone


NTFS_EPOCH_UTC = datetime(1601, 1, 1, tzinfo=timezone.utc)
FILETIME_TICKS_PER_MICROSECOND = 10


def _datetime_from_filetime(filetime: int) -> datetime:
    return NTFS_EPOCH_UTC + timedelta(
        microseconds=filetime // FILETIME_TICKS_PER_MICROSECOND
    )


def filetime_to_utc_iso(filetime: int) -> str | None:
    if filetime <= 0:
        return None
    _, remaining_ticks = divmod(filetime, FILETIME_TICKS_PER_MICROSECOND)
    try:
        utc = _datetime_from_filetime(filetime)
    except OverflowError:
        return None
    fraction_ticks = utc.microsecond * FILETIME_TICKS_PER_MICROSECOND + remaining_ticks
    fraction = f".{fraction_ticks:07d}".rstrip("0") if fraction_ticks else ""
    return f"{utc:%Y-%m-%dT%H:%M:%S}{fraction}Z"
