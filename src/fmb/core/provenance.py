from __future__ import annotations

from datetime import datetime, timezone


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def record_timestamp() -> str:
    return _utc_now().replace(microsecond=0).isoformat()


__all__ = ["record_timestamp"]
