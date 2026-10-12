from __future__ import annotations

import json

PREFIX = "FMB_PROGRESS "


def emit(kind: str, **fields) -> None:
    """One progress record on stdout; `fmb` turns these into short terminal lines and keeps them in the log."""
    try:
        print(PREFIX + json.dumps({"kind": kind, **fields}, sort_keys=True), flush=True)
    except (OSError, ValueError):
        pass
