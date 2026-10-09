from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def _reject_non_standard_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def loads_json_text(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_non_standard_json_constant)


def json_text(payload: Any, *, sort_keys: bool = False) -> str:
    return json.dumps(payload, allow_nan=False, indent=2, sort_keys=sort_keys) + "\n"


def load_json(path: Path) -> Any:
    return loads_json_text(path.read_text(encoding="utf-8-sig"))


def load_json_object(
    path: Path,
    *,
    label: str = "JSON payload",
    error_type: type[Exception] = ValueError,
) -> dict[str, Any]:
    payload = _load_json_for_object(path, label=label, error_type=error_type)
    return _require_json_object(payload, path=path, label=label, error_type=error_type)


def _load_json_for_object(
    path: Path,
    *,
    label: str,
    error_type: type[Exception],
) -> Any:
    try:
        return load_json(path)
    except json.JSONDecodeError as error:
        location = f"line {error.lineno}, column {error.colno}"
        message = f"{label} is not valid JSON at {location}: {error.msg}: {path}"
        raise error_type(message) from error
    except ValueError as error:
        raise error_type(f"{label} is not valid JSON: {error}: {path}") from error
    except OSError as error:
        raise error_type(f"cannot read {label}: {path}: {error}") from error


def _require_json_object(
    payload: Any,
    *,
    path: Path,
    label: str,
    error_type: type[Exception],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise error_type(f"{label} must be a JSON object: {path}")
    return payload


def write_json(path: Path, payload: Any, *, sort_keys: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json_text(payload, sort_keys=sort_keys))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
