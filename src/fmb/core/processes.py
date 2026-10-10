from __future__ import annotations

import os
import shlex
from math import isfinite

from fmb.core.env_lookup import read_env_value


DEFAULT_PROCESS_TIMEOUT_SECONDS = 3600


def command_line_text(argv: list[str]) -> str:
    return shlex.join([str(item) for item in argv])


def timeout_seconds_from_env(
    name: str,
    default: int = DEFAULT_PROCESS_TIMEOUT_SECONDS,
) -> float:
    default_timeout = float(default)
    if not isfinite(default_timeout) or default_timeout <= 0:
        raise ValueError(f"{name} default timeout must be a positive finite number")
    value, _source = read_env_value(name, environ=os.environ)
    if not value:
        return default_timeout
    try:
        timeout = float(value)
    except ValueError:
        raise ValueError(
            f"{name} must be a positive finite number: {value!r}"
        ) from None
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError(f"{name} must be a positive finite number: {value!r}")
    return timeout


def decoded_process_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def process_output_excerpt(
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    *,
    limit: int = 500,
) -> str:
    if limit <= 0:
        raise ValueError("process output excerpt limit must be positive")
    text = "\n".join(
        part
        for part in (decoded_process_output(stdout), decoded_process_output(stderr))
        if part
    ).strip()
    if not text:
        return ""
    return text[:limit].rstrip() + "..." if len(text) > limit else text
