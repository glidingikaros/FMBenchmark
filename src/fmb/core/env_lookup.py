from __future__ import annotations

import os
from collections.abc import Iterable, Mapping


def unique_env_names(names: Iterable[str]) -> tuple[str, ...]:
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return tuple(unique)


def read_env_value(
    *names: str,
    environ: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    env = os.environ if environ is None else environ
    for name in unique_env_names(names):
        value = env.get(name, "").strip()
        if value:
            return value, name
    return None, None
