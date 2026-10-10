from __future__ import annotations

from copy import deepcopy

_REGISTERED: dict[str, dict] = {}


def register(sha256: str, contract: dict) -> None:
    _REGISTERED[sha256] = deepcopy(contract)


def registered(sha256: str) -> dict | None:
    contract = _REGISTERED.get(sha256)
    return None if contract is None else deepcopy(contract)


def registered_hashes() -> frozenset[str]:
    return frozenset(_REGISTERED)
