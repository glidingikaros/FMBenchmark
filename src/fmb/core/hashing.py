from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fmb.core.json_io import json_text

DEFAULT_FILE_CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_FILE_CHUNK_SIZE) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(document: Any) -> bytes:
    return json_text(document, sort_keys=True).encode("utf-8")


def sha256_json(document: Any) -> str:
    return sha256_bytes(canonical_json_bytes(document))


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
