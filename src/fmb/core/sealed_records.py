from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from fmb.core.json_io import write_json


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key: " + key)
        result[key] = value
    return result


def parse_json(text: str):
    def reject(value):
        raise ValueError("non-JSON constant: " + value)

    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=reject)


def read_json(path: Path):
    return parse_json(Path(path).read_text(encoding="utf-8"))


def sha256_json(value) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def contained_path(root: Path, relative: str) -> Path:
    root = Path(root).resolve(strict=True)
    part = Path(relative)
    if (
        part.is_absolute()
        or not part.parts
        or any(p in {"..", "."} for p in part.parts)
    ):
        raise ValueError("invalid sealed relative path: " + relative)
    path = root / part
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("sealed path escapes its root: " + relative)
    return path


def seal_directory(directory: Path, filename: str = "preparation-seal.json") -> str:
    from fmb.core.hashing import sha256_file

    directory = Path(directory).resolve(strict=True)
    target = contained_path(directory, filename)
    if target.exists():
        raise FileExistsError("refusing to replace a seal: " + str(target))
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in sealed artifact: " + str(path))
        if path.is_file() and path != target:
            files[path.relative_to(directory).as_posix()] = sha256_file(path)
    if not files:
        raise ValueError("cannot seal an empty artifact")
    write_json(
        target,
        {"schema_version": "paper_file_seal.v1", "sealed_utc": now(), "files": files},
    )
    return sha256_file(target)


def verify_seal(
    directory: Path, filename: str = "preparation-seal.json", *, exact: bool = False
) -> dict:
    from fmb.core.hashing import sha256_file

    directory = Path(directory).resolve(strict=True)
    record = read_json(contained_path(directory, filename))
    if not isinstance(record.get("files"), dict) or not record["files"]:
        raise ValueError("empty or invalid seal")
    for name, digest in record["files"].items():
        path = contained_path(directory, name)
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError("sealed file changed or is missing: " + name)
    if exact:
        actual = {
            p.relative_to(directory).as_posix()
            for p in directory.rglob("*")
            if p.is_file() and p.name != filename
        }
        if actual != set(record["files"]):
            raise ValueError("sealed inventory membership changed")
    return record


