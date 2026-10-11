from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import time

from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import read_json, contained_path

_MODIFIED_PERMITTED = False
_DIGESTS: dict[Path, tuple[tuple, str]] = {}
_RACY_NS = 2_000_000_000


def permit_modified_sources() -> None:
    global _MODIFIED_PERMITTED
    _MODIFIED_PERMITTED = True


def source_roots():
    import fmb

    return {"package": Path(fmb.__file__).resolve().parent}


def source_files(roots=None):
    roots = roots or source_roots()
    files = {}
    deadline = time.monotonic() + 30
    excluded = {"__pycache__", ".vagrant", "outputs", "private", ".fmb", ".git"}

    def visit(start):
        # os.scandir reports symlinks from the directory listing, without one more system
        # call per entry, which is most of an inventory's cost on Windows.
        count = 0
        pending = [(start, ())]
        while pending:
            directory, relative = pending.pop()
            if (
                len(relative) > 20
                or time.monotonic() > deadline
            ):
                raise ValueError(
                    "paper source inventory exceeded its depth/time budget"
                )
            try:
                with os.scandir(directory) as listing:
                    entries = sorted(listing, key=lambda entry: entry.name)
            except OSError:
                continue
            if any(entry.is_symlink() for entry in entries):
                raise ValueError("symlinked implementation asset")
            directories = [entry for entry in entries if entry.is_dir() and entry.name not in excluded]
            for entry in entries:
                if entry.is_dir():
                    continue
                count += 1
                if count > 10000:
                    raise ValueError("paper source inventory exceeded its file budget")
                yield relative + (entry.name,), Path(entry.path)
            pending.extend((entry.path, relative + (entry.name,)) for entry in reversed(directories))

    package = roots["package"]
    for parts, path in visit(package):
        if parts[-1] == "paper-source-manifest.json":
            continue
        if parts[0] != "fixtures" and path.suffix not in {".pyc", ".pyo"}:
            files["package/" + "/".join(parts)] = path
    return dict(sorted(files.items()))


def _identity(path: Path) -> tuple:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def source_sha256(path: Path) -> str:
    # A digest is reused only while the file keeps its identity, size and timestamps. A file
    # changed within two seconds of being hashed is never remembered, so a rewrite that lands
    # in the same timestamp tick cannot reuse a stale digest.
    identity = _identity(path)
    cached = _DIGESTS.get(path)
    if cached is not None and cached[0] == identity:
        return cached[1]
    hashed_at = time.time_ns()
    digest = sha256_file(path)
    if hashed_at - identity[3] > _RACY_NS and _identity(path) == identity:
        _DIGESTS[path] = (identity, digest)
    return digest


def current_record(roots=None) -> dict:
    roots = roots or source_roots()
    sealed = read_json(roots["package"] / "paper-source-manifest.json")
    return {**sealed, "files": {name: source_sha256(path) for name, path in source_files(roots).items()}}


def record_bytes(record: dict) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()


def modified_files(roots=None) -> list[str]:
    roots = roots or source_roots()
    sealed = read_json(roots["package"] / "paper-source-manifest.json")["files"]
    current = current_record(roots)["files"]
    return sorted(name for name in sealed.keys() | current.keys() if sealed.get(name) != current.get(name))


def verify_sources(manifest_path: Path | None = None, *, roots=None) -> dict:
    roots = roots or source_roots()
    if _MODIFIED_PERMITTED and manifest_path is None and modified_files(roots):
        return current_record(roots)
    manifest_path = manifest_path or roots["package"] / "paper-source-manifest.json"
    record = read_json(manifest_path)
    if record.get("schema_version") != "paper_source_manifest.v1":
        raise ValueError("unsupported paper implementation manifest")
    actual = source_files(roots)
    if set(actual) != set(record["files"]):
        raise ValueError("paper source manifest membership changed")
    for name, digest in record["files"].items():
        prefix, relative = name.split("/", 1)
        path = contained_path(roots[prefix], relative)
        if path != actual[name] or source_sha256(path) != digest:
            raise ValueError("paper implementation changed: " + name)
    if roots == source_roots():
        import fmb.core.case_contract as contract
        import fmb.assessment.rules as rules

        if any(not Path(module.__file__).resolve().is_relative_to(roots["package"])
               for module in (contract, rules)):
            raise ValueError("rule implementation was imported from another root")
    return record


def source_manifest_sha256() -> str:
    roots = source_roots()
    if _MODIFIED_PERMITTED and modified_files(roots):
        return hashlib.sha256(record_bytes(current_record(roots))).hexdigest()
    manifest = roots["package"] / "paper-source-manifest.json"
    verify_sources(manifest, roots=roots)
    return sha256_file(manifest)


def snapshot_sources(output: Path) -> dict:
    verify_sources()
    records = {}
    for name, path in source_files().items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        records[name] = source_sha256(path)
    return records


