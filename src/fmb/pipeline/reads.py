from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import sys

from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import contained_path, read_json

_READS = ContextVar("pipeline_stage_reads", default=None)


def _is_read(event: str, args: tuple) -> bool:
    if event != "open":
        return True
    mode = args[1] if len(args) > 1 else None
    if isinstance(mode, str):
        return "r" in mode or "+" in mode
    flags = args[2] if len(args) > 2 else 0
    return not (isinstance(flags, int) and flags & os.O_WRONLY)


def _audit(event, args):
    reads = _READS.get()
    if (reads is None or event not in {"open", "os.listdir", "os.scandir"} or not args
            or not isinstance(args[0], (str, bytes, os.PathLike))):
        return
    if _is_read(event, args):
        reads.add(os.path.abspath(os.fsdecode(args[0])))


sys.addaudithook(_audit)


@contextmanager
def measured():
    reads: set[str] = set()
    token = _READS.set(reads)
    try:
        yield reads
    finally:
        _READS.reset(token)


CLASSIFY_ORDER = ("analysis", "generation", "run")


def by_root(reads: set[str], roots: dict[str, Path]) -> dict[str, list[str]]:
    forms = {name: {Path(roots[name]).absolute(), Path(roots[name]).resolve()} for name in CLASSIFY_ORDER if name in roots}
    result: dict[str, set[str]] = {name: set() for name in forms}
    for path in map(Path, reads):
        for actual in {path, path.resolve()}:
            for name, candidates in forms.items():
                root = next((c for c in candidates if actual == c or actual.is_relative_to(c)), None)
                if root is not None:
                    result[name].add(actual.relative_to(root).as_posix())
                    break
    return {name: sorted(paths) for name, paths in result.items()}


MAY_READ = {
    "S1": {},
    "S2": {"generation": [""], "analysis": [""], "run": ["preparation/", "analysis/"]},
    "check:presentation": {"run": ["preparation/"]},
    "check:sources": {"generation": [""], "analysis": [""], "run": ["preparation/prepared/"]},
    "S3": {"run": ["preparation/cards/", "assessment/"]},
    "S3':freeze": {"run": ["preparation/cards/", "conditions/"]},
    "S4:admission": {"generation": [""], "run": [""]},
    "S3':dispatch": {"run": ["preparation/cards/", "conditions/"]},
    "S3':publish": {"run": ["conditions/"]},
    "S4:evaluation": {"run": [""]},
}


def _entitled(path: str, prefixes: list[str]) -> bool:
    folder = path.rstrip("/") + "/"
    return path == "." or any(folder.startswith(p) or p.startswith(folder) for p in prefixes)


def undeclared(stage: str, read: dict[str, list[str]]) -> list[str]:
    allowed = MAY_READ[stage]
    bad = []
    for root, paths in read.items():
        for path in paths:
            if root == "run" and stage in {"S1", "S2", "S3", "S4:evaluation"} and (
                    path in {"mock-calls", "mock-calls/" + stage.split(":")[0]}
                    or path.startswith("mock-calls/" + stage.split(":")[0] + "/")):
                continue
            if stage == "check:sources" and root == "run" and path == "analysis-truth-guard.json":
                continue
            if stage == "S2" and root == "run" and any(path == name or (
                    path.startswith("." + name + ".") and path.endswith(".tmp") and "/" not in path)
                    for name in ("analysis-truth-guard.json", "analysis-timing.json")):
                continue
            parts = Path(path).parts
            reference = (root == "run" and stage.startswith("S3'") and len(parts) > 2
                         and parts[0] == "conditions" and (
                             parts[2] in {"references.json", "truth-seal.json"} or
                             (parts[2] == "admission" and (stage != "S3':dispatch" or
                              len(parts) > 3 and parts[3:] not in {
                                  ("admission.json",), ("admission-seal.json",)}))))
            if reference or (path != "." and (root not in allowed or not _entitled(path, allowed[root]))):
                bad.append(f"{root}:{path}")
    return bad


def read_record(run: Path, stage: dict) -> dict:
    reference = stage.get("reads_record")
    if reference is None:
        raise ValueError("a step has no record of what it read: " + stage["stage"])
    path = contained_path(run, reference["path"])
    if sha256_file(path) != reference["sha256"]:
        raise ValueError("a step's record of what it read changed: " + reference["path"])
    record = read_json(path)
    expected = stage.get("step", stage["stage"])
    if "step" not in stage:
        detail = stage.get("detail", {})
        if expected == "check":
            expected += ":" + detail.get("check", "")
        elif expected == "S3'":
            expected += ":dispatch" if "dispatched" in detail else ":freeze"
        elif expected == "S4":
            expected += ":admission" if "admission" in detail else ":evaluation"
    if record.get("step") != expected or expected not in MAY_READ or expected.split(":")[0] != stage["stage"]:
        raise ValueError("read record does not belong to its phase: " + expected)
    counts = {root: len(paths) for root, paths in record["read"].items()}
    if "opened" in stage and stage["opened"] != counts:
        raise ValueError("read counts differ from their phase: " + expected)
    return record
