from __future__ import annotations

import ntpath
import os
import posixpath
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from fmb.core.sealed_records import read_json


def _normal(path: str | PurePath) -> PurePath:
    if isinstance(path, Path):
        return Path(os.path.normpath(path))
    text = os.fspath(path)
    if ntpath.splitdrive(text)[0]:
        return PureWindowsPath(ntpath.normpath(text))
    if text.startswith("/"):
        return PurePosixPath(posixpath.normpath(text))
    return Path(os.path.normpath(text))


def _recorded_outputs(index: Mapping[str, Any]) -> list[PurePath]:
    paths = []
    for run in index.get("parser_runs", []):
        rows = [*run.get("raw_outputs", []), *([run["normalized_output"]] if run.get("normalized_output") else [])]
        paths.extend(_normal(row["path"]) for row in rows if isinstance(row, Mapping) and isinstance(row.get("path"), str))
    return paths


def original_root(analysis: Path, recorded: list[PurePath]) -> PurePath:
    root = Path(analysis).resolve(strict=True)
    if not recorded:
        raise ValueError("the collection index records no parser output")
    for candidate in (root, _normal(Path(analysis).absolute())):
        if all(path.is_relative_to(candidate) for path in recorded):
            return candidate
    first = recorded[0]
    found = next((parent for parent in reversed(first.parents) if (root / first.relative_to(parent)).is_file()), None)
    if found is None:
        raise ValueError("the collection's parser outputs are not in the folder given: " + str(root))
    if any(not path.is_relative_to(found) or not (root / path.relative_to(found)).is_file() for path in recorded):
        raise ValueError("the collection's recorded files do not share one root in the folder given: " + str(root))
    return found


def _within(root: Path, relative: PurePath, recorded) -> Path:
    if any(part in {"..", "."} for part in relative.parts):
        raise ValueError("a collection record names an invalid path: " + str(recorded))
    return root / relative


class CollectionPaths:

    def __init__(self, analysis: Path, index: Mapping[str, Any], *, generation: Path | None = None):
        self.root = Path(analysis).resolve(strict=True)
        record = self.root / "factual-collection.json"
        self.collected_from = _normal(read_json(record)["evidence"]).parent if record.is_file() else None
        self.generation = Path(generation).resolve(strict=True) if generation is not None else None
        recorded = [path for path in _recorded_outputs(index) if not self._from_generation(path)]
        self.original = original_root(analysis, recorded)
        self.relocated = self.original not in (self.root, _normal(Path(analysis).absolute()))

    def _from_generation(self, path: PurePath) -> bool:
        return self.collected_from is not None and path.is_absolute() and path.is_relative_to(self.collected_from)

    def __call__(self, recorded: str | Path) -> Path:
        path = _normal(recorded)
        if self._from_generation(path):
            if self.generation is None:
                raise ValueError("a collection record names a generation file, but no generation folder is given")
            return _within(self.generation, path.relative_to(self.collected_from), recorded)
        if not path.is_absolute():
            return _within(self.root, path, recorded)
        if path.is_relative_to(self.original):
            return _within(self.root, path.relative_to(self.original), recorded)
        raise ValueError("a collection record names a file outside the collection: " + str(path))
