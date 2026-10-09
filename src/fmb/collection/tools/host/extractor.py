from __future__ import annotations

import csv
import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from fmb.collection.tools.host.definitions import TargetRule, split_file_masks
from fmb.collection.tools.host.ntfs_index import (
    ROOT_ENTRY,
    NtfsIndexError,
    StreamCopyReport,
    UnsupportedStreamError,
    VolumeIndex,
)
from fmb.core.path_policy import is_portable_relative_path

USER_PLACEHOLDER = "%user%"
SKIP_LEADING_SPARSE_STREAMS = frozenset({"$j"})
COPY_LOG_FIELDS = (
    "CopiedTimestamp",
    "SourceFile",
    "DestinationFile",
    "FileSize",
    "SourceFileSha1",
    "DeferredCopy",
    "CreatedOnUtc",
    "ModifiedOnUtc",
    "LastAccessedOnUtc",
    "CopyDuration",
)
SKIP_LOG_FIELDS = ("SourceFile", "SourceFileSha1", "Reason")
SKIP_REASON_UNSAFE_PATH = "unsafe_path"
SKIP_REASON_DESTINATION_EXISTS = "destination_exists"
SKIP_REASON_ALREADY_COPIED = "already_copied"
SKIP_REASON_DESTINATION_TAKEN = "destination_taken"
_FORBIDDEN_COMPONENT_CHARACTERS = frozenset("/\\\x00:")


class UnsafeDestinationError(ValueError):
    pass


class DestinationExistsError(UnsafeDestinationError):
    pass


@dataclass(frozen=True, slots=True)
class CopiedFile:
    source_path: str
    relative_path: str
    size_bytes: int
    sha1: str
    sha256: str
    entry: int
    stream_name: str
    rule_name: str
    requested_target: str
    report: StreamCopyReport


@dataclass(frozen=True, slots=True)
class SkippedFile:
    source_path: str
    reason: str
    sha1: str | None = None
    detail: str | None = None


@dataclass(slots=True)
class ExtractionResult:
    targets_root: Path
    drive_letter: str
    copied: list[CopiedFile] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    console_lines: list[str] = field(default_factory=list)
    log_files: dict[str, Path] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def kape_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S.%f") + "0"


def kape_log_stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H_%M_%S_%f") + "0"


def declared_components(path: str) -> list[str]:
    text = path.strip().replace("/", "\\")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    parts = [part for part in text.split("\\") if part and part != "."]
    return [
        "*" if part.casefold() == USER_PLACEHOLDER else part for part in parts
    ]


def _timestamp_text(payload: Any) -> str:
    value = payload.get("utc") if isinstance(payload, dict) else None
    if isinstance(value, str) and value:
        return value.replace("T", " ").replace("Z", "")
    return ""


def _has_wildcard(value: str) -> bool:
    return any(char in value for char in "*?[")


def _resolve_declared_directories(
    index: VolumeIndex, components: list[str]
) -> list[tuple[int, list[str]]]:
    current: list[tuple[int, list[str]]] = [(ROOT_ENTRY, [])]
    for component in components:
        pattern = component.casefold()
        next_level: list[tuple[int, list[str]]] = []
        for directory, display in current:
            table = index.children.get(directory, {})
            if _has_wildcard(pattern):
                candidates = [
                    entry
                    for name, entries in table.items()
                    if fnmatch.fnmatchcase(name, pattern)
                    for entry in entries
                ]
            else:
                candidates = list(table.get(pattern, []))
            for entry in candidates:
                record = index.entries.get(entry)
                if record is None or not record.is_directory:
                    continue
                if any(entry == existing for existing, _ in next_level):
                    continue
                name = component
                if _has_wildcard(pattern):
                    name = index.display_name(entry, directory) or component
                next_level.append((entry, [*display, name]))
        current = next_level
        if not current:
            break
    return current


def _mask_matches(name: str, mask: str) -> bool:
    return fnmatch.fnmatchcase(name.casefold(), mask.casefold())


def component_problem(part: str) -> str | None:
    if not part or part in {".", ".."}:
        return "empty or dot component"
    if any(char in _FORBIDDEN_COMPONENT_CHARACTERS for char in part):
        return "separator, drive or NUL character in component"
    if not is_portable_relative_path(part):
        return "component is not a portable file name"
    return None


def validate_relative_parts(parts: list[str]) -> str:
    for part in parts:
        problem = component_problem(part)
        if problem is not None:
            raise UnsafeDestinationError(f"{problem}: {part!r}")
    relative = "/".join(parts)
    if not is_portable_relative_path(relative):
        raise UnsafeDestinationError(f"relative path is not portable: {relative!r}")
    return relative


def open_destination(targets_root: Path, parts: list[str]) -> tuple[Path, BinaryIO]:
    validate_relative_parts(parts)
    root = targets_root.resolve(strict=True)
    destination = root.joinpath(*parts)
    expected_parent = root.joinpath(*parts[:-1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.resolve(strict=True) != expected_parent:
        raise UnsafeDestinationError(
            f"destination parent resolves outside its expected location: {destination}"
        )
    if destination.is_symlink():
        raise UnsafeDestinationError(f"destination is a symlink: {destination}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(destination, flags, 0o644)
    except FileExistsError as error:
        raise DestinationExistsError(f"destination already exists: {destination}") from error
    return destination, os.fdopen(descriptor, "wb")


class _HashingSink:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self.sha1 = hashlib.sha1()
        self.sha256 = hashlib.sha256()
        self.size = 0

    def __call__(self, chunk: bytes) -> None:
        self._handle.write(chunk)
        self.sha1.update(chunk)
        self.sha256.update(chunk)
        self.size += len(chunk)

    def close(self) -> None:
        self._handle.close()


def extract_targets(
    index: VolumeIndex,
    rules: list[TargetRule],
    *,
    output_root: Path,
    drive_letter: str = "C",
    command_line: str | None = None,
    deduplicate_by_content: bool = True,
) -> ExtractionResult:
    drive_problem = component_problem(drive_letter)
    if drive_problem is not None:
        raise ValueError(f"drive letter is not a safe path component: {drive_problem}")
    targets_root = output_root / "targets"
    drive_root = targets_root / drive_letter
    drive_root.mkdir(parents=True, exist_ok=True)
    started = _utc_now()
    result = ExtractionResult(
        targets_root=targets_root, drive_letter=drive_letter, started_at=started.isoformat()
    )
    seen_sha1: set[str] = set()
    written_relative: dict[str, str] = {}

    def log(level: str, message: str) -> None:
        line = f"[{kape_timestamp(_utc_now())} | {level}] {message}"
        result.console_lines.append(line)

    if command_line:
        log("INF", f"Command line: {command_line}")
    log("INF", f"fmb host collector: expanding {len(rules)} target rules on {index.image_path}")
    for rule in rules:
        components = declared_components(rule.path)
        directories = _resolve_declared_directories(index, components)
        masks = split_file_masks(rule.file_mask)
        for directory, display in directories:
            declared_dir = "\\".join(display)
            for subdir_parts, name, entry in index.iter_file_paths(directory, recursive=rule.recursive):
                record = index.entries[entry]
                subdir = "\\".join(subdir_parts)
                for mask in masks:
                    base_mask, _, stream_mask = mask.partition(":")
                    if not _mask_matches(name, base_mask):
                        continue
                    stream_name = ""
                    if stream_mask:
                        matches = [
                            candidate
                            for candidate in index.stream_names(entry)
                            if candidate and _mask_matches(candidate, stream_mask)
                        ]
                        if not matches:
                            continue
                        stream_name = matches[0]
                    elif "" not in record.streams:
                        continue
                    source_dir = "\\".join(part for part in (declared_dir, subdir) if part)
                    source_name = f"{name}:{stream_name}" if stream_name else name
                    source_path = f"{drive_letter}:\\{source_dir}\\{source_name}" if source_dir else f"{drive_letter}:\\{source_name}"
                    file_name = rule.save_as or name
                    relative_parts = [drive_letter, *display, *subdir_parts, file_name]
                    try:
                        relative_path = "targets/" + validate_relative_parts(relative_parts)
                    except UnsafeDestinationError as error:
                        result.skipped.append(
                            SkippedFile(source_path=source_path, reason=SKIP_REASON_UNSAFE_PATH, detail=str(error))
                        )
                        log("WRN", f"  Refusing unsafe destination for {source_path}: {error}")
                        break
                    if relative_path in written_relative:
                        same = written_relative[relative_path] == source_path
                        result.skipped.append(
                            SkippedFile(
                                source_path=source_path,
                                reason=SKIP_REASON_ALREADY_COPIED if same else SKIP_REASON_DESTINATION_TAKEN,
                                detail=None if same else f"{relative_path} holds {written_relative[relative_path]}",
                            )
                        )
                        if not same:
                            log("WRN", f"  Refusing destination for {source_path}: {relative_path} is already written")
                        break
                    try:
                        destination, handle = open_destination(targets_root, relative_parts)
                    except UnsafeDestinationError as error:
                        reason = (
                            SKIP_REASON_DESTINATION_EXISTS
                            if isinstance(error, DestinationExistsError)
                            else SKIP_REASON_UNSAFE_PATH
                        )
                        result.skipped.append(
                            SkippedFile(source_path=source_path, reason=reason, detail=str(error))
                        )
                        log("WRN", f"  Refusing destination for {source_path}: {error}")
                        break
                    sink = _HashingSink(handle)
                    try:
                        report = index.copy_stream(
                            entry,
                            stream_name,
                            sink,
                            skip_leading_sparse=stream_name.casefold() in SKIP_LEADING_SPARSE_STREAMS,
                        )
                    except (UnsupportedStreamError, NtfsIndexError) as error:
                        sink.close()
                        destination.unlink(missing_ok=True)
                        result.skipped.append(
                            SkippedFile(source_path=source_path, reason="unsupported_stream", detail=str(error))
                        )
                        log("WRN", f"  Skipping {source_path}: {error}")
                        break
                    sink.close()
                    sha1 = sink.sha1.hexdigest().upper()
                    if deduplicate_by_content and sha1 in seen_sha1:
                        destination.unlink(missing_ok=True)
                        result.skipped.append(
                            SkippedFile(source_path=source_path, reason="Deduped", sha1=sha1)
                        )
                        break
                    seen_sha1.add(sha1)
                    written_relative[relative_path] = source_path
                    if report.skipped_leading_sparse_bytes:
                        log("WRN", f"  Skipping sparse data area in {stream_name or name}!")
                    result.copied.append(
                        CopiedFile(
                            source_path=source_path,
                            relative_path=relative_path,
                            size_bytes=sink.size,
                            sha1=sha1,
                            sha256=sink.sha256.hexdigest(),
                            entry=entry,
                            stream_name=stream_name,
                            rule_name=rule.name,
                            requested_target=rule.requested_target,
                            report=report,
                        )
                    )
                    break
    ended = _utc_now()
    result.ended_at = ended.isoformat()
    log(
        "INF",
        f"copied {len(result.copied)} files, skipped {len(result.skipped)} "
        f"in {(ended - started).total_seconds():.3f} seconds",
    )
    _restore_source_times(index, result, targets_root.parent)
    _write_logs(index, result, targets_root, started)
    return result


FILETIME_UNIX_EPOCH = 116444736000000000


def _restore_source_times(index: VolumeIndex, result: ExtractionResult, output_root: Path) -> None:
    for item in result.copied:
        record = index.entries.get(item.entry)
        info = (record.standard_information or {}) if record else {}
        accessed, modified = (
            (info.get(key) or {}).get("ntfs_filetime") for key in ("accessed", "modified")
        )
        if not all(isinstance(value, int) and value > FILETIME_UNIX_EPOCH for value in (accessed, modified)):
            continue
        os.utime(
            output_root / item.relative_path,
            ns=((accessed - FILETIME_UNIX_EPOCH) * 100, (modified - FILETIME_UNIX_EPOCH) * 100),
        )


def _write_logs(
    index: VolumeIndex, result: ExtractionResult, targets_root: Path, started: datetime
) -> None:
    stamp = kape_log_stamp(started)
    copy_log = targets_root / f"{stamp}_CopyLog.csv"
    skip_log = targets_root / f"{stamp}_SkipLog.csv.csv"
    console_log = targets_root / f"{stamp}_ConsoleLog.txt"
    with copy_log.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COPY_LOG_FIELDS)
        writer.writeheader()
        for item in result.copied:
            record = index.entries.get(item.entry)
            info = (record.standard_information or {}) if record else {}
            writer.writerow(
                {
                    "CopiedTimestamp": kape_timestamp(_utc_now()),
                    "SourceFile": item.source_path,
                    "DestinationFile": item.relative_path,
                    "FileSize": item.size_bytes,
                    "SourceFileSha1": item.sha1,
                    "DeferredCopy": "False",
                    "CreatedOnUtc": _timestamp_text(info.get("created")),
                    "ModifiedOnUtc": _timestamp_text(info.get("modified")),
                    "LastAccessedOnUtc": _timestamp_text(info.get("accessed")),
                    "CopyDuration": "00:00:00",
                }
            )
    with skip_log.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SKIP_LOG_FIELDS)
        writer.writeheader()
        for item in result.skipped:
            writer.writerow(
                {
                    "SourceFile": item.source_path,
                    "SourceFileSha1": item.sha1 or "",
                    "Reason": item.reason if item.detail is None else f"{item.reason}: {item.detail}",
                }
            )
    console_log.write_text("\n".join(result.console_lines) + "\n", encoding="utf-8")
    result.log_files = {"copy_log": copy_log, "skip_log": skip_log, "console_log": console_log}


__all__ = [
    "CopiedFile",
    "DestinationExistsError",
    "ExtractionResult",
    "SKIP_REASON_ALREADY_COPIED",
    "SKIP_REASON_DESTINATION_EXISTS",
    "SKIP_REASON_DESTINATION_TAKEN",
    "SKIP_REASON_UNSAFE_PATH",
    "SkippedFile",
    "UnsafeDestinationError",
    "component_problem",
    "declared_components",
    "extract_targets",
    "kape_log_stamp",
    "kape_timestamp",
    "open_destination",
    "validate_relative_parts",
]
