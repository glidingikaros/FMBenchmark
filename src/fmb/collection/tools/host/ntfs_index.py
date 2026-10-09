from __future__ import annotations

import fnmatch
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fmb.collection.tsk_volume import ntfs_volume_offsets, open_image, read_image
from fmb.index.scanners.mft import (
    DATA_ATTR_TYPE,
    STANDARD_INFORMATION_ATTR_TYPE,
    parse_standard_information,
)
from fmb.index.scanners.ntfs import parse_boot_sector

try:
    import pytsk3
except ImportError:
    pytsk3 = None

ROOT_ENTRY = 5
MAX_READ_BYTES = 32 * 1024 * 1024


class NtfsIndexError(ValueError):
    pass


class UnsupportedStreamError(NtfsIndexError):
    pass


@dataclass(frozen=True, slots=True)
class FileName:
    name: str
    parent_entry: int
    parent_sequence: int


@dataclass(slots=True)
class FileEntry:
    entry: int
    sequence: int
    is_directory: bool
    names: list[FileName] = field(default_factory=list)
    streams: dict[str, int] = field(default_factory=dict)
    stream_names: dict[str, str] = field(default_factory=dict)
    standard_information: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class MergedStream:
    stream_name: str
    attribute_id: int
    resident: bytes | None
    runs: tuple[tuple[int, int | None, int], ...]
    logical_size: int
    flags: int


@dataclass(slots=True)
class StreamCopyReport:
    bytes_written: int = 0
    sparse_zero_bytes: int = 0
    skipped_leading_sparse_bytes: int = 0
    resident: bool = False


class VolumeIndex:

    def __init__(
        self,
        image_path: Path,
        *,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.image_path = image_path.expanduser().resolve()
        self._progress = progress or (lambda _message: None)
        try:
            self.image = open_image(self.image_path)
        except ValueError as error:
            raise NtfsIndexError(str(error)) from error
        self.partition_offset, self.geometry = self._select_volume()
        self.cluster = int(self.geometry["bytes_per_cluster"])
        try:
            self.fs = pytsk3.FS_Info(self.image, offset=self.partition_offset, type=pytsk3.TSK_FS_TYPE_NTFS)
        except OSError as error:
            raise NtfsIndexError(f"The Sleuth Kit cannot open the NTFS volume: {error}") from error
        self.entries: dict[int, FileEntry] = {}
        self.children: dict[int, dict[str, list[int]]] = {}
        self._index_records()
        self._build_children()

    def _select_volume(self) -> tuple[int, dict[str, Any]]:
        candidates = []
        for offset in ntfs_volume_offsets(self.image):
            geometry = parse_boot_sector(read_image(self.image, offset, 512))
            candidates.append((int(geometry["volume_size_bytes"]), offset, geometry))
        if not candidates:
            raise NtfsIndexError("evidence image has no NTFS volume")
        candidates.sort(key=lambda item: (-item[0], item[1]))
        _size, offset, geometry = candidates[0]
        return offset, geometry

    def _index_records(self) -> None:
        record_count = int(self.fs.info.last_inum)
        self._progress(f"reading {record_count} MFT records through The Sleuth Kit {pytsk3.TSK_VERSION_STR}")
        extensions = 0
        unreadable = 0
        for entry in range(record_count):
            try:
                file = self.fs.open_meta(inode=entry)
            except OSError:
                unreadable += 1
                continue
            meta = file.info.meta
            if not int(meta.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC):
                continue
            record = FileEntry(
                entry=entry,
                sequence=int(meta.seq),
                is_directory=int(meta.type) == int(pytsk3.TSK_FS_META_TYPE_DIR),
            )
            base = False
            for attribute in file:
                info = attribute.info
                if int(info.type) == STANDARD_INFORMATION_ATTR_TYPE:
                    base = True
                    value = file.read_random(0, int(info.size), info.type, info.id)
                    record.standard_information = parse_standard_information(value)
                elif int(info.type) == DATA_ATTR_TYPE:
                    name = (info.name or b"").decode("utf-8", "replace")
                    record.streams.setdefault(name.casefold(), int(info.id))
                    record.stream_names.setdefault(name.casefold(), name)
            if not base:
                extensions += 1
                continue
            self.entries[entry] = record
        self._progress(
            f"indexed {len(self.entries)} in-use records and {extensions} extension records; "
            f"{unreadable} MFT records TSK cannot read (never used or damaged)"
        )

    def _build_children(self) -> None:
        links: list[tuple[int, int, str]] = []
        for parent_entry, parent in self.entries.items():
            if not parent.is_directory:
                continue
            try:
                directory = self.fs.open_dir(inode=parent_entry)
            except OSError:
                continue
            for file in directory:
                link = file.info.name
                entry = int(link.meta_addr)
                record = self.entries.get(entry)
                if (
                    record is not None
                    and entry != parent_entry
                    and link.name not in (b".", b"..")
                    and int(link.flags) & int(pytsk3.TSK_FS_NAME_FLAG_ALLOC)
                    and int(link.meta_seq) == record.sequence
                ):
                    links.append((entry, parent_entry, link.name.decode("utf-8", "replace")))
        links.sort(key=lambda item: item[:2])
        for entry, parent_entry, name in links:
            bucket = self.children.setdefault(parent_entry, {}).setdefault(name.casefold(), [])
            if entry not in bucket:
                bucket.append(entry)
                self.entries[entry].names.append(
                    FileName(name, parent_entry, self.entries[parent_entry].sequence)
                )

    def display_name(self, entry: int, parent_entry: int) -> str | None:
        record = self.entries.get(entry)
        if record is None:
            return None
        names = [item.name for item in record.names if item.parent_entry == parent_entry]
        return names[0] if names else None

    def link_name(self, entry: int, parent_entry: int, key: str) -> str | None:
        record = self.entries.get(entry)
        if record is None:
            return None
        names = [
            item.name
            for item in record.names
            if item.parent_entry == parent_entry and item.name.casefold() == key
        ]
        return names[0] if names else None

    def resolve_directories(self, components: list[str]) -> list[int]:
        current = [ROOT_ENTRY]
        for component in components:
            if not component or component == ".":
                continue
            pattern = component.casefold()
            wildcard = any(char in pattern for char in "*?[")
            next_entries: list[int] = []
            for directory in current:
                table = self.children.get(directory, {})
                if wildcard:
                    matches = [
                        entry
                        for name, entries in table.items()
                        if fnmatch.fnmatchcase(name, pattern)
                        for entry in entries
                    ]
                else:
                    matches = list(table.get(pattern, []))
                for entry in matches:
                    record = self.entries.get(entry)
                    if record is not None and record.is_directory and entry not in next_entries:
                        next_entries.append(entry)
            current = next_entries
            if not current:
                break
        return current

    def iter_links(self, directory: int) -> list[tuple[str, int]]:
        table = self.children.get(directory, {})
        links: list[tuple[str, int]] = []
        for key, entries in table.items():
            for entry in entries:
                name = self.link_name(entry, directory, key)
                if name is not None:
                    links.append((name, entry))
        links.sort(key=lambda item: (item[0].casefold(), item[1]))
        return links

    def iter_file_paths(
        self, directory: int, *, recursive: bool, relative: tuple[str, ...] = ()
    ) -> Iterator[tuple[tuple[str, ...], str, int]]:
        for name, entry in self.iter_links(directory):
            record = self.entries[entry]
            if record.is_directory:
                if recursive:
                    yield from self.iter_file_paths(
                        entry, recursive=True, relative=(*relative, name)
                    )
                continue
            yield relative, name, entry

    def stream_names(self, entry: int) -> list[str]:
        record = self.entries.get(entry)
        if record is None:
            return []
        return [record.stream_names[key] for key in record.streams]

    def merged_stream(self, entry: int, stream_name: str = "") -> MergedStream | None:
        record = self.entries.get(entry)
        key = stream_name.casefold()
        if record is None or key not in record.streams:
            return None
        file = self.fs.open_meta(inode=entry)
        matches = [
            attribute
            for attribute in file
            if int(attribute.info.type) == DATA_ATTR_TYPE and int(attribute.info.id) == record.streams[key]
        ]
        if len(matches) != 1:
            raise UnsupportedStreamError("TSK does not identify the stream by one attribute id")
        attribute = matches[0]
        info = attribute.info
        display, flags, size = record.stream_names[key], int(info.flags), int(info.size)
        if flags & int(pytsk3.TSK_FS_ATTR_RES):
            value = file.read_random(0, size, info.type, info.id) if size else b""
            return MergedStream(display, int(info.id), value, (), size, flags)
        runs: list[tuple[int, int | None, int]] = []
        next_vcn = 0
        for run in attribute:
            vcn, count, run_flags = int(run.offset), int(run.len), int(run.flags)
            if run_flags & int(pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER):
                raise UnsupportedStreamError("stream mapping pairs are incomplete")
            if vcn != next_vcn or count <= 0:
                raise UnsupportedStreamError("stream VCN coverage is not contiguous")
            sparse = run_flags & int(pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)
            runs.append((vcn, None if sparse else int(run.addr), count))
            next_vcn += count
        if flags & int(pytsk3.TSK_FS_ATTR_COMP):
            raise UnsupportedStreamError("ntfs_compressed_stream")
        if flags & int(pytsk3.TSK_FS_ATTR_ENC):
            raise UnsupportedStreamError("ntfs_encrypted_stream")
        if next_vcn * self.cluster < size:
            raise UnsupportedStreamError("stream mapping pairs do not cover its logical size")
        self._check_physical_runs(runs)
        return MergedStream(display, int(info.id), None, tuple(runs), size, flags)

    def _check_physical_runs(self, runs: list[tuple[int, int | None, int]]) -> None:
        volume_clusters = int(self.geometry["volume_size_bytes"]) // self.cluster
        intervals: list[tuple[int, int]] = []
        for _vcn, lcn, count in runs:
            if lcn is None:
                continue
            if lcn < 0 or lcn + count > volume_clusters:
                raise UnsupportedStreamError("stream maps outside the volume")
            intervals.append((lcn, lcn + count))
        intervals.sort()
        for (_start, end), (next_start, _next_end) in zip(intervals, intervals[1:]):
            if next_start < end:
                raise UnsupportedStreamError("stream physical runs overlap")

    def copy_stream(
        self,
        entry: int,
        stream_name: str,
        sink: Callable[[bytes], None],
        *,
        skip_leading_sparse: bool = False,
    ) -> StreamCopyReport:
        report = StreamCopyReport()
        stream = self.merged_stream(entry, stream_name)
        if stream is None:
            raise NtfsIndexError(f"stream is absent: entry {entry} {stream_name!r}")
        if stream.resident is not None:
            sink(stream.resident)
            report.bytes_written = len(stream.resident)
            report.resident = True
            return report
        file = self.fs.open_meta(inode=entry)
        position = 0
        emitted_data = False
        for _vcn, lcn, count in stream.runs:
            if position >= stream.logical_size:
                break
            take = min(count * self.cluster, stream.logical_size - position)
            if lcn is None:
                if skip_leading_sparse and not emitted_data:
                    report.skipped_leading_sparse_bytes += take
                else:
                    self._emit_zeros(sink, take)
                    report.sparse_zero_bytes += take
                    report.bytes_written += take
                position += take
                continue
            end = position + take
            while position < end:
                length = min(MAX_READ_BYTES, end - position)
                chunk = file.read_random(position, length, DATA_ATTR_TYPE, stream.attribute_id)
                if len(chunk) != length:
                    raise UnsupportedStreamError("stream read ended before its logical size")
                sink(chunk)
                position += length
            report.bytes_written += take
            emitted_data = True
        return report

    @staticmethod
    def _emit_zeros(sink: Callable[[bytes], None], length: int) -> None:
        offset = 0
        while offset < length:
            chunk = min(MAX_READ_BYTES, length - offset)
            sink(bytes(chunk))
            offset += chunk


__all__ = [
    "FileEntry",
    "FileName",
    "MergedStream",
    "NtfsIndexError",
    "ROOT_ENTRY",
    "StreamCopyReport",
    "UnsupportedStreamError",
    "VolumeIndex",
]
