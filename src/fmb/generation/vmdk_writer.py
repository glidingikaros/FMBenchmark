"""fmb's own copy of a VMware sparse disk into the VMDK that `qemu-img convert -O vmdk` writes.

qemu-img convert allocates the new VMDK one 64 KiB grain at a time and updates both copies of its grain table after
each one. This copy writes the same file in large sequential writes: qemu-img itself creates the empty target (header,
descriptor, both grain directories and their zeroed grain tables), every grain that holds a non-zero byte is appended in
ascending disk order, as qemu-img's in-order convert allocates them, and both copies of the grain tables are filled at
the end. The result is qemu-img's file byte for byte except the random CID in the descriptor.

Only a twoGbMaxExtentSparse descriptor whose extents are uncompressed hosted sparse extents (the VMware Fusion box) is
copied. Anything else raises Unsupported before the target is touched, and fmb converts it with qemu-img.
"""
from __future__ import annotations

from array import array
import os
from pathlib import Path
import re
import struct
import sys
from typing import NamedTuple

SECTOR = 512
GRAIN_SECTORS = 128
GRAIN = GRAIN_SECTORS * SECTOR
TABLE_ENTRIES = 512
TABLE_BYTES = TABLE_ENTRIES * 4
RUN_GRAINS = 128  # read up to 8 MiB of consecutive source grains at once
DESCRIPTOR_LIMIT = 1 << 20  # QEMU reads at most this much of a descriptor file
MAX_SECTORS = 1 << 32  # grain table entries are 32-bit sector numbers; QEMU allocates no grain beyond
NEWLINE_DETECT, REDUNDANT_TABLES, ZERO_GRAIN = 1, 2, 4
ZEROED = 1  # the grain table entry of an all-zero grain in an extent with the ZERO_GRAIN flag
HEADER = struct.Struct("<4sIIQQQQIQQQB4sH")
EXTENT_LINE = re.compile(r'RW (\d+) SPARSE "([^"]+)"')
ACCESS = frozenset({"RW", "RDONLY", "NOACCESS"})
ZEROS = bytes(GRAIN)


class Unsupported(Exception):
    """A disk this copy does not reproduce qemu-img's output for; qemu-img converts it instead."""


class Header(NamedTuple):
    magic: bytes
    version: int
    flags: int
    capacity: int
    granularity: int
    descriptor_offset: int
    descriptor_size: int
    table_entries: int
    backup_directory: int
    directory: int
    grain_offset: int
    unclean: int
    check: bytes
    compression: int


def read_header(fd: int, name: str) -> Header:
    raw = os.pread(fd, HEADER.size, 0)
    if len(raw) < HEADER.size or not raw.startswith(b"KDMV"):
        raise Unsupported(f"{name} is not a hosted sparse extent")
    return Header._make(HEADER.unpack(raw))


def read_entries(fd: int, offset: int, count: int, name: str) -> array:
    """count little-endian 32-bit grain directory or grain table entries at offset."""
    raw = os.pread(fd, count * 4, offset)
    if len(raw) != count * 4:
        raise Unsupported(f"{name}: a grain table lies beyond the end of the file")
    entries = array("I", raw)
    if sys.byteorder == "big":
        entries.byteswap()
    return entries


def extent_lines(descriptor: Path) -> list[tuple[Path, int]]:
    """The extents of a VMware twoGbMaxExtentSparse descriptor file, as QEMU's vmdk driver reads them."""
    try:
        with descriptor.open("rb") as handle:
            raw = handle.read(DESCRIPTOR_LIMIT)
    except OSError as error:
        raise Unsupported(f"cannot read {descriptor.name}: {error}") from error
    # QEMU reads the text up to the first NUL: when it writes a shorter CID into a descriptor, NULs and the end of the
    # old text follow.
    if raw.startswith(b"KDMV"):
        raise Unsupported(f"{descriptor.name} is a single-file sparse VMDK, not a descriptor file")
    head = raw.split(b"\0", 1)[0]
    if len(raw) >= DESCRIPTOR_LIMIT or b"\r" in head or not head.isascii():
        raise Unsupported(f"{descriptor.name} is not a VMware descriptor file")
    text = head.decode("ascii")
    lines = text.split("\n")
    # QEMU takes a file for a VMDK descriptor only when its first line that is no comment and no run of spaces is
    # version=N; otherwise it would convert the text as a raw disk.
    first = next((line for line in lines if not line.startswith("#") and not (line and not line.strip(" "))), "")
    if first != "version=1":
        raise Unsupported(f"{descriptor.name} is not a VMware descriptor file")
    # QEMU reads the first createType it finds, and opens any parentFileNameHint as a backing disk.
    if not text[text.find("createType"):].startswith('createType="twoGbMaxExtentSparse"\n'):
        raise Unsupported(f"{descriptor.name} is not a twoGbMaxExtentSparse disk")
    parent = re.search(r'(?m)^parentCID=(\S+)$', text)
    if "parentFileNameHint" in text or (parent and parent.group(1).strip('"').casefold() != "ffffffff"):
        raise Unsupported(f"{descriptor.name} has a parent disk")
    extents = []
    for line in lines:
        words = line.split()
        if not words or words[0] not in ACCESS:
            continue
        match = EXTENT_LINE.fullmatch(line)
        if match is None or not 0 < int(match.group(1)) < MAX_SECTORS:
            raise Unsupported(f"{descriptor.name} has an extent other than a writable sparse one: {line[:120]}")
        extents.append((descriptor.parent / match.group(2), int(match.group(1))))
    if not extents:
        raise Unsupported(f"{descriptor.name} lists no extent")
    return extents


class Extent:
    """One hosted sparse extent of the source, read as QEMU's vmdk driver reads it: through its primary grain
    directory."""

    def __init__(self, path: Path, sectors: int, *, last: bool):
        try:
            self.fd = os.open(path, os.O_RDONLY)
        except OSError as error:
            raise Unsupported(f"cannot open the extent {path.name}: {error}") from error
        try:
            self.load(path.name, sectors, last)
        except BaseException:
            os.close(self.fd)
            raise

    def load(self, name: str, sectors: int, last: bool) -> None:
        header = read_header(self.fd, name)
        if (header.version not in (1, 2) or header.compression
                or header.flags & ~(NEWLINE_DETECT | REDUNDANT_TABLES | ZERO_GRAIN)):
            raise Unsupported(f"{name}: a compressed, streamed or unknown sparse extent "
                              f"(version {header.version}, flags {header.flags:#x})")
        if header.granularity != GRAIN_SECTORS or header.table_entries != TABLE_ENTRIES:
            raise Unsupported(f"{name}: grains or grain tables of another size")
        # Only the last extent may end inside a grain; anywhere else its grains would not be the target's.
        if header.capacity != sectors or (header.capacity % GRAIN_SECTORS and not last):
            raise Unsupported(f"{name}: its size differs from its descriptor line or ends inside a grain")
        if header.unclean:
            raise Unsupported(f"{name} was not closed cleanly")
        size = os.fstat(self.fd).st_size
        if not 0 < header.directory < size // SECTOR or not 0 < header.grain_offset <= size // SECTOR:
            raise Unsupported(f"{name}: no usable grain directory")
        self.name = name
        self.sectors = sectors
        self.grains = -(-sectors // GRAIN_SECTORS)
        self.zero_grain = bool(header.flags & ZERO_GRAIN)
        tables = -(-self.grains // TABLE_ENTRIES)
        entries = array("I")
        for table in read_entries(self.fd, header.directory * SECTOR, tables, name):
            if table:
                entries.extend(read_entries(self.fd, table * SECTOR, TABLE_ENTRIES, name))
            else:  # a grain table never allocated: its grains read as zeros
                entries.frombytes(bytes(TABLE_BYTES))
        del entries[self.grains:]
        for entry in entries:
            if entry and not (entry == ZEROED and self.zero_grain) and (
                    entry < header.grain_offset or (entry + GRAIN_SECTORS) * SECTOR > size):
                raise Unsupported(f"{name}: a grain table entry points outside the grains")
        self.entries = entries


class Target:
    """The empty monolithicSparse VMDK `qemu-img create -f vmdk` wrote, checked to be what qemu-img convert fills."""

    def __init__(self, fd: int, size: int):
        self.fd = fd
        header = read_header(fd, "qemu-img's new VMDK")
        length = os.fstat(fd).st_size
        self.grains = -(-header.capacity // GRAIN_SECTORS)
        tables = -(-self.grains // TABLE_ENTRIES)
        # QEMU puts the first new grain at the end of the file, rounded up to a whole grain.
        self.next_sector = -(-length // SECTOR // GRAIN_SECTORS) * GRAIN_SECTORS
        if (header.version != 1 or header.flags != NEWLINE_DETECT | REDUNDANT_TABLES or header.compression
                or header.capacity * SECTOR != size or header.granularity != GRAIN_SECTORS
                or header.table_entries != TABLE_ENTRIES or header.unclean or length % SECTOR
                or header.grain_offset != self.next_sector
                or self.next_sector + self.grains * GRAIN_SECTORS > MAX_SECTORS):
            raise Unsupported("qemu-img's new VMDK has another layout")
        if header.descriptor_offset + header.descriptor_size > header.grain_offset:
            raise Unsupported("qemu-img's new VMDK has another layout")
        descriptor = os.pread(fd, header.descriptor_size * SECTOR, header.descriptor_offset * SECTOR)
        if b'\ncreateType="monolithicSparse"\n' not in descriptor.split(b"\0", 1)[0]:
            raise Unsupported("qemu-img's new VMDK is of another subformat")
        # Two grain directories, each pointing at its own empty grain tables between the descriptor and the grains.
        self.directories = []
        for start in (header.directory, header.backup_directory):
            directory = read_entries(fd, start * SECTOR, tables, "qemu-img's new VMDK")
            for table in directory:
                if (table < header.descriptor_offset + header.descriptor_size
                        or table * SECTOR + TABLE_BYTES > header.grain_offset * SECTOR
                        or os.pread(fd, TABLE_BYTES, table * SECTOR) != bytes(TABLE_BYTES)):
                    raise Unsupported("qemu-img's new VMDK has unexpected grain tables")
            self.directories.append(directory)
        if set(self.directories[0]) & set(self.directories[1]):
            raise Unsupported("qemu-img's new VMDK has no redundant grain tables")
        self.entries = array("I", bytes(tables * TABLE_BYTES))

    def append(self, first_grain: int, buffer: bytearray, length: int) -> int:
        """Appends the grains in buffer[:length] that hold a non-zero byte; returns how many."""
        view = memoryview(buffer)
        parts = []
        for offset in range(0, length, GRAIN):
            if not buffer.startswith(ZEROS, offset, offset + GRAIN):
                self.entries[first_grain + offset // GRAIN] = self.next_sector
                self.next_sector += GRAIN_SECTORS
                parts.append(view[offset:offset + GRAIN])
        count = len(parts)
        while parts:
            written = os.writev(self.fd, parts)
            if written <= 0:
                raise OSError("the new VMDK took no more bytes")
            while parts and written >= len(parts[0]):
                written -= len(parts.pop(0))
            if written:
                parts[0] = parts[0][written:]
        return count

    def write_tables(self) -> None:
        entries = self.entries
        if sys.byteorder == "big":
            entries = array("I", entries)
            entries.byteswap()
        for index in range(len(self.directories[0])):
            table = entries[index * TABLE_ENTRIES:(index + 1) * TABLE_ENTRIES]
            if any(table):
                raw = table.tobytes()
                for directory in self.directories:
                    os.pwrite(self.fd, raw, directory[index] * SECTOR)


class SparseDisk:
    """A VMware twoGbMaxExtentSparse disk, a descriptor file and its hosted sparse extents, open for reading."""

    def __init__(self, descriptor: Path | str):
        if not all(hasattr(os, name) for name in ("pread", "pwrite", "writev")) or array("I").itemsize != 4:
            raise Unsupported("this host has no positional and vectored file writes")
        self.extents: list[Extent] = []
        try:
            lines = extent_lines(Path(descriptor))
            for number, (path, sectors) in enumerate(lines, 1):
                self.extents.append(Extent(path, sectors, last=number == len(lines)))
        except OSError as error:
            self.close()
            raise Unsupported(f"cannot read {Path(descriptor).name}: {error}") from error
        except BaseException:
            self.close()
            raise
        self.size = sum(extent.sectors for extent in self.extents) * SECTOR
        if self.size >= MAX_SECTORS * SECTOR:
            self.close()
            raise Unsupported(f"{Path(descriptor).name} is too large for one sparse extent")

    def close(self) -> None:
        while self.extents:
            os.close(self.extents.pop().fd)

    def __enter__(self) -> SparseDisk:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def write_vmdk(self, path: Path | str) -> int:
        """Fills the empty VMDK that `qemu-img create -f vmdk path <self.size>` wrote, and syncs it to disk; returns
        the number of grains written."""
        with open(path, "r+b", buffering=0) as handle:
            target = Target(handle.fileno(), self.size)
            handle.seek(target.next_sector * SECTOR)
            buffer = bytearray(RUN_GRAINS * GRAIN)
            written = first = 0
            for extent in self.extents:
                written += self.copy_extent(extent, target, first, buffer)
                first += extent.grains
            target.write_tables()
            os.fsync(handle.fileno())
        return written


    @staticmethod
    def copy_extent(extent: Extent, target: Target, first: int, buffer: bytearray) -> int:
        """Appends the extent's grains, first being the disk's grain number of its first; returns how many."""
        written = index = 0
        entries = extent.entries
        zeroed = ZEROED if extent.zero_grain else 0
        with open(extent.fd, "rb", buffering=0, closefd=False) as source:
            while index < extent.grains:
                entry = entries[index]
                if entry == 0 or entry == zeroed:
                    index += 1
                    continue
                run = 1
                while (run < RUN_GRAINS and index + run < extent.grains
                       and entries[index + run] == entry + run * GRAIN_SECTORS):
                    run += 1
                length = run * GRAIN
                read_into(source, memoryview(buffer)[:length], entry * SECTOR, extent.name)
                if index + run == extent.grains and extent.sectors % GRAIN_SECTORS:
                    # QEMU reads the last grain only up to the end of the disk and pads the new grain with zeros.
                    end = length - GRAIN + extent.sectors % GRAIN_SECTORS * SECTOR
                    buffer[end:length] = bytes(length - end)
                written += target.append(first + index, buffer, length)
                index += run
        return written


def read_into(source, view: memoryview, offset: int, name: str) -> None:
    source.seek(offset)
    filled = 0
    while filled < len(view):
        count = source.readinto(view[filled:])
        if not count:
            raise OSError(f"{name} ended inside a grain")
        filled += count
