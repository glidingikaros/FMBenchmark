from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.index.scanners.ntfs import parse_boot_sector

try:
    import pytsk3
    import pyvmdk
except ImportError:
    pytsk3 = pyvmdk = None

NTFS_OEM_ID = b"NTFS    "
DATA = 0x80
INDEX_ALLOCATION = 0xA0
BITMAP = 0xB0
MAX_READ_BYTES = 32 * 1024 * 1024


class ImageReadError(ValueError):
    pass


def open_image(path: Path) -> Any:
    if pytsk3 is None or pyvmdk is None:
        raise ImageReadError(
            "reading the evidence image requires pytsk3 and libvmdk-python (the 'collection' extra)"
        )
    if not pyvmdk.check_file_signature(str(path)):
        return pytsk3.Img_Info(str(path))
    handle = pyvmdk.handle()
    handle.open(str(path))
    handle.open_extent_data_files()
    if handle.get_parent_filename():
        raise ImageReadError("bounded NTFS reads require a self-contained image; this VMDK has a parent")

    class VmdkImage(pytsk3.Img_Info):
        def __init__(self) -> None:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            return handle.read_buffer_at_offset(size, offset)

        def get_size(self) -> int:
            return handle.get_media_size()

    return VmdkImage()


def read_image(image: Any, offset: int, length: int, *, max_bytes: int = MAX_READ_BYTES) -> bytes:
    if offset < 0 or length < 0 or length > max_bytes or offset + length > int(image.get_size()):
        raise ImageReadError("image read exceeds the source or the configured bound")
    data = image.read(offset, length) if length else b""
    if len(data) != length:
        raise ImageReadError("image read returned a truncated range")
    return data


def ntfs_volume_offsets(image: Any) -> list[int]:
    try:
        volumes = pytsk3.Volume_Info(image)
    except OSError:
        return [0] if read_image(image, 0, 512)[3:11] == NTFS_OEM_ID else []
    block = int(volumes.info.block_size)
    offsets = set()
    for part in volumes:
        if not int(part.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC):
            continue
        offset = int(part.start) * block
        if offset + 512 <= int(image.get_size()) and read_image(image, offset, 512)[3:11] == NTFS_OEM_ID:
            offsets.add(offset)
    return sorted(offsets)


class NtfsVolume:

    def __init__(self, image: Any, offset: int, *, max_read_bytes: int = MAX_READ_BYTES) -> None:
        self.image = image
        self.offset = offset
        self.max_read_bytes = max_read_bytes
        self.boot_sector = read_image(image, offset, 512)
        self.geometry = parse_boot_sector(self.boot_sector)
        self.record_size = int(self.geometry["mft_record_size"])
        try:
            self.fs = pytsk3.FS_Info(image, offset=offset, type=pytsk3.TSK_FS_TYPE_NTFS)
        except OSError as error:
            raise ImageReadError(f"The Sleuth Kit cannot open the NTFS volume: {error}") from error
        self._mft = self.fs.open_meta(inode=0)

    def mft_record(self, entry: int) -> bytes:
        if entry < 0:
            raise ImageReadError("invalid MFT entry")
        data = self._mft.read_random(entry * self.record_size, self.record_size)
        if len(data) != self.record_size:
            raise ImageReadError(f"MFT record {entry} lies outside the $MFT file")
        return data

    def first_mft_record_on_disk(self) -> bytes:
        start = self.offset + int(self.geometry["mft_start_lcn"]) * int(self.geometry["bytes_per_cluster"])
        return read_image(self.image, start, self.record_size)

    def path_entry(self, path: str) -> int:
        try:
            return int(self.fs.open(path).info.meta.addr)
        except OSError as error:
            raise ImageReadError(f"path is absent from the volume: {path}") from error

    def read_attribute(
        self,
        entry: int,
        attribute_type: int,
        *,
        attribute_id: int | None = None,
        name: str | None = None,
        allocated: bool = False,
        max_bytes: int | None = None,
    ) -> bytes:
        limit = self.max_read_bytes if max_bytes is None else max_bytes
        try:
            file = self.fs.open_meta(inode=entry)
        except OSError as error:
            raise ImageReadError(f"MFT entry {entry} cannot be opened") from error
        matches = [
            attribute
            for attribute in file
            if int(attribute.info.type) == attribute_type
            and (attribute_id is None or int(attribute.info.id) == attribute_id)
            and (name is None or (attribute.info.name or b"").decode("utf-8", "replace") == name)
        ]
        if len(matches) != 1:
            raise ImageReadError("attribute is absent or ambiguous")
        info = matches[0].info
        flags = int(info.flags)
        if flags & (int(pytsk3.TSK_FS_ATTR_COMP) | int(pytsk3.TSK_FS_ATTR_ENC)):
            raise ImageReadError("compressed/encrypted native stream is unsupported")
        size = int(info.size)
        read_flags = 0
        if allocated and not flags & int(pytsk3.TSK_FS_ATTR_RES):
            size = sum(int(run.len) for run in matches[0]) * int(self.geometry["bytes_per_cluster"])
            read_flags = pytsk3.TSK_FS_FILE_READ_FLAG_SLACK
        if size > limit:
            raise ImageReadError("stream length exceeds the configured bound")
        if not size:
            return b""
        data = file.read_random(0, size, info.type, info.id, read_flags)
        if len(data) != size:
            raise ImageReadError("stream read ended before its length")
        return data


__all__ = [
    "BITMAP",
    "DATA",
    "INDEX_ALLOCATION",
    "ImageReadError",
    "NtfsVolume",
    "ntfs_volume_offsets",
    "open_image",
    "read_image",
]
