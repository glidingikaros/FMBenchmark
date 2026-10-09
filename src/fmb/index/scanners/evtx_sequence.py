from __future__ import annotations

import struct
import zlib


def retained_record_ids(data: bytes) -> tuple[int, ...]:
    def u32(raw: bytes, offset: int) -> int:
        return struct.unpack_from("<I", raw, offset)[0]

    def u64(raw: bytes, offset: int) -> int:
        return struct.unpack_from("<Q", raw, offset)[0]

    if len(data) < 4096 or data[:8] != b"ElfFile\0" or (len(data) - 4096) % 65536:
        raise ValueError("invalid EVTX file envelope")
    capacity = (len(data) - 4096) // 65536
    count = struct.unpack_from("<H", data, 42)[0]
    first, last = u64(data, 8), u64(data, 16)
    if (not capacity or not 0 < count <= capacity
            or u32(data, 32) != 128
            or struct.unpack_from("<H", data, 40)[0] != 4096
            or u32(data, 120) & 1
            or u32(data, 124) != zlib.crc32(data[:120])):
        raise ValueError("unverified EVTX header or dirty log")
    if ((last - first) % capacity) + 1 != count:
        raise ValueError("EVTX active chunk range disagrees with count")
    records: list[int] = []
    for ordinal in range(count):
        slot = (first + ordinal) % capacity
        chunk = data[4096 + slot * 65536:4096 + (slot + 1) * 65536]
        if chunk[:8] != b"ElfChnk\0" or u32(chunk, 40) != 128:
            raise ValueError("invalid active EVTX chunk")
        last_offset, free_offset = u32(chunk, 44), u32(chunk, 48)
        if not 512 <= last_offset < free_offset <= 65536:
            raise ValueError("invalid active EVTX record extent")
        if (u32(chunk, 124) != zlib.crc32(chunk[:120] + chunk[128:512])
                or u32(chunk, 52) != zlib.crc32(chunk[512:free_offset])):
            raise ValueError("EVTX chunk checksum mismatch")
        position = 512
        chunk_ids: list[int] = []
        while position <= last_offset:
            if position + 28 > free_offset or chunk[position:position + 4] != b"**\0\0":
                raise ValueError("EVTX active record missing or malformed")
            size = u32(chunk, position + 4)
            end = position + size
            if size < 28 or end > free_offset or u32(chunk, end - 4) != size:
                raise ValueError("EVTX active record length mismatch")
            chunk_ids.append(u64(chunk, position + 8))
            if position == last_offset:
                if any(chunk[end:free_offset]):
                    raise ValueError("unaccounted active EVTX bytes")
                break
            position = end
        else:
            raise ValueError("EVTX last-record offset not on an envelope boundary")
        if (chunk_ids[0] != u64(chunk, 24) or chunk_ids[-1] != u64(chunk, 32)
                or any(b <= a for a, b in zip(chunk_ids, chunk_ids[1:]))):
            raise ValueError("EVTX chunk identifiers contradict active envelopes")
        records.extend(chunk_ids)
    if any(b <= a for a, b in zip(records, records[1:])):
        raise ValueError("EVTX retained identifiers duplicate or reverse")
    return tuple(records)
