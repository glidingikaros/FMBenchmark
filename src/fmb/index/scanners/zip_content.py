from __future__ import annotations

import struct
import zlib
from typing import Any

MAX_ZIP_ENTRIES = 32
MAX_ZIP_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ZIP_STREAM_BYTES = 32 * 1024 * 1024


def zip_content_fields(data: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {
        'zip_signature_hex': data[:4].hex(), 'zip_structure_status': 'not_zip',
    }
    if data[:4] not in (b'PK\x03\x04', b'PK\x05\x06'):
        return fields
    fields['zip_structure_status'] = 'incomplete_or_unsupported'
    if len(data) > MAX_ZIP_STREAM_BYTES:
        return fields
    try:
        end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
        if end < 0 or end + 22 > len(data):
            return fields
        disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack_from('<4H2IH', data, end + 4)
        fields.update(zip_end_record_offset=end, zip_end_signature_hex=data[end:end+4].hex(),
                      zip_disk_number=disk, zip_directory_disk=cd_disk,
                      zip_disk_entry_count=disk_count, zip_entry_count=count,
                      zip_directory_size=cd_size, zip_directory_offset=cd_offset,
                      zip_comment_length=comment)
        if (disk or cd_disk or disk_count != count or not 0 <= count <= MAX_ZIP_ENTRIES
                or end + 22 + comment != len(data) or cd_offset + cd_size != end):
            return fields
        entries = []
        cursor, expanded = cd_offset, 0
        for _ in range(count):
            if cursor + 46 > end or data[cursor:cursor+4] != b'PK\x01\x02':
                return fields
            (made, needed, flags, method, time, date, crc, compressed, size,
             name_len, extra_len, comment_len, start_disk, internal, external,
             local) = struct.unpack_from('<6H3I5H2I', data, cursor + 4)
            next_cursor = cursor + 46 + name_len + extra_len + comment_len
            if (next_cursor > end or not name_len or needed not in (10, 20) or start_disk
                    or flags & ~0x080e or method not in (0, 8)
                    or method == 0 and flags & 6 or method == 8 and needed != 20
                    or size > MAX_ZIP_MEMBER_BYTES or compressed > MAX_ZIP_STREAM_BYTES
                    or local + 30 > cd_offset):
                return fields
            name = data[cursor+46:cursor+46+name_len]
            name.decode("utf-8" if flags & 0x800 else "cp437")
            if data[local:local+4] != b'PK\x03\x04':
                return fields
            (local_needed, local_flags, local_method, local_time, local_date,
             local_crc, local_compressed, local_size, local_name_len,
             local_extra_len) = struct.unpack_from('<5H3I2H', data, local+4)
            if ((local_needed, local_flags, local_method, local_time, local_date)
                    != (needed, flags, method, time, date)):
                return fields
            start = local + 30 + local_name_len + local_extra_len
            stop = start + compressed
            if (stop > cd_offset or local_name_len != name_len
                    or data[local+30:local+30+local_name_len] != name):
                return fields
            if flags & 8:
                if (local_crc not in (0, crc) or local_compressed not in (0, compressed)
                        or local_size not in (0, size)):
                    return fields
                descriptor = stop + (4 if data[stop:stop+4] == b'PK\x07\x08' else 0)
                if descriptor + 12 > cd_offset or struct.unpack_from('<3I', data, descriptor) != (crc, compressed, size):
                    return fields
                record_end = descriptor + 12
            else:
                if (local_crc, local_compressed, local_size) != (crc, compressed, size):
                    return fields
                record_end = stop
            raw = data[start:stop]
            if method == 0:
                decoded = raw
            else:
                inflater = zlib.decompressobj(-15)
                decoded = inflater.decompress(raw, size + 1)
                if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                    return fields
            observed_crc = zlib.crc32(decoded)
            if len(decoded) != size or observed_crc != crc:
                return fields
            expanded += len(decoded)
            if expanded > MAX_ZIP_TOTAL_BYTES:
                return fields
            entries.append({
                'central_header_offset': cursor, 'central_header_end': next_cursor,
                'central_signature_hex': data[cursor:cursor+4].hex(),
                'local_header_offset': local, 'local_signature_hex': data[local:local+4].hex(),
                'data_offset': start, 'data_end': stop, 'record_end': record_end,
                'flags': flags, 'compression_method': method, 'version_needed': needed,
                'central_name_hex': name.hex(),
                'local_name_hex': data[local+30:local+30+local_name_len].hex(),
                'local_flags': local_flags, 'local_compression_method': local_method,
                'local_version_needed': local_needed,
                'compressed_size': compressed, 'uncompressed_size': size,
                'observed_uncompressed_size': len(decoded),
                'crc32': crc, 'observed_crc32': observed_crc,
                'local_crc32': local_crc, 'local_compressed_size': local_compressed,
                'local_uncompressed_size': local_size,
            })
            cursor = next_cursor
        if cursor != end:
            return fields
        previous = 0
        for item in sorted(entries, key=lambda row: row['local_header_offset']):
            if item['local_header_offset'] != previous:
                return fields
            previous = item['record_end']
        if previous != cd_offset:
            return fields
        fields.update(zip_entries=entries, zip_expanded_size=expanded,
                      zip_structure_status='complete')
    except (struct.error, zlib.error, OverflowError, UnicodeDecodeError):
        pass
    return fields
