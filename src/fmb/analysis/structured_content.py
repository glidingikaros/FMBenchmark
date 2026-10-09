from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def zip_content_evidence(fields: Mapping[str, Any], size: int, *, require_parser_verdict: bool = True) -> bool | None:
    def integer(value, minimum=0, maximum=0xffffffff):
        return type(value) is int and minimum <= value <= maximum

    count = fields.get('zip_entry_count')
    offset, length, end = (fields.get(k) for k in ('zip_directory_offset', 'zip_directory_size', 'zip_end_record_offset'))
    comment = fields.get('zip_comment_length')
    entries = fields.get('zip_entries')
    if not (
        (not require_parser_verdict or fields.get('zip_structure_status') == 'complete')
        and fields.get('zip_signature_hex') in {'504b0304', '504b0506'}
        and fields.get('zip_end_signature_hex') == '504b0506'
        and integer(size, maximum=32*1024*1024)
        and integer(count, maximum=32)
        and type(fields.get('zip_disk_number')) is int and fields['zip_disk_number'] == 0
        and type(fields.get('zip_directory_disk')) is int and fields['zip_directory_disk'] == 0
        and type(fields.get('zip_disk_entry_count')) is int and fields['zip_disk_entry_count'] == count
        and all(integer(n) for n in (offset, length, end))
        and integer(comment, maximum=65535) and offset + length == end
        and end + 22 + comment == size
        and isinstance(entries, (list, tuple)) and len(entries) == count
    ):
        return None
    central_end, expanded = offset, 0
    ranges = []
    for item in entries:
        names = ('central_header_offset', 'central_header_end', 'local_header_offset',
                 'data_offset', 'data_end', 'record_end', 'flags', 'compression_method',
                 'compressed_size', 'uncompressed_size', 'observed_uncompressed_size',
                 'version_needed', 'local_flags', 'local_compression_method', 'local_version_needed', 'crc32', 'observed_crc32', 'local_crc32', 'local_compressed_size', 'local_uncompressed_size')
        if not isinstance(item, Mapping) or not all(integer(item.get(key)) for key in names):
            return None
        if not (
            item.get('central_signature_hex') == '504b0102'
            and item.get('local_signature_hex') == '504b0304'
            and item['central_header_offset'] == central_end
            and item['central_header_offset'] + 46 < item['central_header_end'] <= end
            and item['local_header_offset'] + 30 < item['data_offset']
            and item['data_offset'] + item['compressed_size'] == item['data_end'] <= item['record_end'] <= offset
            and isinstance(item.get('central_name_hex'), str)
            and 0 < len(item['central_name_hex']) <= 131070
            and len(item['central_name_hex']) % 2 == 0
            and all(c in '0123456789abcdef' for c in item['central_name_hex'])
            and item.get('local_name_hex') == item['central_name_hex']
            and item['local_header_offset'] + 30 + len(item['local_name_hex']) // 2 <= item['data_offset']
            and item['central_header_offset'] + 46 + len(item['central_name_hex']) // 2 <= item['central_header_end']
            and item['local_flags'] == item['flags']
            and item['local_compression_method'] == item['compression_method']
            and item['local_version_needed'] == item['version_needed']
            and item['flags'] & ~0x080e == 0 and item['compression_method'] in (0, 8)
            and item['version_needed'] in (10, 20)
            and (item['compression_method'] != 8 or item['version_needed'] == 20)
            and (item['compression_method'] != 0 or item['flags'] & 6 == 0)
            and item['uncompressed_size'] == item['observed_uncompressed_size'] <= 8*1024*1024
            and item['crc32'] == item['observed_crc32']
        ):
            return None
        if item['compression_method'] == 0 and item['compressed_size'] != item['uncompressed_size']:
            return None
        if item['flags'] & 8:
            if (item['record_end'] - item['data_end'] not in (12, 16)
                    or item['local_crc32'] not in (0, item['crc32'])
                    or item['local_compressed_size'] not in (0, item['compressed_size'])
                    or item['local_uncompressed_size'] not in (0, item['uncompressed_size'])):
                return None
        elif (item['record_end'] != item['data_end'] or item['local_crc32'] != item['crc32']
              or item['local_compressed_size'] != item['compressed_size']
              or item['local_uncompressed_size'] != item['uncompressed_size']):
            return None
        expanded += item['uncompressed_size']
        if expanded > 16*1024*1024:
            return None
        central_end = item['central_header_end']
        ranges.append((item['local_header_offset'], item['record_end']))
    if central_end != end or fields.get('zip_expanded_size') != expanded or type(fields.get('zip_expanded_size')) is not int:
        return None
    previous = 0
    for start, stop in sorted(ranges):
        if start != previous:
            return None
        previous = stop
    return expanded > 0 if previous == offset else None
