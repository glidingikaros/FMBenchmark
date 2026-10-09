from __future__ import annotations

import struct

import pytest

from fmb.generation.qemu_image import read_ntfs_attribute_content
from fmb.index.adapters.stream_content import executable_content_fields
from fmb.index.scanners.ntfs import read_nonresident_stream
from test_ntfs_surfaces import _nonresident, _record

GEOMETRY = {
    "bytes_per_cluster": 4096,
    "total_clusters": 128,
    "bytes_per_sector": 512,
    "mft_record_size": 1024,
}


def attribute(*, logical=8192, initialized=4090):
    return {
        "runlist_complete": True,
        "lowest_vcn": 0,
        "attribute_flags": 0,
        "logical_size": logical,
        "valid_data_length": initialized,
        "data_runs": [
            {"vcn": 0, "lcn": 50, "cluster_count": 1},
            {"vcn": 1, "lcn": 60, "cluster_count": 1},
        ],
    }


def test_partial_initialized_tail_is_zero_and_never_reads_stale_backing():
    calls = []

    def read(offset, size):
        calls.append((offset, size))
        return b'A' * size

    assert read_nonresident_stream(read, attribute(), GEOMETRY) == b'A' * 4090 + bytes(4102)
    assert calls == [(50 * 4096, 4090)]


def test_initialized_bytes_can_cross_fragmented_runs_and_sparse_holes():
    value = attribute(initialized=4100)
    value["data_runs"][0]["lcn"] = None
    calls = []

    def read(offset, size):
        calls.append((offset, size))
        return b'B' * size

    assert read_nonresident_stream(read, value, GEOMETRY) == bytes(4096) + b'BBBB' + bytes(4092)
    assert calls == [(60 * 4096, 4)]


def test_explicit_raw_allocation_mode_preserves_uninitialized_and_eof_slack():
    value = attribute(logical=5000, initialized=100)
    result = read_nonresident_stream(lambda offset, size: b'R' * size, value, GEOMETRY, allocated=True)
    assert result == b'R' * 8192
    assert read_nonresident_stream(lambda offset, size: b'R' * size, value, GEOMETRY) == b'R' * 100 + bytes(4900)


@pytest.mark.parametrize('initialized', [None, -1, 8193, True, '4096'])
def test_invalid_vdl_fails_before_read(initialized):
    with pytest.raises(ValueError, match='initialized length'):
        read_nonresident_stream(lambda *_: pytest.fail('invalid bounds read backing'), attribute(initialized=initialized), GEOMETRY)


@pytest.mark.parametrize('defect', ['outside_volume', 'noncontiguous_vcn'])
def test_zero_tail_does_not_hide_invalid_unread_mapping(defect):
    value = attribute(logical=1, initialized=0)
    value['data_runs'][1]['lcn' if defect == 'outside_volume' else 'vcn'] = 128
    with pytest.raises(ValueError, match='outside|noncontiguous'):
        read_nonresident_stream(lambda *_: pytest.fail('invalid mapping read backing'), value, GEOMETRY)


def test_truncated_initialized_read_still_fails():
    with pytest.raises(ValueError, match='truncated'):
        read_nonresident_stream(lambda *_: b'', attribute(), GEOMETRY)


def test_protected_native_ads_with_zero_vdl_cannot_acquire_stale_pe_structure():
    pe = bytearray(1024)
    pe[:2] = b'MZ'
    struct.pack_into('<I', pe, 60, 64)
    pe[64:68] = b'PE\0\0'
    struct.pack_into('<HH', pe, 68, 0x14c, 1)
    struct.pack_into('<HH', pe, 84, 224, 2)
    struct.pack_into('<H', pe, 88, 0x10b)
    struct.pack_into('<I', pe, 148, 512)
    struct.pack_into('<II', pe, 328, 512, 512)
    struct.pack_into('<I', pe, 348, 0x20000000)
    assert executable_content_fields(bytes(pe))['pe_structure_status'] == 'complete'
    native = bytearray(_nonresident(0x80, name='public', count=1, logical=1024))
    struct.pack_into('<Q', native, 56, 0)
    record = _record(30, [bytes(native)])

    class Reader:
        def read_at(self, offset, size):
            pytest.fail('VDL=0 must not read stale PE backing')

    result = read_ntfs_attribute_content(Reader(), 0, GEOMETRY, record, 2)
    assert result == bytes(1024)
    assert executable_content_fields(result)['pe_structure_status'] == 'not_pe'
