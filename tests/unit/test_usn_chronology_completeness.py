from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmb.analysis.deterministic import _usn_journal_window
from fmb.index.adapters import usn as usn_adapters
from fmb.index.scanners import usn

FILETIME = 132223104000000000
BASE = 8192
FRN = (3 << 48) | 42


def record(offset: int, seconds: int = 0) -> bytes:
    name = 'public.txt'.encode('utf-16le')
    length = (60 + len(name) + 7) // 8 * 8
    return (struct.pack('<IHHQQqQIIIIHH', length, 2, 0, FRN, (2 << 48) | 5,
                        BASE + offset, FILETIME + seconds * 10_000_000,
                        0x8000, 0, 0, 0, len(name), 60)
            + name + bytes(length - 60 - len(name)))


def journal(tmp_path: Path, data: bytes, minimum: int = 0):
    root = tmp_path / 'collected'
    path = root / 'targets/C/$Extend/$UsnJrnl/$J'
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    path.with_name('$Max').write_bytes(struct.pack('<QQQQ', 33554432, 8388608, 123456, minimum))
    return path, {'collector': 'kape', 'output_root': str(root)}


def rule_window(scope):
    return _usn_journal_window(SimpleNamespace(coverage=[SimpleNamespace(artifact_family='ntfs.usn', scope=scope)]))


def three_records():
    data = bytearray()
    for second in range(3):
        data.extend(record(len(data), second))
    return data


def test_complete_aligned_records_and_zero_padding_preserve_scope(tmp_path):
    data = bytes(16)
    data += record(len(data))
    data += bytes(4096 - len(data))
    data += record(len(data), 1) + bytes(11)
    path, collector = journal(tmp_path, data)
    order = usn.usn_journal_timestamp_order(path)
    assert order == {'order_checked': True, 'checked_record_count': 2,
                     'timestamp_reversal_count': 0, 'first_reversal_usn': None,
                     'max_backward_seconds': 0}
    scope = usn_adapters.raw_usn_journal_scope(path, collector_run=collector)
    assert rule_window(scope) is not None


@pytest.mark.parametrize('middle_usn', [99999, BASE, BASE + 8, -1, BASE + 88])
def test_interior_usn_must_match_physical_offset_not_just_timestamp_order(tmp_path, middle_usn):
    data = three_records()
    struct.pack_into('<q', data, 80 + 24, middle_usn)
    path, collector = journal(tmp_path, data)
    assert usn.usn_journal_window(path)['window_complete'] is True
    scope = usn_adapters.raw_usn_journal_scope(path, collector_run=collector)
    assert scope['order_checked'] is False and scope['timestamp_reversal_count'] == 0
    assert rule_window(scope) is None


@pytest.mark.parametrize('defect', ['major3', 'major4', 'minor1', 'unaligned_length',
                                  'invalid_name', 'invalid_timestamp', 'zero_length', 'oversized_length'])
def test_retained_malformed_or_unsupported_record_is_not_silently_skipped(tmp_path, defect):
    data = three_records()
    if defect in {'major3', 'major4'}:
        struct.pack_into('<H', data, 84, int(defect[-1]))
    elif defect == 'minor1':
        struct.pack_into('<H', data, 86, 1)
    elif defect == 'unaligned_length':
        struct.pack_into('<I', data, 80, 81)
    elif defect == 'invalid_name':
        struct.pack_into('<H', data, 80 + 56, 19)
    elif defect == 'invalid_timestamp':
        struct.pack_into('<Q', data, 80 + 32, 2**64 - 1)
    else:
        struct.pack_into('<I', data, 80, 0 if defect == 'zero_length' else 65536)
    path, collector = journal(tmp_path, data)
    scope = usn_adapters.raw_usn_journal_scope(path, collector_run=collector)
    assert scope['order_checked'] is False
    assert rule_window(scope) is None


@pytest.mark.parametrize('tail', [b'X', bytes(7) + b'X', bytes(16) + b'nonzero', record(160)[:59]])
def test_nonzero_unparsed_tail_refuses_complete_order(tmp_path, tail):
    path, collector = journal(tmp_path, record(0) + record(80, 1) + tail)
    scope = usn_adapters.raw_usn_journal_scope(path, collector_run=collector)
    assert scope['order_checked'] is False
    assert rule_window(scope) is None


@pytest.mark.parametrize('reversal', [False, True])
def test_verified_minimum_preserves_stale_prefix_filter_and_all_observations(tmp_path, reversal):
    data = record(0, 10) + record(80, 2) + record(160, 1 if reversal else 3)
    path, collector = journal(tmp_path, data, BASE + 80)
    before = usn.usn_journal_timestamp_order(path)
    after = usn.usn_journal_timestamp_order(path, minimum_usn=BASE + 80)
    assert before['timestamp_reversal_count'] == 1 + int(reversal)
    assert after['order_checked'] is True and after['checked_record_count'] == 2
    assert after['timestamp_reversal_count'] == int(reversal)
    assert (rule_window(usn_adapters.raw_usn_journal_scope(path, collector_run=collector)) is None) is reversal
    records, scan = usn.scan_usn_records_for_references(
        lambda offset, size: data[offset:offset + size], stream_size_bytes=len(data), references={(42, 3)})
    assert len(records) == 3 and scan['status'] == 'complete'
    assert path.read_bytes() == data


def test_forged_low_header_usn_cannot_hide_damage_inside_physical_valid_interval(tmp_path):
    data = three_records()
    struct.pack_into('<q', data, 80 + 24, BASE - 100)
    path, _ = journal(tmp_path, data)
    assert usn.usn_journal_timestamp_order(path, minimum_usn=BASE + 80)['order_checked'] is False


def test_malformed_bytes_wholly_below_verified_bound_do_not_veto_valid_records(tmp_path):
    data = b'bad head' + record(8, 1) + record(88, 2)
    path, _ = journal(tmp_path, data)
    assert usn.usn_journal_timestamp_order(path)['order_checked'] is False
    result = usn.usn_journal_timestamp_order(path, minimum_usn=BASE + 8)
    assert result['order_checked'] is True and result['checked_record_count'] == 2


def test_no_valid_records_never_certify_order(tmp_path):
    path, _ = journal(tmp_path, bytes(256))
    assert usn.usn_journal_timestamp_order(path)['order_checked'] is False
    path.write_bytes(record(0))
    result = usn.usn_journal_timestamp_order(path, minimum_usn=BASE + 80)
    assert result['order_checked'] is False and result['checked_record_count'] == 0


def test_cap_refuses_before_reading_and_stays_one_gib_by_default(tmp_path, monkeypatch):
    import inspect

    path, _ = journal(tmp_path, three_records())
    monkeypatch.setattr(Path, 'open', lambda *args, **kwargs: pytest.fail('over-cap journal was opened'))
    assert usn.usn_journal_timestamp_order(path, max_bytes=100)['order_checked'] is False
    assert inspect.signature(usn.usn_journal_timestamp_order).parameters['max_bytes'].default == 1024**3


def record_v3(offset: int) -> bytes:
    name = 'v3.txt'.encode('utf-16le')
    length = (76 + len(name) + 7) // 8 * 8
    header = struct.pack('<IHH', length, 3, 0) + struct.pack('<QQ', FRN, 0) + struct.pack('<QQ', (2 << 48) | 5, 0)
    header += struct.pack('<qQIIIIHH', BASE + offset, FILETIME, 0x100, 0, 0, 0, len(name), 76)
    return header + name + bytes(length - 76 - len(name))


def test_undecoded_record_versions_make_journal_coverage_partial(tmp_path):
    data = bytearray(three_records())
    _records, clean = usn.scan_usn_records_by_reason(lambda offset, size: bytes(data[offset:offset + size]),
                                                      stream_size_bytes=len(data))
    assert 'unsupported_record_count' not in clean
    data.extend(record_v3(len(data)))
    data.extend(record(len(data), 3))
    reader = lambda offset, size: bytes(data[offset:offset + size])
    assert list(usn.usn_unsupported_record_offsets(bytes(data), base_offset=0)) == [len(three_records())]
    _records, stats = usn.scan_usn_records_by_reason(reader, stream_size_bytes=len(data))
    assert stats['parsed_record_count'] == 4 and stats['unsupported_record_count'] == 1
    retained, scan = usn.scan_usn_records_for_references(reader, stream_size_bytes=len(data), references={(42, 3)})
    assert len(retained) == 4 and scan['status'] == 'partial' and scan['unsupported_record_count'] == 1
    path, collector = journal(tmp_path, bytes(data))
    run = usn_adapters.raw_usn_journal_parser_run(journal_path=path, normalized_output_dir=tmp_path / 'normalized',
                                                   collector_run=collector)
    assert run['coverage_status'] == 'partial'
