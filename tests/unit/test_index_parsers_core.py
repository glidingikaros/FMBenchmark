from __future__ import annotations


import struct


from pathlib import Path


import pytest


from fmb.index.adapters import usn as usn_adapters
import fmb.index.support.windows_artifacts as windows_artifacts


from fmb.index.scanners import mft, usn


NTFS_2020_UTC = 132223104000000000


def usn_v2_record(
    file_name: str,
    *,
    reason: int,
    timestamp: int = NTFS_2020_UTC,
    file_reference: int = 10,
    parent_reference: int = 5,
) -> bytes:
    name = file_name.encode("utf-16le")
    record_length = 60 + len(name)
    return (
        struct.pack(
            "<IHHQQqQIIIIHH",
            record_length,
            2,
            0,
            file_reference,
            parent_reference,
            42,
            timestamp,
            reason,
            0,
            7,
            0,
            len(name),
            60,
        )
        + name
    )


@pytest.mark.parametrize(
    ("filetime", "record_offset", "expected_utc"),
    [
        (
            134306819598294232,
            37885431,
            "2026-08-08T16:59:19.8294232Z",
        ),
        (
            134306819372981719,
            37818463,
            "2026-08-08T16:58:57.2981719Z",
        ),
    ],
)
def test_usn_v2_parser_preserves_native_filetime_precision_and_offset(
    filetime: int,
    record_offset: int,
    expected_utc: str,
) -> None:
    record = usn_v2_record(
        "candidate.txt",
        reason=0x00008000,
        timestamp=filetime,
    )

    parsed = usn.parse_usn_record_v2(
        record,
        absolute_offset=record_offset,
    )

    assert parsed is not None
    assert parsed["record_offset"] == record_offset
    assert parsed["timestamp_filetime"] == filetime
    assert parsed["timestamp_utc"] == expected_utc


def file_name_attribute_value(name: str, *, namespace: int = 1) -> bytes:
    name_bytes = name.encode("utf-16le")
    value = bytearray(66 + len(name_bytes))
    struct.pack_into("<Q", value, 0, 0x0005000000000042)
    struct.pack_into(
        "<QQQQ",
        value,
        8,
        NTFS_2020_UTC,
        NTFS_2020_UTC + 10_000_000,
        NTFS_2020_UTC,
        NTFS_2020_UTC,
    )
    struct.pack_into("<Q", value, 40, 4096)
    struct.pack_into("<Q", value, 48, 128)
    struct.pack_into("<I", value, 56, 0x20)
    struct.pack_into("<I", value, 60, 0)
    value[64] = len(name)
    value[65] = namespace
    value[66:] = name_bytes
    return bytes(value)


def resident_mft_attribute(
    attr_type: int,
    value: bytes,
    *,
    attr_id: int,
    attr_name: str = "",
) -> bytes:
    name_bytes = attr_name.encode("utf-16le")
    name_offset = 24 if name_bytes else 0
    value_offset = 24 + len(name_bytes)
    attr_length = value_offset + len(value)
    attribute = bytearray(attr_length)
    struct.pack_into("<I", attribute, 0, attr_type)
    struct.pack_into("<I", attribute, 4, attr_length)
    attribute[8] = 0
    attribute[9] = len(attr_name)
    struct.pack_into("<H", attribute, 10, name_offset)
    struct.pack_into("<H", attribute, 14, attr_id)
    struct.pack_into("<I", attribute, 16, len(value))
    struct.pack_into("<H", attribute, 20, value_offset)
    attribute[24 : 24 + len(name_bytes)] = name_bytes
    attribute[value_offset : value_offset + len(value)] = value
    return bytes(attribute)


def mft_record_with_attributes(
    attributes: list[bytes], *, record_size: int = 256
) -> bytes:
    attr_offset = 48
    record = bytearray(record_size)
    record[:4] = b"FILE"
    struct.pack_into("<H", record, 16, 1)
    struct.pack_into("<H", record, 20, attr_offset)
    struct.pack_into("<H", record, 22, mft.MFT_RECORD_IN_USE_FLAG)
    cursor = attr_offset
    for attribute in attributes:
        record[cursor : cursor + len(attribute)] = attribute
        cursor += len(attribute)
    struct.pack_into("<I", record, 24, cursor + 4)
    struct.pack_into("<I", record, cursor, mft.END_ATTR_TYPE)
    return bytes(record)


def mft_record_with_file_name(name: str, *, record_size: int = 256) -> bytes:
    value = file_name_attribute_value(name)
    return mft_record_with_attributes(
        [
            resident_mft_attribute(
                mft.FILE_NAME_ATTR_TYPE,
                value,
                attr_id=1,
            )
        ],
        record_size=record_size,
    )


def mft_record_with_timestamp_mismatch_and_stream(
    name: str,
    stream_name: str,
    *,
    record_size: int = 512,
) -> bytes:
    standard_information = struct.pack(
        "<QQQQ",
        NTFS_2020_UTC,
        NTFS_2020_UTC + 366 * 24 * 60 * 60 * 10_000_000,
        NTFS_2020_UTC,
        NTFS_2020_UTC,
    )
    return mft_record_with_attributes(
        [
            resident_mft_attribute(
                mft.STANDARD_INFORMATION_ATTR_TYPE,
                standard_information,
                attr_id=1,
            ),
            resident_mft_attribute(
                mft.FILE_NAME_ATTR_TYPE,
                file_name_attribute_value(name),
                attr_id=2,
            ),
            resident_mft_attribute(
                mft.DATA_ATTR_TYPE,
                b"stream marker",
                attr_id=3,
                attr_name=stream_name,
            ),
        ],
        record_size=record_size,
    )


def test_usn_reference_scan_retains_every_record_for_the_fixed_roster() -> None:
    requested_reference = (10, 0)
    blob = b"noise" + b"".join(
        (
            usn_v2_record(
                "candidate.txt",
                reason=0x00008000,
                file_reference=10,
            ),
            usn_v2_record(
                "candidate.txt",
                reason=0x00000100,
                file_reference=10,
            ),
            usn_v2_record(
                "unrelated.txt",
                reason=0x00008000,
                file_reference=11,
            ),
        )
    )

    records, stats = usn.scan_usn_records_for_references(
        lambda offset, size: blob[offset : offset + size],
        stream_size_bytes=len(blob),
        references={requested_reference},
        chunk_size_bytes=64,
    )

    assert [record["file_name"] for record in records] == [
        "candidate.txt",
        "candidate.txt",
    ]
    assert stats["reference_count"] == 1
    assert stats["matched_record_count"] == 2
    assert stats["retained_record_count"] == 2
    assert stats["source_bytes_covered"] == len(blob)
    assert stats["status"] == "complete"


def test_usn_reference_scan_fails_closed_at_its_retention_cap() -> None:
    blob = b"".join(
        usn_v2_record(
            "candidate.txt",
            reason=0x00008000,
            file_reference=10,
        )
        for _index in range(2)
    )

    records, stats = usn.scan_usn_records_for_references(
        lambda offset, size: blob[offset : offset + size],
        stream_size_bytes=len(blob),
        references={(10, 0)},
        max_records=1,
        chunk_size_bytes=64,
    )

    assert len(records) == 1
    assert stats["matched_record_count"] == 2
    assert stats["retained_record_count"] == 1
    assert stats["status"] == "partial"


def test_usn_reference_parser_preserves_every_scoped_record_and_scope(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "$J"
    journal_path.write_bytes(
        b"".join(
            (
                usn_v2_record(
                    "candidate.txt",
                    reason=0x00008000,
                    file_reference=10,
                ),
                usn_v2_record(
                    "candidate.txt",
                    reason=0,
                    file_reference=10,
                ),
            )
        )
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    parser_run = usn_adapters.raw_usn_reference_parser_run(
        journal_path=journal_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape"},
        references={(10, 0)},
        filesystem_scope_id="mft-source:test",
        mft_context={
            "row_count": 1,
            "mft_volume_id": "mft-source:test",
            "reference_absence_check_supported": True,
            "path_absence_check_supported": True,
            "active_refs": {(10, 0)},
            "entry_sequences": {10: (0, True)},
            "active_full_paths": {r"candidate.txt"},
            "active_basenames": {"candidate.txt"},
            "directory_paths_by_ref": {},
            "indexed_volumes": {"c"},
            "ambiguous_entries": set(),
        },
    )

    assert parser_run["observation_count"] == 2
    assert [
        observation["observation_type"] for observation in parser_run["observations"]
    ] == ["usn_basic_info_change", "usn_journal_record"]
    assert parser_run["selection_scope"] == {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": "mft-source:test",
        "reference_count": 1,
        "reference_sha256": usn.ntfs_reference_set_sha256({(10, 0)}),
        "matched_record_count": 2,
        "retained_record_count": 2,
        "normalized_record_count": 2,
        "source_size_bytes": journal_path.stat().st_size,
        "source_bytes_covered": journal_path.stat().st_size,
        "status": "complete",
    }


def test_usn_reference_parsers_keep_separate_scope_outputs_and_observation_ids(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "$J"
    journal_path.write_bytes(
        b"".join(
            (
                usn_v2_record(
                    "first.txt",
                    reason=0x00000200,
                    file_reference=10,
                ),
                usn_v2_record(
                    "second.txt",
                    reason=0x00000200,
                    file_reference=11,
                ),
            )
        )
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    mft_context = {
        "row_count": 2,
        "mft_volume_id": "mft-source:test",
        "reference_absence_check_supported": True,
        "path_absence_check_supported": True,
        "active_refs": {(10, 0), (11, 0)},
        "entry_sequences": {10: (0, True), 11: (0, True)},
        "active_full_paths": {r"first.txt", r"second.txt"},
        "active_basenames": {"first.txt", "second.txt"},
        "directory_paths_by_ref": {},
        "indexed_volumes": {"c"},
        "ambiguous_entries": set(),
    }

    first = usn_adapters.raw_usn_reference_parser_run(
        journal_path=journal_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape"},
        references={(10, 0)},
        filesystem_scope_id="mft-source:test",
        mft_context=mft_context,
    )
    second = usn_adapters.raw_usn_reference_parser_run(
        journal_path=journal_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape"},
        references={(11, 0)},
        filesystem_scope_id="mft-source:test",
        mft_context=mft_context,
    )

    assert first["normalized_output"]["path"] != second["normalized_output"]["path"]
    assert {
        item["observation_id"] for item in first["observations"]
    }.isdisjoint(item["observation_id"] for item in second["observations"])


def test_usn_record_normalization_path() -> None:
    reason = 0x00000200 | 0x80000000
    record = usn.parse_usn_record_v2(
        usn_v2_record("secret_evidence.txt", reason=reason)
    )

    assert record is not None
    assert record["file_name"] == "secret_evidence.txt"
    assert record["reason_labels"] == ["FILE_DELETE", "CLOSE"]


    blob = b"noise" + usn_v2_record("secret_evidence.txt", reason=reason)
    records, stats = usn.scan_usn_records_by_reason(
        lambda offset, size: blob[offset : offset + size],
        stream_size_bytes=len(blob),
        chunk_size_bytes=32,
    )

    assert stats["parsed_record_count"] == 1
    assert stats["interesting_reason_labels"] == [
        "FILE_DELETE",
        "RENAME_OLD_NAME",
        "BASIC_INFO_CHANGE",
    ]
    assert [label for item in records for label in item["reason_labels"]].count("FILE_DELETE") == 1


def test_parser_integer_parsers_keep_decimal_truncation_policy() -> None:
    assert windows_artifacts.parse_int("10.5") == 10


def test_raw_mft_parser_preserves_timestamp_difference_and_named_stream():
    raw = mft_record_with_timestamp_mismatch_and_stream('evidence.txt', 'Zone.Identifier')
    record = mft.parse_mft_record(raw, record_offset=0, record_size=512)
    assert record is not None and mft.mft_record_is_in_use(record)
    name = record['file_name_attributes'][0]
    assert name['name'] == 'evidence.txt' and name['namespace_name'] == 'win32'
    assert record['metadata_timestamps']['modified'] != name['file_name_timestamps']['modified']
    assert any(a['stream_name'] == 'Zone.Identifier' and a['is_named_stream'] for a in record['data_attributes'])


def test_usn_rejects_nonpositive_scan_chunks():
    with pytest.raises(ValueError, match='chunk_size_bytes'):
        usn.scan_usn_records_by_reason(lambda offset, size: b'', stream_size_bytes=1, chunk_size_bytes=0)


def test_usn_reason_scan_keeps_records_that_end_past_a_chunk_read():
    names = [f"file{index:06d}.txt" for index in range(1000)]
    blob = b"".join(usn_v2_record(name, reason=0x00000200) for name in names)
    records, stats = usn.scan_usn_records_by_reason(
        lambda offset, size: blob[offset : offset + size],
        stream_size_bytes=len(blob),
        chunk_size_bytes=4096,
    )
    _retained, reference_stats = usn.scan_usn_records_for_references(
        lambda offset, size: blob[offset : offset + size],
        stream_size_bytes=len(blob),
        references={(10, 0)},
        chunk_size_bytes=4096,
    )

    assert sorted(record["file_name"] for record in records) == names
    assert stats["parsed_record_count"] == reference_stats["parsed_record_count"] == len(names)
    assert stats["duplicate_record_count"] == 0
