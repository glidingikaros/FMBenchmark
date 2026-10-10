from __future__ import annotations

import struct
from pathlib import Path

from fmb.index.scanners.logfile import (
    bind_mft_record,
    decode_si_timestamp_update,
    preferred_file_name,
    read_mft_record,
    si_updates_from_records,
)

FILETIME_2010 = 0x01CA8B1CFFC62000
FILETIME_2017 = 0x01D298F26586B400
FILETIME_2026_A = 0x01DD425240D07874
FILETIME_2026_B = 0x01DD42A5A32A12F8


def _resident_attribute(attr_type: int, value: bytes, *, attr_id: int = 0) -> bytes:
    length = 24 + len(value)
    length += (-length) % 8
    header = struct.pack(
        "<IIBBHHHIHBB",
        attr_type,
        length,
        0,
        0,
        0x18,
        0,
        attr_id,
        len(value),
        0x18,
        0,
        0,
    )
    return (header + value).ljust(length, b"\0")


def file_record_bytes(
    *,
    entry: int,
    sequence: int,
    in_use: bool = True,
    lsn: int = 4242,
    si_times: tuple[int, int, int, int] = (FILETIME_2010, FILETIME_2010, FILETIME_2026_B, FILETIME_2026_A),
    file_name: str = "stomped.txt",
    parent: tuple[int, int] = (5, 1),
    fn_times: tuple[int, int, int, int] = (FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B),
    record_size: int = 1024,
) -> bytes:
    si_value = struct.pack("<QQQQ", *si_times) + struct.pack("<IIIIIIQ", 0x20, 0, 0, 0, 0, 0, 0)[:16]
    name = file_name.encode("utf-16le")
    fn_value = (
        struct.pack("<Q", (parent[1] << 48) | parent[0])
        + struct.pack("<QQQQ", *fn_times)
        + struct.pack("<QQII", 0, 0, 0x20, 0)
        + bytes([len(file_name), 1])
        + name
    )
    attributes = _resident_attribute(0x10, si_value, attr_id=0) + _resident_attribute(
        0x30, fn_value, attr_id=1
    )
    body = attributes + b"\xff\xff\xff\xff" + b"\0" * 4
    usa_count = record_size // 512 + 1
    header = bytearray(56)
    header[0:4] = b"FILE"
    struct.pack_into("<HH", header, 4, 48, usa_count)
    struct.pack_into("<Q", header, 8, lsn)
    struct.pack_into("<HHHHII", header, 16, sequence, 1, 56, 1 if in_use else 0, 56 + len(body), record_size)
    struct.pack_into("<Q", header, 32, 0)
    struct.pack_into("<H", header, 40, 2)
    record = bytearray(record_size)
    record[:56] = header
    record[56 : 56 + len(body)] = body
    usn = b"\x07\x00"
    struct.pack_into("<2s", record, 48, usn)
    for sector in range(usa_count - 1):
        trailer = (sector + 1) * 512 - 2
        original = bytes(record[trailer : trailer + 2])
        record[50 + sector * 2 : 52 + sector * 2] = original
        record[trailer : trailer + 2] = usn
    return bytes(record)


def test_bind_mft_record_resolves_the_si_value_offset_and_identity() -> None:
    record = file_record_bytes(entry=10, sequence=3, lsn=99)

    binding = bind_mft_record(record, entry=10)

    assert binding is not None
    assert binding.si_value_offset == 80
    assert binding.si_value_length == 48
    assert binding.sequence_number == 3
    assert binding.in_use is True
    assert binding.record_lsn == 99
    assert binding.standard_information["created"]["utc"] == "2010-01-01T20:00:00Z"
    assert binding.file_names[0]["name"] == "stomped.txt"
    assert binding.file_names[0]["parent_inode"] == 5
    assert preferred_file_name(binding.file_names)["name"] == "stomped.txt"


def test_bind_mft_record_rejects_non_file_bytes() -> None:
    assert bind_mft_record(b"\0" * 1024, entry=1) is None
    assert bind_mft_record(b"BAAD" + b"\0" * 1020, entry=1) is None


def test_decode_si_update_reads_old_from_undo_and_new_from_redo() -> None:
    redo = struct.pack("<QQQQ", FILETIME_2010, FILETIME_2010, FILETIME_2026_B, FILETIME_2010)
    undo = struct.pack("<QQQQ", FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B)

    decoded = decode_si_timestamp_update(offset_in_target=80, redo=redo, undo=undo, si_value_offset=80)

    assert decoded is not None
    assert decoded["covered_fields"] == ["created", "modified", "record_changed", "accessed"]
    assert decoded["new"]["created"] == FILETIME_2010
    assert decoded["old"]["created"] == FILETIME_2026_B
    assert decoded["update_offset_in_si"] == 0


def test_decode_si_update_covers_only_the_rewritten_fields() -> None:
    redo = struct.pack("<Q", FILETIME_2026_A) + b"\0" * 40
    undo = struct.pack("<Q", FILETIME_2010) + b"\0" * 40

    decoded = decode_si_timestamp_update(offset_in_target=104, redo=redo, undo=undo, si_value_offset=80)

    assert decoded is not None
    assert decoded["covered_fields"] == ["accessed"]
    assert decoded["old"]["accessed"] == FILETIME_2010
    assert decoded["new"]["accessed"] == FILETIME_2026_A
    assert decoded["update_offset_in_si"] == 24
    decoded = decode_si_timestamp_update(
        offset_in_target=88,
        redo=struct.pack("<Q", FILETIME_2017),
        undo=struct.pack("<Q", FILETIME_2026_B),
        si_value_offset=80,
    )
    assert decoded is not None and decoded["covered_fields"] == ["modified"]
    assert decode_si_timestamp_update(offset_in_target=144, redo=b"\0" * 8, undo=b"\0" * 8, si_value_offset=80) is None
    assert decode_si_timestamp_update(offset_in_target=84, redo=b"\0" * 4, undo=b"\0" * 4, si_value_offset=80) is None


def _driver_record(
    *,
    lsn: int,
    entry: int,
    offset: int,
    redo: bytes = b"",
    undo: bytes = b"",
    name: str = "UpdateResidentValue",
    transaction_id: int = 24,
    forgotten: int | None = 1_000_000,
) -> dict[str, object]:
    return {
        "lsn": lsn,
        "transaction_id": transaction_id,
        "redo_operation_name": name,
        "undo_operation_name": name,
        "mft_target_number": entry,
        "offset_in_target": offset,
        "target_block_size": 2,
        "redo_hex": redo.hex(),
        "undo_hex": undo.hex(),
        "transaction_forgotten_lsn": forgotten,
        "transaction_rolled_back": False,
    }


def test_partial_si_bytes_remain_partial_and_default_decoder_is_unchanged():
    old = bytes.fromhex("cbc827773145dd01")
    new = bytes.fromhex("cb08be4c6844dd01")
    for offset in range(1, 8):
        decoded = decode_si_timestamp_update(offset_in_target=88 + offset,
            redo=new[offset:], undo=old[offset:], si_value_offset=80,
            include_timestamp_fragments=True)
        assert decoded["old"] == decoded["new"] == {}
        assert decoded["covered_fields"] == []
        assert decoded["si_timestamp_fragments"] == [{"field": "modified", "byte_order": "little",
            "field_width_bytes": 8, "offset_in_field": offset,
            "undo_hex": old[offset:].hex(), "redo_hex": new[offset:].hex()}]
    assert decode_si_timestamp_update(offset_in_target=89, redo=new[1:], undo=old[1:], si_value_offset=80) is None


def test_partial_write_crossing_si_field_boundary_has_two_bounded_fragments():
    decoded = decode_si_timestamp_update(offset_in_target=94, redo=b"\x01" * 4,
        undo=b"\x02" * 4, si_value_offset=80, include_timestamp_fragments=True)
    assert [(f["field"], f["offset_in_field"], len(bytes.fromhex(f["redo_hex"])))
            for f in decoded["si_timestamp_fragments"]] == [("modified", 6, 2), ("record_changed", 0, 2)]


def test_partial_si_update_keeps_native_lifecycle_and_sequence_gates(tmp_path):
    mft = tmp_path / "$MFT"
    mft.write_bytes(b"\0" * 1024 + file_record_bytes(entry=1, sequence=3, lsn=900))
    update = _driver_record(lsn=500, entry=1, offset=89,
        redo=bytes.fromhex("08be4c6844dd01"), undo=bytes.fromhex("c827773145dd01"))
    rows, _ = si_updates_from_records([update], mft_path=mft, include_timestamp_fragments=True)
    assert rows[0]["si_timestamp_fragments"][0]["field"] == "modified"
    reuse = _driver_record(lsn=800, entry=1, offset=0, name="InitializeFileRecordSegment")
    rows, diagnostics = si_updates_from_records([update, reuse], mft_path=mft, include_timestamp_fragments=True)
    assert not rows and diagnostics["unbound_reasons"] == {"entry_reinitialised_after_update": 1}


def test_si_updates_bind_only_to_current_in_use_records(tmp_path: Path) -> None:
    mft = tmp_path / "$MFT"
    table = bytearray(1024 * 13)
    table[10 * 1024 : 11 * 1024] = file_record_bytes(entry=10, sequence=3, lsn=900)
    table[11 * 1024 : 12 * 1024] = file_record_bytes(entry=11, sequence=9, lsn=900, file_name="reused.txt")
    table[12 * 1024 : 13 * 1024] = file_record_bytes(entry=12, sequence=2, in_use=False, file_name="freed.txt")
    mft.write_bytes(bytes(table))
    stomp_redo = struct.pack("<QQQQ", FILETIME_2010, FILETIME_2010, FILETIME_2026_B, FILETIME_2010)
    stomp_undo = struct.pack("<QQQQ", FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B)
    records = [
        _driver_record(lsn=500, entry=10, offset=80, redo=stomp_redo, undo=stomp_undo),
        _driver_record(lsn=510, entry=10, offset=144, redo=b"\0" * 8, undo=b"\1" * 8),
        _driver_record(lsn=600, entry=11, offset=80, redo=stomp_redo, undo=stomp_undo),
        _driver_record(lsn=650, entry=11, offset=0, name="InitializeFileRecordSegment"),
        _driver_record(lsn=700, entry=12, offset=80, redo=stomp_redo, undo=stomp_undo),
        _driver_record(lsn=800, entry=5, offset=80, redo=stomp_redo, undo=stomp_undo),
        _driver_record(lsn=900, entry=10, offset=104, redo=struct.pack("<Q", FILETIME_2026_A) + b"\0" * 40, undo=struct.pack("<Q", FILETIME_2010) + b"\0" * 40, forgotten=None),
        _driver_record(lsn=950, entry=10, offset=80, redo=stomp_redo, undo=stomp_undo),
    ]

    updates, diagnostics = si_updates_from_records(records, mft_path=mft, mft_entry_sequences={10: (3, True), 11: (9, True)})

    assert diagnostics == {
        "si_update_count": 6,
        "bound_count": 2,
        "unbound_count": 4,
        "unbound_reasons": {
            "entry_reinitialised_after_update": 1,
            "record_lsn_precedes_update": 1,
            "record_not_in_use": 1,
            "record_unreadable": 1,
        },
    }
    first, second = updates
    assert (first["lsn"], first["mft_entry"], first["sequence_number"]) == (500, 10, 3)
    assert first["covered_fields"] == ["created", "modified", "record_changed", "accessed"]
    assert first["old"]["created"] == "2026-09-12T10:58:26.5463544Z"
    assert first["new"]["created"] == "2010-01-01T20:00:00Z"
    assert first["current_si"]["created"] == "2010-01-01T20:00:00Z"
    assert first["file_names"][0]["name"] == "stomped.txt"
    assert first["transaction_forgotten_lsn"] == 1_000_000
    assert second["lsn"] == 900 and second["covered_fields"] == ["accessed"]
    assert second["old"]["accessed"] == "2010-01-01T20:00:00Z"
    assert second["transaction_forgotten_lsn"] is None


def test_si_updates_skip_records_whose_mft_context_sequence_disagrees(tmp_path: Path) -> None:
    mft = tmp_path / "$MFT"
    table = bytearray(1024 * 11)
    table[10 * 1024 : 11 * 1024] = file_record_bytes(entry=10, sequence=3)
    mft.write_bytes(bytes(table))
    records = [_driver_record(lsn=1, entry=10, offset=80, redo=b"\0" * 32, undo=b"\1" * 32)]

    updates, diagnostics = si_updates_from_records(records, mft_path=mft, mft_entry_sequences={10: (4, True)})

    assert updates == []
    assert diagnostics["unbound_reasons"] == {"mft_context_sequence_disagrees": 1}


def test_read_mft_record_requires_the_file_signature(tmp_path: Path) -> None:
    mft = tmp_path / "$MFT"
    mft.write_bytes(b"\0" * 2048 + file_record_bytes(entry=2, sequence=1))
    with mft.open("rb") as handle:
        assert read_mft_record(handle, 1) is None
        assert read_mft_record(handle, 2) is not None
        assert read_mft_record(handle, 3) is None
        assert read_mft_record(handle, -1) is None


def test_a_log_record_aimed_far_past_the_mft_is_unreadable_not_an_error(tmp_path: Path) -> None:
    # One of 65,597 records in a real $LogFile (macOS guest, I1) parsed as this update; seeking to it raised.
    mft = tmp_path / "$MFT"
    mft.write_bytes(b"\0" * 2048 + file_record_bytes(entry=2, sequence=1))
    garbage = dict(_driver_record(lsn=3917479929, entry=2253688922204337, offset=89905, redo=b"\0" * 38),
                   target_block_size=475)
    with mft.open("rb") as handle:
        assert read_mft_record(handle, 2253688922204337, record_size=475 * 512) is None
        assert read_mft_record(handle, 2) is not None

    updates, diagnostics = si_updates_from_records([garbage], mft_path=mft)

    assert updates == []
    assert diagnostics["unbound_reasons"] == {"record_unreadable": 1}
