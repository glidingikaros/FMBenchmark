from __future__ import annotations

import csv
import struct
import zlib

import pytest

from fmb.analysis.catalog import TECHNIQUES
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.index.adapters.registry import (
    shellbag_csv_files,
    shellbag_parser_run,
)
from fmb.index.adapters.stream_content import executable_content_fields
from fmb.index.scanners.evtx_sequence import retained_record_ids
from fmb.index.scanners.zip_content import zip_content_fields
from paper_fixtures import projected_input


def record(kind, fields, *, path=r"C:\Records\item", family="ntfs.file_size_allocation", identifier="row1"):
    return {"observation_id": identifier, "artifact_family": family, "observation_type": kind,
            "subject_ref": path, "fields": fields, "source_record_ref": "native-fixture:" + identifier}


def assess(technique, records):
    definition = next(item for item in TECHNIQUES if item.technique_id == technique)
    index = {"schema_version": "evidence_index.v1", "run_id": "native-fixture",
             "artifact_coverage": [{"artifact_family": family, "status": "complete"}
                          for family in definition.required_artifact_families],
             "parser_runs": [{"parser_kind": "ntfs_mft", "status": "consumed",
                              "coverage_status": "complete", "observations": records}]}
    value = build_analysis_input(index, definition)
    result = analyze_input(value)
    return value, result.assessments[0].outcome


def allocation_fields(**changes):
    return {"mft_entry": 42, "sequence_number": 3, "mft_volume_id": "volume:test",
            "stream_name": "", "native_identity_verified": True,
            "attribute_chain_complete": True, "resident_status": "nonresident",
            "is_sparse": False, "is_compressed": False, "is_encrypted": False,
            "logical_size": 4097, "allocated_size": 8192, "allocated_cluster_count": 2,
            "bytes_per_cluster": 4096, "geometry_source": "native_ntfs_boot_sector",
            "runlist_complete": True, "runlist_in_volume": True, "lowest_vcn": 0,
            "runlist_physical_overlap": False,
            "sparse_cluster_count": 0, **changes}


@pytest.mark.parametrize(("changes", "outcome"), [
    ({}, "not_supported"),
    ({"allocated_size": 16384, "allocated_cluster_count": 4}, "not_supported"),
    ({"resident_status": "resident", "logical_size": 20}, "not_supported"),
    ({"allocated_size": 4097}, "supported"),
    ({"allocated_size": 4096}, "supported"),
    ({"logical_size": 8193}, "supported"),
    ({"is_sparse": True}, "indeterminate"),
    ({"is_compressed": True}, "indeterminate"),
    ({"is_encrypted": True}, "indeterminate"),
    ({"runlist_in_volume": False}, "indeterminate"),
    ({"runlist_physical_overlap": True}, "supported"),
    ({"runlist_physical_overlap": None}, "indeterminate"),
    ({"bytes_per_cluster": True}, "indeterminate"),
    ({"native_identity_verified": False}, "indeterminate"),
])
def test_allocation_rounding_preallocation_and_unknown_storage(changes, outcome):
    _, actual = assess("ntfs_allocation_inconsistency", [record("ntfs_allocation_record", allocation_fields(**changes))])
    assert actual == outcome


def pe_bytes():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0xaa64, 1)
    struct.pack_into("<HH", data, 148, 240, 2)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<I", data, 212, 512)
    struct.pack_into("<II", data, 408, 512, 512)
    struct.pack_into("<I", data, 428, 0x60000020)
    return bytes(data)


def ads_records(data, **content_changes):
    identity = {"mft_entry": 42, "sequence_number": 3, "mft_volume_id": "volume:test"}
    return [record("named_data_stream", {**identity, "stream_name": "shared_name", "stream_size": len(data)},
                   family="ntfs.ads", identifier="stream"),
            record("named_stream_content", {**identity, "stream_name": "shared_name", "stream_size": len(data),
                "native_identity_verified": True, "content_complete": True,
                **executable_content_fields(data), **zip_content_fields(data), **content_changes}, family="ntfs.ads", identifier="content")]


def test_ads_requires_content_and_does_not_use_rarity():
    value, outcome = assess("alternate_data_stream", ads_records(pe_bytes()))
    assert outcome == "supported"
    packet = projected_input(value)
    assert "pe_sections" in str(packet)
    assert "named_stream_contains_pe_executable_structure" not in str(packet)
    for data in (b"[ZoneTransfer]\r\nZoneId=3\r\n", b'{"application":"viewer"}', b""):
        _, outcome = assess("alternate_data_stream", ads_records(data))
        assert outcome == "not_supported"
    _, outcome = assess("alternate_data_stream", ads_records(pe_bytes(), content_complete=False))
    assert outcome == "indeterminate"


def test_ads_rejects_truncated_pe_and_out_of_file_sections():
    for data in (b"MZ", pe_bytes()[:700]):
        _, outcome = assess("alternate_data_stream", ads_records(data))
        assert outcome == "indeterminate"


def _pe_with(offset, fmt, value, data=None):
    data = bytearray(data or pe_bytes())
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


HEADER = {"pe_header_offset": 128, "pe_signature_hex": "50450000", "pe_machine": 0xaa64,
          "pe_section_count": 1, "pe_optional_header_size": 240, "pe_characteristics": 2}


@pytest.mark.parametrize(("data", "expected"), [
    (b"MZ" + b"document_revision=3;application=records" * 2, {"pe_header_offset": 1886413115}),
    (_pe_with(0x3c, "<I", 4096), {"pe_header_offset": 4096}),
    (_pe_with(0x3c, "<I", 32), {"pe_header_offset": 32}),
    (_pe_with(128, "<I", 0x454e), {"pe_header_offset": 128, "pe_signature_hex": "4e450000"}),
    (_pe_with(134, "<H", 0), {**HEADER, "pe_section_count": 0}),
    (_pe_with(148, "<H", 32), {**HEADER, "pe_optional_header_size": 32}),
    (pe_bytes()[:420], HEADER),
    (_pe_with(152, "<H", 0x107), {**HEADER, "pe_optional_magic": 0x107, "pe_size_of_headers": 512}),
    (_pe_with(212, "<I", 4096), {**HEADER, "pe_optional_magic": 0x20b, "pe_size_of_headers": 4096}),
    (_pe_with(412, "<I", 1000), {**HEADER, "pe_optional_magic": 0x20b, "pe_size_of_headers": 512}),
])
def test_pe_decoys_keep_their_partial_header_measurements(data, expected):
    fields = executable_content_fields(data)
    assert fields["pe_structure_status"] == "incomplete_or_malformed"
    assert {key: value for key, value in fields.items() if key.startswith("pe_") and key != "pe_structure_status"} == expected


def test_empty_pe_section_needs_no_file_range():
    data = _pe_with(412, "<I", 0xFFFFFFF0, _pe_with(408, "<I", 0))
    fields = executable_content_fields(data)
    assert fields["pe_structure_status"] == "complete"
    assert fields["pe_sections"] == [{"raw_size": 0, "raw_offset": 0xFFFFFFF0, "characteristics": 0x60000020}]


@pytest.mark.parametrize("case_directory", ["positive", "benign"])
def test_native_shellbag_discovery_and_path_absence(tmp_path, case_directory):
    tmp_path = tmp_path / case_directory
    tmp_path.mkdir()
    path = tmp_path / "vagrant_UsrClass.csv"
    with path.open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=["AbsolutePath", "BagPath", "ShellType", "HasExplored"])
        writer.writeheader()
        writer.writerow({"AbsolutePath": r"Desktop\My Computer\C:\Records\folder", "BagPath": r"BagMRU\0\2",
                         "ShellType": "Directory", "HasExplored": "True"})
        writer.writerow({"AbsolutePath": r"Desktop\Control Panel", "BagPath": "BagMRU", "ShellType": "Root folder: GUID"})
    assert shellbag_csv_files(tmp_path) == [path]
    parsed = shellbag_parser_run(csv_path=path, normalized_output_dir=tmp_path,
        collector_run={"collector": "kape"}, mft_context={"row_count": 1,
            "mft_volume_id": "volume:test", "indexed_volumes": {"c"},
            "path_absence_check_supported": True, "active_full_paths": set()})
    assert len(parsed["observations"]) == 1
    value, outcome = assess("shellbag_missing_directory", parsed["observations"])
    assert outcome == "supported"
    packet = projected_input(value)
    fields = packet["candidate_roster"][0]["evidence_records"][0]["fields"]
    assert "active_mft_lookup" in fields
    assert fields["path"] == r"C:\Records\folder"
    assert fields["bag_path"] == r"BagMRU\0\2"
    assert fields["shell_type"] == "Directory"
    assert fields["source_parser"] == "SBECmd"
    assert "source_file" not in fields
    assert str(tmp_path) not in str(packet)
    assert parsed["observations"][0]["fields"]["source_file"] == str(path)
    parsed["observations"][0]["fields"]["shell_type"] = "Root folder: GUID"
    assert assess("shellbag_missing_directory", parsed["observations"])[1] == "indeterminate"


def evtx_bytes(identifiers):
    data = bytearray(4096 + 65536)
    data[:8] = b"ElfFile\0"
    struct.pack_into("<IHHHI", data, 32, 128, 2, 3, 4096, 1)
    struct.pack_into("<I", data, 124, zlib.crc32(data[:120]))
    chunk = memoryview(data)[4096:]
    chunk[:8] = b"ElfChnk\0"
    struct.pack_into("<QQ", chunk, 24, identifiers[0], identifiers[-1])
    struct.pack_into("<I", chunk, 40, 128)
    position = 512
    for identifier in identifiers:
        last = position
        struct.pack_into("<4sIQQ4sI", chunk, position, b"**\0\0", 32, identifier, 1, b"test", 32)
        position += 32
    struct.pack_into("<III", chunk, 44, last, position, zlib.crc32(chunk[512:position]))
    struct.pack_into("<I", chunk, 124, zlib.crc32(bytes(chunk[:120]) + bytes(chunk[128:512])))
    return bytes(data)


def test_retained_evtx_inventory_excludes_slack_and_detects_corruption():
    data = evtx_bytes([200, 202, 203])
    assert retained_record_ids(data) == (200, 202, 203)
    damaged = bytearray(data)
    damaged[-32:] = data[4096 + 512:4096 + 544]
    assert retained_record_ids(bytes(damaged)) == (200, 202, 203)
    damaged[4096 + 540] ^= 1
    with pytest.raises(ValueError, match="checksum"):
        retained_record_ids(bytes(damaged))


