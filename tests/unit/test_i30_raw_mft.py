from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from fmb.analysis.catalog import techniques_for_question
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input, canonical_sha256
from fmb.analysis.population_binding import (
    BOUNDED_POPULATION_CONTRACT_SHA256,
    bind_population_manifest,
)
from fmb.index.adapters.i30 import bounded_i30_parser_run
from fmb.index.kape.sources import scan_kape_output_root
from fmb.index.scanners.mft import (
    ATTRIBUTE_LIST_ATTR_TYPE,
    DEFAULT_MFT_RECORD_SIZE,
    FILE_NAME_ATTR_TYPE,
    INDEX_ROOT_ATTR_TYPE,
    MFT_RECORD_DIRECTORY_FLAG,
    MFT_RECORD_IN_USE_FLAG,
    parse_directory_i30_record,
)


def _file_name_value(
    name: str,
    *,
    parent_entry: int,
    parent_sequence: int,
) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    struct.pack_into(
        "<Q", value, 0, parent_entry | (parent_sequence << 48)
    )
    value[64] = len(name)
    value[65] = 1
    value[66:] = encoded
    return bytes(value)


def _resident_attribute(attr_type: int, value: bytes, *, attr_id: int) -> bytes:
    length = 24 + len(value)
    attribute = bytearray(length)
    struct.pack_into("<II", attribute, 0, attr_type, length)
    struct.pack_into("<H", attribute, 14, attr_id)
    struct.pack_into("<I", attribute, 16, len(value))
    struct.pack_into("<H", attribute, 20, 24)
    attribute[24:] = value
    return bytes(attribute)


def _index_entry(
    name: str,
    *,
    entry: int,
    sequence: int,
    parent_entry: int,
    parent_sequence: int,
) -> bytes:
    key = _file_name_value(
        name,
        parent_entry=parent_entry,
        parent_sequence=parent_sequence,
    )
    length = (16 + len(key) + 7) & ~7
    value = bytearray(length)
    struct.pack_into("<QHH", value, 0, entry | (sequence << 48), length, len(key))
    value[16 : 16 + len(key)] = key
    return bytes(value)


def _index_root_value(*entries: bytes) -> bytes:
    end = bytearray(16)
    struct.pack_into("<H", end, 8, len(end))
    struct.pack_into("<H", end, 12, 2)
    body = b"".join((*entries, bytes(end)))
    value = bytearray(32 + len(body))
    struct.pack_into("<III", value, 0, FILE_NAME_ATTR_TYPE, 1, 4096)
    struct.pack_into("<III", value, 16, 16, 16 + len(body), 16 + len(body))
    value[32:] = body
    return bytes(value)


def _directory_record(*, entry: int, sequence: int) -> bytearray:
    record = bytearray(DEFAULT_MFT_RECORD_SIZE)
    record[:4] = b"FILE"
    struct.pack_into("<H", record, 16, sequence)
    struct.pack_into("<H", record, 20, 56)
    struct.pack_into(
        "<H",
        record,
        22,
        MFT_RECORD_IN_USE_FLAG | MFT_RECORD_DIRECTORY_FLAG,
    )
    struct.pack_into("<I", record, 44, entry)
    return record


def _finish_record(record: bytearray, attributes: list[bytes]) -> int:
    cursor = 56
    for attribute in attributes:
        record[cursor : cursor + len(attribute)] = attribute
        cursor += len(attribute)
    struct.pack_into("<I", record, cursor, 0xFFFFFFFF)
    used_size = cursor + 4
    struct.pack_into("<I", record, 24, used_size)
    return used_size


def test_directory_i30_parser_distinguishes_index_root_from_record_slack() -> None:
    directory_entry = 42
    directory_sequence = 3
    live = _index_entry(
        "live.txt",
        entry=100,
        sequence=1,
        parent_entry=directory_entry,
        parent_sequence=directory_sequence,
    )
    removed = _index_entry(
        "removed.txt",
        entry=101,
        sequence=7,
        parent_entry=directory_entry,
        parent_sequence=directory_sequence,
    )
    attributes = [
        _resident_attribute(
            FILE_NAME_ATTR_TYPE,
            _file_name_value(
                "evidence-dir",
                parent_entry=5,
                parent_sequence=1,
            ),
            attr_id=1,
        ),
        _resident_attribute(
            INDEX_ROOT_ATTR_TYPE,
            _index_root_value(live),
            attr_id=2,
        ),
    ]
    record = _directory_record(entry=directory_entry, sequence=directory_sequence)
    used_size = _finish_record(record, attributes)
    slack_offset = (used_size + 7) & ~7
    record[slack_offset : slack_offset + len(removed)] = removed

    parsed = parse_directory_i30_record(
        bytes(record),
        record_offset=directory_entry * DEFAULT_MFT_RECORD_SIZE,
        record_size=DEFAULT_MFT_RECORD_SIZE,
    )

    assert parsed is not None
    assert parsed["mft_entry"] == directory_entry
    assert parsed["sequence_number"] == directory_sequence
    assert parsed["is_active_directory"] is True
    assert parsed["index_allocation_parsed"] is False
    assert parsed["index_root_present"] is True
    assert parsed["index_root_parsed"] is True
    assert [item["name"] for item in parsed["resident_index_root_entries"]] == [
        "live.txt"
    ]
    assert [item["name"] for item in parsed["record_slack_entries"]] == [
        "removed.txt"
    ]
    assert parsed["record_slack_entries"][0]["file_reference_entry"] == 101
    assert parsed["record_slack_entries"][0]["file_reference_sequence"] == 7
    assert parsed["record_slack_entries"][0]["residue_surface"] == "record_slack"


@pytest.mark.parametrize("attribute_list_present", [False, True])
def test_exact_i30_scope_rejects_missing_or_relocated_index_root(
    tmp_path: Path,
    attribute_list_present: bool,
) -> None:
    directory_path = r"C:\Users\alice\Documents\incomplete-directory"
    directory = _directory_record(entry=42, sequence=3)
    attributes = [
        _resident_attribute(
            FILE_NAME_ATTR_TYPE,
            _file_name_value(
                "incomplete-directory", parent_entry=5, parent_sequence=1
            ),
            attr_id=1,
        )
    ]
    if attribute_list_present:
        attributes.append(
            _resident_attribute(ATTRIBUTE_LIST_ATTR_TYPE, b"relocated", attr_id=2)
        )
    _finish_record(directory, attributes)
    mft_bytes = bytearray(43 * DEFAULT_MFT_RECORD_SIZE)
    _write_record(mft_bytes, 42, directory)
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(mft_bytes)
    csv_path = tmp_path / "MFTECmd_$MFT_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
        r"42,3,True,.\Users\alice\Documents,incomplete-directory,True"
        "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="INDEX_ROOT"):
        bounded_i30_parser_run(
            mft_csv_path=csv_path,
            raw_mft_path=raw_mft_path,
            directory_paths=(directory_path,),
            normalized_output_dir=tmp_path / "exact-normalized",
            collector_run={"collector": "kape", "provenance": {}},
        )

    unscoped = bounded_i30_parser_run(
        mft_csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        directory_paths=None,
        normalized_output_dir=tmp_path / "unscoped-normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert unscoped["coverage_status"] == "partial"
    assert unscoped["observations"] == []


def _write_record(mft: bytearray, entry: int, record: bytes) -> None:
    offset = entry * DEFAULT_MFT_RECORD_SIZE
    mft[offset : offset + DEFAULT_MFT_RECORD_SIZE] = record


def test_bounded_i30_adapter_emits_complete_scans_and_directory_bound_residue(
    tmp_path: Path,
) -> None:
    manipulated_path = r"C:\Users\vagrant\Documents\d_manipulated"
    neutral_path = r"C:\Users\vagrant\Documents\d_neutral"
    manipulated = _directory_record(entry=42, sequence=3)
    used_size = _finish_record(
        manipulated,
        [
            _resident_attribute(
                FILE_NAME_ATTR_TYPE,
                _file_name_value(
                    "d_manipulated", parent_entry=10, parent_sequence=1
                ),
                attr_id=1,
            ),
            _resident_attribute(
                INDEX_ROOT_ATTR_TYPE,
                _index_root_value(),
                attr_id=2,
            ),
        ],
    )
    removed = _index_entry(
        "removed.txt",
        entry=101,
        sequence=7,
        parent_entry=42,
        parent_sequence=3,
    )
    slack_offset = (used_size + 7) & ~7
    struct.pack_into("<H", manipulated, slack_offset + 12, 2)
    removed_offset = slack_offset + 24
    manipulated[removed_offset : removed_offset + len(removed)] = removed

    neutral = _directory_record(entry=43, sequence=4)
    _finish_record(
        neutral,
        [
                _resident_attribute(
                    FILE_NAME_ATTR_TYPE,
                    _file_name_value("d_neutral", parent_entry=10, parent_sequence=1),
                    attr_id=1,
                ),
                _resident_attribute(
                    INDEX_ROOT_ATTR_TYPE,
                    _index_root_value(),
                    attr_id=2,
                ),
        ],
    )
    reused_child = _directory_record(entry=101, sequence=8)
    struct.pack_into("<H", reused_child, 22, MFT_RECORD_IN_USE_FLAG)
    _finish_record(
        reused_child,
        [
            _resident_attribute(
                FILE_NAME_ATTR_TYPE,
                _file_name_value("replacement.txt", parent_entry=43, parent_sequence=4),
                attr_id=1,
            )
        ],
    )

    mft_bytes = bytearray(102 * DEFAULT_MFT_RECORD_SIZE)
    _write_record(mft_bytes, 42, manipulated)
    _write_record(mft_bytes, 43, neutral)
    _write_record(mft_bytes, 101, reused_child)
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(mft_bytes)
    csv_path = tmp_path / "MFTECmd_$MFT_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
        r"42,3,True,.\Users\vagrant\Documents,d_manipulated,True"
        "\n"
        r"43,4,True,.\Users\vagrant\Documents,d_neutral,True"
        "\n",
        encoding="utf-8",
    )

    run = bounded_i30_parser_run(
        mft_csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        directory_paths=(manipulated_path, neutral_path),
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["parser"] == "fmb_bounded_parser"
    assert run["parser_kind"] == "ntfs_i30"
    assert run["coverage_status"] == "complete"
    scans = [
        item
        for item in run["observations"]
        if item["observation_type"] == "i30_directory_scan"
    ]
    residues = [
        item
        for item in run["observations"]
        if item["observation_type"] == "i30_filename_residue"
    ]
    assert len(scans) == 2
    assert {item["subject_ref"] for item in scans} == {
        manipulated_path,
        neutral_path,
    }
    neutral_scan = next(item for item in scans if item["subject_ref"] == neutral_path)
    assert neutral_scan["fields"]["residue_count"] == 0
    assert neutral_scan["fields"]["scan_complete"] is True
    assert len(residues) == 1
    residue = residues[0]
    assert residue["subject_ref"] == manipulated_path
    assert residue["fields"]["mft_entry"] == 42
    assert residue["fields"]["sequence_number"] == 3
    assert residue["fields"]["file_reference_entry"] == 101
    assert residue["fields"]["file_reference_sequence"] == 7
    assert residue["fields"]["mft_active_presence_status"] == "active_mft_absent"
    assert residue["fields"]["mft_active_presence_basis"] == "file_reference_entry_reused"
    assert residue["fields"]["mft_lookup_target"] == {
        "mft_volume_id": residue["fields"]["mft_volume_id"],
        "object_id": f"ntfs:{residue['fields']['mft_volume_id']}:101:7",
        "target_role": "referenced_object",
    }
    assert residue["fields"]["mft_lookup_observed"]["entry"] == 101
    assert residue["fields"]["mft_lookup_observed"]["sequence"] != 7
    assert isinstance(residue["fields"]["mft_lookup_observed"]["in_use"], bool)
    assert residue["fields"]["index_allocation_parsed"] is False

    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "bounded-i30",
        "parser_runs": [
            run,
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": [],
            },
        ],
    }
    members = [
        {
            "candidate_id": f"candidate:i30-{index}",
            "subject_ref": path,
            "subject_type": "directory_entry",
            "identity_hint": {
                "canonical_path": path.casefold(),
                "canonical_name": path.rsplit("\\", 1)[-1],
            },
        }
        for index, path in enumerate((manipulated_path, neutral_path), start=1)
    ]
    manifest = {
        "schema_version": "population_manifest.v1",
        "experiment": "full_scale",
        "contract_sha256": BOUNDED_POPULATION_CONTRACT_SHA256,
        "expected_completeness": "complete",
        "declared_count": len(members),
        "scenarios": {
            "directory_cleaning_i30_01": {
                "question_id": "Q-DEL-03",
                "technique_id": "i30_directory_residue",
                "subject_type": "directory_entry",
                "expected_completeness": "complete",
                "declared_count": len(members),
                "members": members,
            }
        },
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = build_analysis_input(
        bound,
        techniques_for_question("Q-DEL-03")[0],
    )
    result = analyze_input(analysis_input)
    assessments = {
        subject.display_name: assessment
        for subject, assessment in zip(
            analysis_input.candidate_roster.subjects,
            result.assessments,
            strict=True,
        )
    }
    assert assessments[manipulated_path].outcome == "supported"
    assert assessments[neutral_path].outcome == "not_supported"
    assert assessments[neutral_path].reason_code == (
        "i30_supported_surface_has_no_residue"
    )
    assert result.supported_subjects.subject_ids == (
        next(
            subject.subject_id
            for subject in analysis_input.candidate_roster.subjects
            if subject.display_name == manipulated_path
        ),
    )


@pytest.mark.parametrize(
    (
        "child_record_state",
        "expected_check_supported",
        "expected_status",
        "expected_basis",
        "expected_outcome",
    ),
    [
        (
            "outside_source",
            False,
            "unknown",
            "file_reference_record_outside_source",
            "indeterminate",
        ),
        (
            "never_allocated",
            False,
            "unknown",
            "file_reference_record_never_allocated",
            "indeterminate",
        ),
        (
            "free",
            True,
            "active_mft_absent",
            "file_reference_record_free",
            "supported",
        ),
    ],
)
def test_i30_active_presence_requires_a_parseable_allocated_child_record(
    tmp_path: Path,
    child_record_state: str,
    expected_check_supported: bool,
    expected_status: str,
    expected_basis: str,
    expected_outcome: str,
) -> None:
    directory_path = r"C:\Users\alice\Documents\case-directory"
    directory_entry = 42
    directory_sequence = 3
    child_entry = 50
    child_sequence = 7
    directory = _directory_record(
        entry=directory_entry,
        sequence=directory_sequence,
    )
    used_size = _finish_record(
        directory,
        [
            _resident_attribute(
                FILE_NAME_ATTR_TYPE,
                _file_name_value(
                    "case-directory", parent_entry=5, parent_sequence=1
                ),
                attr_id=1,
            ),
            _resident_attribute(
                INDEX_ROOT_ATTR_TYPE,
                _index_root_value(),
                attr_id=2,
            ),
        ],
    )
    removed = _index_entry(
        "removed.txt",
        entry=child_entry,
        sequence=child_sequence,
        parent_entry=directory_entry,
        parent_sequence=directory_sequence,
    )
    slack_offset = (used_size + 7) & ~7
    directory[slack_offset : slack_offset + len(removed)] = removed

    record_count = 43 if child_record_state == "outside_source" else 51
    mft_bytes = bytearray(record_count * DEFAULT_MFT_RECORD_SIZE)
    _write_record(mft_bytes, directory_entry, directory)
    if child_record_state == "free":
        child = _directory_record(entry=child_entry, sequence=child_sequence)
        struct.pack_into("<H", child, 22, 0)
        _finish_record(
            child,
            [
                _resident_attribute(
                    FILE_NAME_ATTR_TYPE,
                    _file_name_value(
                        "removed.txt",
                        parent_entry=directory_entry,
                        parent_sequence=directory_sequence,
                    ),
                    attr_id=1,
                )
            ],
        )
        _write_record(mft_bytes, child_entry, child)

    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(mft_bytes)
    csv_path = tmp_path / "MFTECmd_$MFT_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
        r"42,3,True,.\Users\alice\Documents,case-directory,True"
        "\n",
        encoding="utf-8",
    )
    run = bounded_i30_parser_run(
        mft_csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        directory_paths=(directory_path,),
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    residue = next(
        item
        for item in run["observations"]
        if item["observation_type"] == "i30_filename_residue"
    )
    assert residue["fields"]["mft_active_presence_check_supported"] is (
        expected_check_supported
    )
    assert residue["fields"]["mft_active_presence_status"] == expected_status
    assert residue["fields"]["mft_active_presence_basis"] == expected_basis

    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": f"i30-{child_record_state}",
        "parser_runs": [
            run,
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": [],
            },
        ],
    }
    member = {
        "candidate_id": f"candidate:i30-{child_record_state}",
        "subject_ref": directory_path,
        "subject_type": "directory_entry",
        "identity_hint": {
            "canonical_path": directory_path.casefold(),
            "canonical_name": "case-directory",
        },
    }
    manifest = {
        "schema_version": "population_manifest.v1",
        "experiment": "full_scale",
        "contract_sha256": BOUNDED_POPULATION_CONTRACT_SHA256,
        "expected_completeness": "complete",
        "declared_count": 1,
        "scenarios": {
            "directory_cleaning_i30_01": {
                "question_id": "Q-DEL-03",
                "technique_id": "i30_directory_residue",
                "subject_type": "directory_entry",
                "expected_completeness": "complete",
                "declared_count": 1,
                "members": [member],
            }
        },
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = build_analysis_input(
        bound,
        techniques_for_question("Q-DEL-03")[0],
    )
    result = analyze_input(analysis_input)

    assert result.assessments[0].outcome == expected_outcome


def test_unscoped_i30_discovery_reports_complete_empty_and_partial_bounds(
    tmp_path: Path,
) -> None:
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(bytes(DEFAULT_MFT_RECORD_SIZE))
    empty_csv = tmp_path / "empty-mft.csv"
    empty_csv.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n",
        encoding="utf-8",
    )

    empty = bounded_i30_parser_run(
        mft_csv_path=empty_csv,
        raw_mft_path=raw_mft_path,
        directory_paths=None,
        max_directories=1,
        normalized_output_dir=tmp_path / "empty-normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert empty["parser_kind"] == "ntfs_i30"
    assert empty["coverage_status"] == "complete"
    assert empty["observation_count"] == 0

    csv_path = tmp_path / "bounded-mft.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
        r"42,3,True,.\ProgramData,cache,True"
        "\n"
        r"43,4,True,.\Users\alice\Documents,case,True"
        "\n",
        encoding="utf-8",
    )
    mft_bytes = bytearray(44 * DEFAULT_MFT_RECORD_SIZE)
    for entry, sequence, name in ((42, 3, "cache"), (43, 4, "case")):
        record = _directory_record(entry=entry, sequence=sequence)
        used_size = _finish_record(
            record,
            [
                    _resident_attribute(
                        FILE_NAME_ATTR_TYPE,
                        _file_name_value(name, parent_entry=5, parent_sequence=1),
                        attr_id=1,
                    ),
                    _resident_attribute(
                        INDEX_ROOT_ATTR_TYPE,
                        _index_root_value(),
                        attr_id=2,
                    ),
            ],
        )
        residue = _index_entry(
            f"removed-{entry}.txt",
            entry=entry + 100,
            sequence=1,
            parent_entry=entry,
            parent_sequence=sequence,
        )
        residue_offset = (used_size + 7) & ~7
        record[residue_offset : residue_offset + len(residue)] = residue
        _write_record(mft_bytes, entry, record)
    raw_mft_path.write_bytes(mft_bytes)

    partial = bounded_i30_parser_run(
        mft_csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        directory_paths=None,
        max_directories=1,
        normalized_output_dir=tmp_path / "partial-normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert partial["coverage_status"] == "partial"
    assert partial["observation_count"] == 2
    assert partial["observations"][0]["observation_type"] == "i30_directory_scan"
    assert partial["observations"][1]["observation_type"] == (
        "i30_filename_residue"
    )
    assert partial["observations"][0]["subject_ref"] == (
        r".\Users\alice\Documents\case"
    )
    normalized = json.loads(
        Path(partial["normalized_output"]["path"]).read_text(encoding="utf-8")
    )
    assert normalized["scanned_directory_count"] == 2
    assert normalized["residue_directory_count"] == 2
    assert normalized["retained_residue_directory_count"] == 1


def test_kape_discovery_replaces_missing_i30_module_with_raw_mft_projection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "kape-output"
    raw_mft_path = root / "targets" / "F" / "$MFT"
    raw_mft_path.parent.mkdir(parents=True)
    directory_path = r"C:\Users\alice\Documents\case-directory"
    directory = _directory_record(entry=42, sequence=3)
    _finish_record(
        directory,
        [
                _resident_attribute(
                    FILE_NAME_ATTR_TYPE,
                    _file_name_value(
                        "case-directory", parent_entry=5, parent_sequence=1
                    ),
                    attr_id=1,
                ),
                _resident_attribute(
                    INDEX_ROOT_ATTR_TYPE,
                    _index_root_value(),
                    attr_id=2,
                ),
        ],
    )
    mft_bytes = bytearray(43 * DEFAULT_MFT_RECORD_SIZE)
    _write_record(mft_bytes, 42, directory)
    raw_mft_path.write_bytes(mft_bytes)
    csv_path = root / "modules" / "FileSystem" / "MFTECmd_$MFT_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
        r"42,3,True,.\Users\alice\Documents,case-directory,True"
        "\n",
        encoding="utf-8",
    )

    runs = scan_kape_output_root(
        root=root,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}, "artifacts": []},
        bounded_i30_directory_paths=(directory_path,),
    )

    i30_runs = [item for item in runs if item.get("parser_kind") == "ntfs_i30"]
    assert len(i30_runs) == 1
    assert i30_runs[0]["parser"] == "fmb_bounded_parser"
    assert i30_runs[0]["coverage_status"] == "complete"
    assert [
        item["observation_type"] for item in i30_runs[0]["observations"]
    ] == ["i30_directory_scan"]
