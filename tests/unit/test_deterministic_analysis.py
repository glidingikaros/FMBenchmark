from __future__ import annotations


from copy import deepcopy
from typing import Any

import pytest

from fmb.analysis.catalog import TECHNIQUES, techniques_for_question
from fmb.analysis.deterministic import ANALYZERS
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input


PARSER_KIND_BY_FAMILY = {
    "ntfs.mft": "ntfs_mft",
    "ntfs.usn": "ntfs_usn",
    "ntfs.logfile": "ntfs_logfile",
    "ntfs.ads": "ntfs_ads",
    "ntfs.file_size_allocation": "ntfs_file_size_allocation",
    "ntfs.i30": "ntfs_i30",
    "windows.registry.typed_paths": "windows_typed_paths",
    "windows.prefetch": "windows_prefetch",
    "windows.registry.shimcache": "windows_registry_paths",
    "windows.event_log.security": "windows_evtx_security",
    "windows.event_log.record_sequence": "windows_evtx_security",
    "windows.registry.usbstor": "windows_usbstor",
    "windows.setupapi": "windows_setupapi",
    "collected.file.content": "materialized_file_content",
}

TYPED_PATHS_SOURCE_KEY = (
    r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
)


def observation(
    observation_id: str,
    family: str,
    observation_type: str,
    subject: str,
    **fields: Any,
) -> dict[str, object]:
    if observation_type in {
        "usn_file_delete",
        "usn_rename_old_name",
        "usn_basic_info_change",
    }:
        fields.setdefault(
            "update_reasons",
            {
                "usn_file_delete": "FILE_DELETE|CLOSE",
                "usn_rename_old_name": "RENAME_OLD_NAME|CLOSE",
                "usn_basic_info_change": "BASIC_INFO_CHANGE|CLOSE",
            }[observation_type],
        )
    if "mft_active_presence_status" in fields:
        fields.setdefault("mft_volume_id", "volume:test")
        if observation_type in {
            "usn_file_delete",
            "usn_rename_old_name",
            "i30_filename_residue",
        }:
            fields.setdefault("file_reference_entry", 42)
            fields.setdefault("file_reference_sequence", 3)
            fields.setdefault("mft_active_presence_basis", "file_reference_record_free")
        else:
            fields.setdefault("mft_active_presence_basis", "path_comparison")
    if observation_type == "i30_filename_residue":
        fields.setdefault("mft_entry", 43)
        fields.setdefault("sequence_number", 1)
        fields.setdefault("mft_volume_id", "volume:test")
        fields.setdefault("parent_reference_entry", 43)
        fields.setdefault("parent_reference_sequence", 1)
    if observation_type == "prefetch_execution":
        fields.setdefault(
            "executable_name", subject.replace("/", "\\").rsplit("\\", 1)[-1]
        )
        fields.setdefault("run_count", 1)
        fields.setdefault("last_run", "2026-01-01 12:00:00")
    if observation_type == "usb_device_seen":
        fields.setdefault("first_install", "2026-01-01 12:00:00")
    if family == "windows.event_log.security":
        fields.setdefault("channel", "Security")
        fields.setdefault(
            "source_file", r"C:\Windows\System32\winevt\Logs\Security.evtx"
        )
    if observation_type == "materialized_file_content_record":
        size = fields.get("materialized_size", 8192)
        relation = fields.get("content_length_relation")
        fields.setdefault(
            "declared_content_end",
            size
            if relation == "equal"
            else size + 1
            if relation == "materialized_below_declared"
            else 54,
        )
    if observation_type == "si_fn_timestamp_difference":
        for pair in fields.get("mismatches", []):
            field = pair["field"]
            fields.setdefault(f"si_{field}", pair["standard_information"])
            fields.setdefault(f"fn_{field}", pair["file_name"])
        fields.setdefault("si_record_changed", fields.get("record_changed_si"))
    return {
        "observation_id": observation_id,
        "artifact_family": family,
        "observation_type": observation_type,
        "subject_ref": subject,
        "fields": fields,
        "source_record_ref": f"fixture:{observation_id}",
    }


DEFAULT_COVERAGE_SCOPES: dict[str, dict[str, object]] = {
    "ntfs_usn": {
        "kind": "usn_journal",
        "journal_id": 123,
        "lowest_valid_usn": 0,
        "window_validity": "retained_records_within_valid_range",
        "control_identity_bound": True,
        "journal_source": "targets/F/$Extend/$J",
        "order_checked": True,
        "checked_record_count": 2,
        "timestamp_reversal_count": 0,
        "first_usn": 0,
        "first_timestamp": "2000-01-01 00:00:00",
        "last_usn": 1_000_000_000_000,
        "last_timestamp": "2099-01-01 00:00:00",
        "window_complete": True,
    },
    "windows_setupapi": {
        "kind": "setupapi_log",
        "files": ["setupapi.dev.log"],
        "section_count": 1,
        "first_section_timestamp": "2000-01-01 00:00:00",
        "last_section_timestamp": "2099-01-01 00:00:00",
        "window_complete": True,
    },
}


def evidence_index(
    *observations: dict[str, object],
    families: set[str],
    coverage_scopes: dict[str, dict[str, object] | None] | None = None,
) -> dict[str, object]:
    by_kind: dict[str, list[dict[str, object]]] = {}
    for item in observations:
        family = str(item["artifact_family"])
        by_kind.setdefault(PARSER_KIND_BY_FAMILY[family], []).append(item)
    for family in families:
        by_kind.setdefault(PARSER_KIND_BY_FAMILY[family], [])
    scopes = {**DEFAULT_COVERAGE_SCOPES, **(coverage_scopes or {})}
    parser_runs = []
    for kind, items in sorted(by_kind.items()):
        run: dict[str, object] = {
            "parser_kind": kind,
            "status": "consumed",
            "coverage_status": "complete",
            "observations": items,
        }
        scope = scopes.get(kind)
        if scope is not None:
            run["coverage_scope"] = dict(scope)
        parser_runs.append(run)
    return {
        "schema_version": "evidence_index.v1",
        "run_id": "fixture-run",
        "parser_runs": parser_runs,
    }


POSITIVE_CASES = [
    (
        "Q-TIME-01",
        "timestamp_manipulation",
        r"C:\Users\alice\Desktop\time.txt",
        {
            "ntfs.mft",
            "ntfs.usn",
        },
        [
            observation(
                "time-mft",
                "ntfs.mft",
                "si_fn_timestamp_difference",
                r"C:\Users\alice\Desktop\time.txt",
                mismatch_count=3,
                mft_volume_id="volume:test",
                mft_entry=42,
                sequence_number=3,
                mismatches=[
                    {
                        "field": field,
                        "standard_information": "2010-01-01 12:00:00",
                        "file_name": "2026-01-01 12:00:00",
                    }
                    for field in ("created", "modified", "accessed")
                ],
                record_changed_si="2026-01-01 12:05:00",
            ),
            observation(
                "time-usn",
                "ntfs.usn",
                "usn_basic_info_change",
                r"C:\Users\alice\Desktop\time.txt",
                mft_volume_id="volume:test",
                file_reference_entry=42,
                file_reference_sequence=3,
                update_reasons="BASIC_INFO_CHANGE|CLOSE",
                update_timestamp="2026-01-01 12:05:00",
            ),
        ],
    ),
    (
        "Q-HIDE-01",
        "alternate_data_stream",
        r"C:\Users\alice\Desktop\hidden.txt",
        {"ntfs.ads", "ntfs.mft"},
        [
            observation(
                "ads",
                "ntfs.ads",
                "named_data_stream",
                r"C:\Users\alice\Desktop\hidden.txt",
                mft_volume_id="volume:test",
                mft_entry=42,
                sequence_number=3,
                stream_name="payload",
                stream_size=1024,
                host_population_complete=True,
                host_population_size=20,
                hosts_without_named_stream_count=19,
                host_named_stream_count=1,
                stream_name_occurrences=1,
            ),
            observation(
                "ads-content", "ntfs.ads", "named_stream_content",
                r"C:\Users\alice\Desktop\hidden.txt",
                mft_volume_id="volume:test", mft_entry=42, sequence_number=3,
                stream_name="payload", stream_size=1024, materialized_size=1024,
                native_identity_verified=True, content_complete=True,
                content_sha256="a" * 64, dos_signature_hex="4d5a",
                pe_structure_status="complete", pe_signature_hex="50450000",
                pe_optional_magic=0x20b, pe_header_offset=128,
                pe_optional_header_size=240, pe_section_count=1,
                pe_size_of_headers=512, pe_characteristics=2,
                pe_sections=[{"raw_size":512, "raw_offset":512, "characteristics":0x60000020}],
            )
        ],
    ),
    (
        "Q-DEL-01",
        "deleted_file_journal_residue",
        r"C:\Users\alice\Desktop\deleted.txt",
        {"ntfs.usn", "ntfs.mft"},
        [
            observation(
                "delete",
                "ntfs.usn",
                "usn_file_delete",
                r"C:\Users\alice\Desktop\deleted.txt",
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_absent",
            )
        ],
    ),
    (
        "Q-DEL-02",
        "typed_path_residue",
        r"C:\Users\alice\Documents\missing",
        {"windows.registry.typed_paths", "ntfs.mft"},
        [
            observation(
                "mru",
                "windows.registry.typed_paths",
                "typed_path_seen",
                r"C:\Users\alice\Documents\missing",
                candidate_score=90,
                source_key=TYPED_PATHS_SOURCE_KEY,
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_absent",
            )
        ],
    ),
    (
        "Q-DEL-03",
        "i30_directory_residue",
        r"C:\Users\alice\Desktop\gone.txt",
        {"ntfs.i30", "ntfs.mft"},
        [
            observation(
                "i30",
                "ntfs.i30",
                "i30_filename_residue",
                r"C:\Users\alice\Desktop\gone.txt",
                i30_entry_state="slack",
                file_reference_entry=42,
                file_reference_sequence=3,
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_absent",
            )
        ],
    ),
    (
        "Q-FILE-01",
        "bitmap_trailing_data",
        r"C:\Users\alice\Desktop\padded.bin",
        {"ntfs.file_size_allocation", "ntfs.mft"},
        [
            observation(
                "size",
                "ntfs.file_size_allocation",
                "logical_allocated_size_record",
                r"C:\Users\alice\Desktop\padded.bin",
                entity_id="mft:42:3",
                mft_entry=42,
                sequence_number=3,
                resident_status="nonresident",
                attribute_flags=0,
                attribute_parse_error_count=0,
                is_sparse=False,
                is_compressed=False,
                is_encrypted=False,
                mftecmd_identity_match=True,
                attribute_chain_complete=True,
                runlist_complete=True,
                lowest_vcn=0,
                stream_name="",
                logical_size=8192,
                mftecmd_file_size=8192,
            ),
            observation(
                "content",
                "collected.file.content",
                "materialized_file_content_record",
                r"C:\Users\alice\Desktop\padded.bin",
                entity_id="mft:42:3",
                mft_entry=42,
                sequence_number=3,
                materialized_size=8192,
                format_id="bmp",
                header_parse_status="complete",
                content_length_relation="materialized_exceeds_declared",
                structure_validation="declared_length_mismatch",
            ),
        ],
    ),
    (
        "Q-EXEC-01",
        "prefetch_missing_executable",
        r"C:\Users\alice\Downloads\runner.exe",
        {"windows.prefetch", "ntfs.mft"},
        [
            observation(
                "prefetch",
                "windows.prefetch",
                "prefetch_execution",
                r"C:\Users\alice\Downloads\runner.exe",
                candidate_score=120,
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_absent",
            )
        ],
    ),
    (
        "Q-EXEC-01",
        "shimcache_path_residue",
        r"C:\Users\alice\Downloads\runner.exe",
        {"windows.registry.shimcache", "ntfs.mft"},
        [
            observation(
                "shimcache",
                "windows.registry.shimcache",
                "shimcache_path_seen",
                r"C:\Users\alice\Downloads\runner.exe",
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_absent",
            )
        ],
    ),
    (
        "Q-MEDIA-01",
        "usbstor_setupapi_discrepancy",
        "USB Disk",
        {
            "windows.registry.usbstor",
            "windows.setupapi",
        },
        [
            observation(
                "usb",
                "windows.registry.usbstor",
                "usb_device_seen",
                "USB Disk",
                serial_number="SERIAL-1",
                device_instance_id="USBSTOR\\DISK&VEN_ACME\\SERIAL-1",
                control_set="ControlSet001",
            ),
        ],
    ),
]


def _case_from_positive(
    technique_id: str,
    field_updates: dict[str, dict[str, object]],
    observation_type_updates: dict[str, str],
    extra_records: list[dict[str, object]],
) -> tuple[str, set[str], list[dict[str, object]]]:
    question_id, _technique_id, _subject, families, source_records = next(
        case for case in POSITIVE_CASES if case[1] == technique_id
    )
    records = deepcopy(source_records)
    records_by_id = {str(item["observation_id"]): item for item in records}
    for observation_id, updates in field_updates.items():
        fields = records_by_id[observation_id]["fields"]
        assert isinstance(fields, dict)
        fields.update(updates)
    for observation_id, observation_type in observation_type_updates.items():
        records_by_id[observation_id]["observation_type"] = observation_type
    records.extend(deepcopy(extra_records))
    return question_id, set(families), records


def _benign_noise_records(technique_id: str) -> list[dict[str, object]]:
    if technique_id == "usbstor_setupapi_discrepancy":
        return [
            observation(
                "noise-external-media",
                "windows.setupapi",
                "setupapi_usb_event",
                r"USBSTOR\DISK&VEN_OTHER\SERIAL-NOISE",
                serial_number="SERIAL-NOISE",
                device_instance_id=r"USBSTOR\DISK&VEN_OTHER\SERIAL-NOISE",
            )
        ]
    return [
        observation(
            f"noise-{technique_id}",
            "ntfs.mft",
            "mft_file_record",
            rf"C:\Windows\Temp\noise-{technique_id}.tmp",
            mft_entry=9000,
            sequence_number=1,
            **(
                {
                    **{
                        f"{prefix}_{field}": "2026-01-01 12:00:00"
                        for prefix in ("si", "fn")
                        for field in ("created", "modified", "accessed")
                    },
                    "si_record_changed": "2026-01-01 12:00:00",
                }
                if technique_id == "timestamp_manipulation"
                else {}
            ),
        )
    ]


BENIGN_NEGATIVE_CASES = [
    (
        "timestamp_manipulation",
        {"time-usn": {"update_timestamp": "2026-01-01 12:05:01"}},
        {},
        [],
        {
            "coordinated_si_backdating_not_observed",
            "temporal_basic_info_change_not_observed",
        },
    ),
    (
        "alternate_data_stream",
        {"ads-content": {"dos_signature_hex": "7b22", "pe_structure_status": "not_pe", "zip_signature_hex": "7b227822", "zip_structure_status": "not_zip"}},
        {}, [], {"no_supported_format_named_stream_content"},
    ),
    (
        "deleted_file_journal_residue",
        {
            "delete": {
                "mft_active_presence_status": "active_mft_present",
                "mft_active_presence_basis": "file_reference_in_use",
            }
        },
        {},
        [],
        {"active_mft_entry_present"},
    ),
    (
        "typed_path_residue",
        {"mru": {"mft_active_presence_status": "active_mft_present"}},
        {},
        [],
        {"active_mft_entry_present"},
    ),
    (
        "i30_directory_residue",
        {"i30": {"i30_entry_state": "live"}},
        {},
        [],
        {"i30_entries_are_live"},
    ),
    (
        "bitmap_trailing_data",
        {
            "content": {
                "declared_content_end": 8192,
                "content_length_relation": "equal",
                "structure_validation": "consistent",
            }
        },
        {},
        [],
        {"self_describing_content_length_consistent"},
    ),
    (
        "prefetch_missing_executable",
        {"prefetch": {"mft_active_presence_status": "active_mft_present"}},
        {},
        [],
        {"active_mft_entry_present"},
    ),
    (
        "shimcache_path_residue",
        {"shimcache": {"mft_active_presence_status": "active_mft_present"}},
        {},
        [],
        {"active_mft_entry_present"},
    ),
    (
        "usbstor_setupapi_discrepancy",
        {},
        {},
        [
            observation(
                "setup",
                "windows.setupapi",
                "setupapi_usb_event",
                r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
                serial_number="SERIAL-1",
                device_instance_id=r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
            )
        ],
        {"consistent_device_identity_observed"},
    ),
]


FAIL_CLOSED_MUTATION_CASES = [
    (
        "timestamp_manipulation",
        {"time-mft": {"si_created": None}},
        {},
        [],
        {"timestamp_delta_contract_unavailable"},
    ),
    (
        "alternate_data_stream",
        {"ads-content": {"content_complete": False}},
        {},
        [],
        {"stream_native_content_unavailable"},
    ),
    (
        "alternate_data_stream",
        {"ads": {"stream_size": None}},
        {},
        [],
        {"stream_native_content_unavailable"},
    ),
    (
        "deleted_file_journal_residue",
        {"delete": {"mft_active_presence_check_supported": False}},
        {},
        [],
        {"active_mft_absence_unavailable"},
    ),
    (
        "typed_path_residue",
        {"mru": {"mft_active_presence_check_supported": False}},
        {},
        [],
        {"active_mft_absence_unavailable"},
    ),
    (
        "i30_directory_residue",
        {"i30": {"file_reference_sequence": None}},
        {},
        [],
        {"i30_state_contract_unavailable"},
    ),
    (
        "bitmap_trailing_data",
        {"size": {"attribute_chain_complete": False}},
        {},
        [],
        {"storage_contract_unavailable"},
    ),
    (
        "prefetch_missing_executable",
        {"prefetch": {"mft_active_presence_check_supported": False}},
        {},
        [],
        {"active_mft_absence_unavailable"},
    ),
    (
        "shimcache_path_residue",
        {"shimcache": {"mft_active_presence_check_supported": False}},
        {},
        [],
        {"active_mft_absence_unavailable"},
    ),
    (
        "usbstor_setupapi_discrepancy",
        {"usb": {"serial_number": "SERIAL-2"}},
        {},
        [],
        {"usbstor_identity_malformed"},
    ),
]


def test_behavior_grids_cover_retained_criteria() -> None:
    additions = {"shellbag_missing_directory", "ntfs_allocation_inconsistency",
                 "event_record_sequence_gap", "security_log_clear_event",
                 "usb_volume_activity_gap"}
    expected = {item.technique_id for item in TECHNIQUES} - additions

    assert {case[1] for case in POSITIVE_CASES} == expected
    assert {case[0] for case in BENIGN_NEGATIVE_CASES} == expected
    assert {case[0] for case in FAIL_CLOSED_MUTATION_CASES} == expected


def test_full_scale_operator_preserves_exact_sets_and_shared_decision_hashes() -> None:
    records: list[dict[str, object]] = []
    families: set[str] = set()
    expected_labels: dict[str, str] = {}
    for (
        _question_id,
        technique_id,
        subject,
        case_families,
        case_records,
    ) in POSITIVE_CASES:
        records.extend(deepcopy(case_records))
        families.update(case_families)
        expected_labels[technique_id] = subject

    index = evidence_index(*records, families=families)
    for definition in TECHNIQUES:
        if definition.technique_id not in ANALYZERS:
            continue
        analysis_input = build_analysis_input(index, definition)
        result = analyze_input(analysis_input)
        supported_labels = {
            subject.display_name
            for subject in analysis_input.candidate_roster.subjects
            if subject.subject_id in result.supported_subjects.subject_ids
        }
        if analysis_input.technique_id not in expected_labels:
            assert all(item.outcome == "indeterminate" for item in result.assessments)
            assert not supported_labels
            continue
        assert supported_labels == {expected_labels[analysis_input.technique_id]}

        assert result.input_id == analysis_input.input_id
        assert result.input_sha256 == analysis_input.input_sha256
        assert result.roster_sha256 == analysis_input.candidate_roster.roster_sha256
        assert result.reviewed_subject_ids == (
            analysis_input.candidate_roster.subject_ids()
        )


@pytest.mark.parametrize(
    ("question_id", "technique_id", "subject", "families", "records"),
    POSITIVE_CASES,
)
def test_each_technique_reports_a_supported_subject(
    question_id: str,
    technique_id: str,
    subject: str,
    families: set[str],
    records: list[dict[str, object]],
) -> None:
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == technique_id
    )
    analysis_input = build_analysis_input(
        evidence_index(*records, families=families), definition
    )

    result = analyze_input(analysis_input)

    supported_labels = {
        item.display_name
        for item in analysis_input.candidate_roster.subjects
        if item.subject_id in result.supported_subjects.subject_ids
    }
    assert result.status == "completed"
    assert supported_labels == {subject}
    assert result.truth_sources_used == ()


@pytest.mark.parametrize(
    (
        "technique_id",
        "field_updates",
        "observation_type_updates",
        "extra_records",
        "expected_reasons",
    ),
    BENIGN_NEGATIVE_CASES,
    ids=[case[0] for case in BENIGN_NEGATIVE_CASES],
)
def test_each_technique_rejects_benign_evidence_and_noise(
    technique_id: str,
    field_updates: dict[str, dict[str, object]],
    observation_type_updates: dict[str, str],
    extra_records: list[dict[str, object]],
    expected_reasons: set[str],
) -> None:
    question_id, families, records = _case_from_positive(
        technique_id,
        field_updates,
        observation_type_updates,
        extra_records,
    )
    records.extend(_benign_noise_records(technique_id))
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == technique_id
    )
    index = evidence_index(*records, families=families)
    result = analyze_input(build_analysis_input(index, definition))

    assert result.status == "completed"
    assert result.supported_subjects.subject_ids == ()
    assert {item.outcome for item in result.assessments} == {"not_supported"}
    assert {item.reason_code for item in result.assessments} == expected_reasons


@pytest.mark.parametrize(
    (
        "technique_id",
        "field_updates",
        "observation_type_updates",
        "extra_records",
        "expected_reasons",
    ),
    FAIL_CLOSED_MUTATION_CASES,
    ids=[case[0] for case in FAIL_CLOSED_MUTATION_CASES],
)
def test_each_technique_fails_closed_when_one_required_signal_is_mutated(
    technique_id: str,
    field_updates: dict[str, dict[str, object]],
    observation_type_updates: dict[str, str],
    extra_records: list[dict[str, object]],
    expected_reasons: set[str],
) -> None:
    question_id, families, records = _case_from_positive(
        technique_id,
        field_updates,
        observation_type_updates,
        extra_records,
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == technique_id
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert result.status == "completed"
    assert result.supported_subjects.subject_ids == ()
    assert {item.outcome for item in result.assessments} == {"indeterminate"}
    assert {item.reason_code for item in result.assessments} == expected_reasons


def test_external_media_exact_identity_match_is_not_a_discrepancy() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instance = r"USBSTOR\DISK&VEN_ACME\SERIAL-1"
    value = build_analysis_input(
        evidence_index(
            observation(
                "usb",
                "windows.registry.usbstor",
                "usb_device_seen",
                "USB Disk",
                serial_number="SERIAL-1",
                device_instance_id=instance,
                control_set="ControlSet001",
            ),
            observation(
                "setup",
                "windows.setupapi",
                "setupapi_usb_event",
                instance,
                serial_number="SERIAL-1",
                device_instance_id=instance,
            ),
            families={"windows.registry.usbstor", "windows.setupapi"},
        ),
        definition,
    )

    result = analyze_input(value)

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "consistent_device_identity_observed"


def test_ads_does_not_treat_an_author_named_dollar_stream_as_ntfs_metadata() -> None:
    question_id, families, records = _case_from_positive(
        "alternate_data_stream",
        {"ads": {"stream_name": "$secret"}, "ads-content": {"stream_name": "$secret"}},
        {},
        [],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "alternate_data_stream"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].outcome == "supported"
    assert (
        result.assessments[0].reason_code == "named_stream_contains_pe_executable_structure"
    )


def test_ads_decision_is_content_based_independent_of_stream_name() -> None:
    question_id, families, records = _case_from_positive(
        "alternate_data_stream",
        {"ads": {"stream_name": "Zone.Identifier"}, "ads-content": {"stream_name": "Zone.Identifier"}},
        {},
        [],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "alternate_data_stream"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].outcome == "supported"
    assert (
        result.assessments[0].reason_code == "named_stream_contains_pe_executable_structure"
    )


def test_ads_content_assessment_does_not_require_a_separable_host_population() -> None:
    question_id, families, records = _case_from_positive(
        "alternate_data_stream",
        {
            "ads": {
                "host_population_size": 2,
                "hosts_without_named_stream_count": 1,
            }
        },
        {},
        [],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "alternate_data_stream"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == "named_stream_contains_pe_executable_structure"


def test_ads_candidates_are_host_files() -> None:
    definition = techniques_for_question("Q-HIDE-01")[0]

    assert definition.subject_type == "file"


def test_ads_question_requires_executable_structure() -> None:
    definition = techniques_for_question("Q-HIDE-01")[0]

    assert "complete executable PE image" in definition.question_text
    assert "bounded ZIP archive" in definition.question_text
    assert "PE" in definition.claim_boundary


def test_external_media_partial_identity_mapping_is_indeterminate() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    value = build_analysis_input(
        evidence_index(
            observation(
                "usb",
                "windows.registry.usbstor",
                "usb_device_seen",
                "USB Disk",
                serial_number="SERIAL-1",
                device_instance_id=r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
                control_set="ControlSet001",
            ),
            observation(
                "setup",
                "windows.setupapi",
                "setupapi_usb_event",
                "SERIAL-1",
                serial_number="SERIAL-1",
                device_instance_id="",
            ),
            families={"windows.registry.usbstor", "windows.setupapi"},
        ),
        definition,
    )

    result = analyze_input(value)

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == (
        "device_identity_correlation_conflicting"
    )


def test_external_media_partial_setupapi_coverage_is_insufficient() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    usb = observation(
        "usb",
        "windows.registry.usbstor",
        "usb_device_seen",
        "USB Disk",
        serial_number="SERIAL-1",
        device_instance_id=r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
        control_set="ControlSet001",
    )
    value = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "partial-setupapi",
            "parser_runs": [
                {
                    "parser_kind": "windows_usbstor",
                    "status": "consumed",
                    "coverage_status": "complete",
                    "raw_outputs": [{"path": "USBSTOR.csv"}],
                    "observations": [usb],
                },
                {
                    "parser_kind": "windows_setupapi",
                    "status": "consumed",
                    "coverage_status": "partial",
                    "raw_outputs": [{"path": "setupapi.dev.log"}],
                    "observations": [],
                },
            ],
        },
        definition,
    )

    result = analyze_input(value)

    assert result.status == "insufficient_evidence"
    assert result.assessments[0].outcome == "indeterminate"
    assert result.coverage_gaps == ("windows.setupapi",)


def test_external_media_duplicate_control_set_identity_is_indeterminate() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instance = r"USBSTOR\DISK&VEN_ACME\SERIAL-1"
    records = [
        observation(
            f"usb-{control_set}",
            "windows.registry.usbstor",
            "usb_device_seen",
            "USB Disk",
            serial_number="SERIAL-1",
            device_instance_id=instance,
            control_set=control_set,
        )
        for control_set in ("ControlSet001", "ControlSet002")
    ]
    value = build_analysis_input(
        evidence_index(
            *records,
            families={"windows.registry.usbstor", "windows.setupapi"},
        ),
        definition,
    )

    result = analyze_input(value)

    assert len(value.candidate_roster.subjects) == 1
    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == (
        "device_identity_control_set_conflicting"
    )


def test_external_media_flattened_identity_without_control_set_is_indeterminate() -> (
    None
):
    definition = techniques_for_question("Q-MEDIA-01")[0]
    value = build_analysis_input(
        evidence_index(
            observation(
                "usb-summary",
                "windows.registry.usbstor",
                "usb_device_seen",
                "USB Disk",
                serial_number="SERIAL-1",
                device_instance_id=r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
                control_set="",
            ),
            families={"windows.registry.usbstor", "windows.setupapi"},
        ),
        definition,
    )

    result = analyze_input(value)

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == (
        "device_identity_control_set_unavailable"
    )


def test_external_media_duplicate_parser_records_for_one_identity_are_corroborating() -> (
    None
):
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instance = r"USBSTOR\DISK&VEN_ACME\SERIAL-1"
    records = [
        observation(
            f"usb-{source}",
            "windows.registry.usbstor",
            "usb_device_seen",
            "USB Disk",
            serial_number="SERIAL-1",
            device_instance_id=instance,
            control_set=control_set,
        )
        for source, control_set in (
            ("registry", "ControlSet001"),
            ("summary", ""),
        )
    ]
    value = build_analysis_input(
        evidence_index(
            *records,
            families={"windows.registry.usbstor", "windows.setupapi"},
        ),
        definition,
    )

    result = analyze_input(value)

    assert result.supported_subjects.subject_ids
    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == (
        "usbstor_identity_missing_from_setupapi"
    )


def test_missing_required_family_is_insufficient_not_clean_negative() -> None:
    definition = techniques_for_question("Q-DEL-01")[0]
    record = observation(
        "delete",
        "ntfs.usn",
        "usn_file_delete",
        r"C:\Users\alice\Desktop\deleted.txt",
        mft_active_presence_check_supported=False,
        mft_active_presence_status="mft_context_unavailable",
    )
    value = build_analysis_input(
        evidence_index(record, families={"ntfs.usn"}), definition
    )

    result = analyze_input(value)

    assert result.status == "insufficient_evidence"
    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"


def test_shimcache_residue_with_proven_active_absence_is_selected() -> None:
    definition = next(
        item
        for item in techniques_for_question("Q-EXEC-01")
        if item.technique_id == "shimcache_path_residue"
    )
    record = observation(
        "shim",
        "windows.registry.shimcache",
        "shimcache_path_seen",
        r"C:\Users\alice\Downloads\runner.exe",
        mft_active_presence_check_supported=True,
        mft_active_presence_status="active_mft_absent",
    )
    value = build_analysis_input(
        evidence_index(record, families={"windows.registry.shimcache", "ntfs.mft"}),
        definition,
    )

    result = analyze_input(value)

    assert result.status == "completed"
    assert result.supported_subjects.subject_ids == (
        value.candidate_roster.subjects[0].subject_id,
    )
    assert result.assessments[0].outcome == "supported"
    assert (
        result.assessments[0].reason_code == "shimcache_residue_with_active_mft_absence"
    )
    assert "not proof of execution" in result.findings[0].limitations[-1]


def test_shimcache_residue_without_an_absence_proof_is_indeterminate() -> None:
    definition = next(
        item
        for item in techniques_for_question("Q-EXEC-01")
        if item.technique_id == "shimcache_path_residue"
    )
    record = observation(
        "shim",
        "windows.registry.shimcache",
        "shimcache_path_seen",
        r"C:\Users\alice\Downloads\runner.exe",
        mft_active_presence_check_supported=False,
        mft_active_presence_status="active_mft_absence_undecidable",
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(record, families={"windows.registry.shimcache", "ntfs.mft"}),
            definition,
        )
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"


def test_malformed_absence_check_is_indeterminate() -> None:
    definition = techniques_for_question("Q-DEL-01")[0]
    record = observation(
        "delete",
        "ntfs.usn",
        "usn_file_delete",
        r"C:\Users\alice\Desktop\deleted.txt",
    )
    value = build_analysis_input(
        evidence_index(record, families={"ntfs.usn", "ntfs.mft"}), definition
    )

    result = analyze_input(value)

    assert result.status == "completed"
    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"


def test_execution_question_distinguishes_prefetch_from_shimcache_residue() -> None:
    definitions = techniques_for_question("Q-EXEC-01")

    assert {item.question_text for item in definitions} == {
        "Is there Prefetch execution residue or Shimcache path residue for an "
        "executable absent from the active filesystem?"
    }


@pytest.mark.parametrize(
    "subject_ref",
    [
        r"Documents\missing.txt",
        r"\\server\share\missing.txt",
        r"\\?\C:\Users\alice\missing.txt",
    ],
)
def test_typed_path_residue_rejects_nonlocal_or_device_path_scopes(
    subject_ref: str,
) -> None:
    definition = techniques_for_question("Q-DEL-02")[0]
    record = observation(
        "mru",
        "windows.registry.typed_paths",
        "typed_path_seen",
        subject_ref,
        source_key=TYPED_PATHS_SOURCE_KEY,
        mft_active_presence_check_supported=True,
        mft_active_presence_status="active_mft_absent",
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(
                record, families={"windows.registry.typed_paths", "ntfs.mft"}
            ),
            definition,
        )
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "typed_path_scope_unavailable"


def test_typed_path_residue_accepts_an_absolute_local_custom_profile_path() -> None:
    definition = techniques_for_question("Q-DEL-02")[0]
    record = observation(
        "mru",
        "windows.registry.typed_paths",
        "typed_path_seen",
        r"D:\Profiles\analyst\missing.txt",
        source_key=TYPED_PATHS_SOURCE_KEY,
        mft_active_presence_check_supported=True,
        mft_active_presence_status="active_mft_absent",
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(
                record, families={"windows.registry.typed_paths", "ntfs.mft"}
            ),
            definition,
        )
    )

    assert result.supported_subjects.subject_ids
    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == (
        "typed_path_residue_with_active_mft_absence"
    )


def test_registry_path_question_does_not_infer_deletion_or_user_intent() -> None:
    definition = techniques_for_question("Q-DEL-02")[0]

    assert definition.question_text == (
        "Does a structured TypedPaths registry value reference an absolute local "
        "path proven absent from the active filesystem?"
    )


def test_typed_path_residue_excludes_other_registry_path_records() -> None:
    definition = techniques_for_question("Q-DEL-02")[0]
    record = observation(
        "mru",
        "windows.registry.typed_paths",
        "typed_path_seen",
        r"C:\Users\alice\Documents\missing",
        source_key=(
            r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        ),
        mft_active_presence_check_supported=True,
        mft_active_presence_status="active_mft_absent",
    )

    analysis_input = build_analysis_input(
        evidence_index(record, families={"windows.registry.typed_paths", "ntfs.mft"}),
        definition,
    )

    assert analysis_input.candidate_roster.subjects == ()
    assert analyze_input(analysis_input).supported_subjects.subject_ids == ()


def test_i30_live_and_slack_states_for_one_subject_are_indeterminate() -> None:
    question_id, families, records = _case_from_positive(
        "i30_directory_residue",
        {},
        {},
        [
            observation(
                "i30-live",
                "ntfs.i30",
                "i30_filename_residue",
                r"C:\Users\alice\Desktop\gone.txt",
                i30_entry_state="live",
                file_reference_entry=42,
                file_reference_sequence=3,
                mft_active_presence_check_supported=True,
                mft_active_presence_status="active_mft_present",
            )
        ],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "i30_directory_residue"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "i30_live_and_residue_states_conflicting"


def test_i30_zero_file_reference_sequence_is_indeterminate() -> None:
    question_id, families, records = _case_from_positive(
        "i30_directory_residue",
        {"i30": {"file_reference_sequence": 0}},
        {},
        [],
    )
    definition = techniques_for_question(question_id)[0]

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "i30_state_contract_unavailable"


def test_i30_claim_requires_at_least_one_residue_record() -> None:
    definition = techniques_for_question("Q-DEL-03")[0]

    assert "at least one" in definition.claim_boundary


def test_i30_question_names_only_the_supported_parser_surface() -> None:
    definition = techniques_for_question("Q-DEL-03")[0]

    assert "$INDEX_ALLOCATION" in definition.question_text
    assert "at least one" in definition.claim_boundary


def test_i30_complete_supported_surface_without_residue_is_not_supported() -> None:
    definition = techniques_for_question("Q-DEL-03")[0]
    directory = r"C:\Users\alice\Documents\clean-directory"
    scan = observation(
        "i30-scan",
        "ntfs.i30",
        "i30_directory_scan",
        directory,
        mft_volume_id="volume:test",
        mft_entry=42,
        sequence_number=3,
        scan_complete=True,
        supported_surface="resident_index_root_and_mft_record_slack",
        resident_index_root_scanned=True,
        mft_record_slack_scanned=True,
        index_allocation_parsed=False,
        residue_count=0,
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(scan, families={"ntfs.i30", "ntfs.mft"}),
            definition,
        )
    )

    assert len(result.assessments) == 1
    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "i30_supported_surface_has_no_residue"


def test_i30_scan_requires_a_positive_sequence_identity() -> None:
    definition = techniques_for_question("Q-DEL-03")[0]
    scan = observation(
        "i30-scan-zero-sequence",
        "ntfs.i30",
        "i30_directory_scan",
        r"C:\Users\alice\Documents\invalid-directory-identity",
        mft_volume_id="volume:test",
        mft_entry=42,
        sequence_number=0,
        scan_complete=True,
        supported_surface="resident_index_root_and_mft_record_slack",
        resident_index_root_scanned=True,
        mft_record_slack_scanned=True,
        index_allocation_parsed=False,
        residue_count=0,
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(scan, families={"ntfs.i30", "ntfs.mft"}),
            definition,
        )
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "i30_scan_contract_unavailable"


def test_i30_incomplete_supported_surface_without_residue_is_indeterminate() -> None:
    definition = techniques_for_question("Q-DEL-03")[0]
    directory = r"C:\Users\alice\Documents\clean-directory"
    scan = observation(
        "i30-scan",
        "ntfs.i30",
        "i30_directory_scan",
        directory,
        mft_volume_id="volume:test",
        mft_entry=42,
        sequence_number=3,
        scan_complete=False,
        supported_surface="resident_index_root_and_mft_record_slack",
        resident_index_root_scanned=True,
        mft_record_slack_scanned=True,
        index_allocation_parsed=False,
        residue_count=0,
    )

    result = analyze_input(
        build_analysis_input(
            evidence_index(scan, families={"ntfs.i30", "ntfs.mft"}),
            definition,
        )
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "i30_scan_contract_unavailable"


def test_event_log_question_is_limited_to_valid_security_event_1102() -> None:
    definition = techniques_for_question("Q-LOG-01")[0]

    assert "1102" in definition.claim_boundary
    gap = next(item for item in techniques_for_question("Q-LOG-01")
               if item.technique_id == "event_record_sequence_gap")
    assert "1102" in gap.claim_boundary
    assert "discontinuity" in gap.claim_boundary


def test_capped_parser_output_is_insufficient_evidence() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            r"C:\Users\alice\Desktop\time.txt",
            mismatch_count=1,
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            r"C:\Users\alice\Desktop\time.txt",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )
    index["parser_runs"][0]["coverage_status"] = "partial"

    result = analyze_input(build_analysis_input(index, definition))

    assert result.status == "insufficient_evidence"
    assert result.supported_subjects.subject_ids == ()


def test_same_path_different_ntfs_generations_are_not_joined() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\reused.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01 12:00:00",
                    "file_name": "2026-01-01 12:00:00",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01 12:05:00",
        ),
        observation(
            "time-usn-other-generation",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            file_reference_entry=42,
            file_reference_sequence=4,
            update_timestamp="2026-01-01 12:05:00",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"


def test_timestomp_requires_coordinated_user_settable_timestamp_deltas() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=1,
            si_created="2026-01-01 12:00:00",
            fn_created="2026-01-01 12:00:00",
            si_accessed="2026-01-01 12:00:00",
            fn_accessed="2026-01-01 12:00:00",
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": "modified",
                    "standard_information": "2010-01-01 12:00:00",
                    "file_name": "2026-01-01 12:00:00",
                }
            ],
            record_changed_si="2026-01-01 12:05:00",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01 12:05:00",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "coordinated_si_backdating_not_observed"


def test_timestomp_rejects_basic_info_change_at_one_second_boundary() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": "2010-01-01 12:00:00",
            "file_name": "2026-01-01 12:00:00",
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01 12:05:00",
        ),
        observation(
            "time-usn-wrong-time",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01 12:05:01",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"
    assert (
        result.assessments[0].reason_code == "temporal_basic_info_change_not_observed"
    )


def test_timestomp_accepts_same_object_usn_event_logged_after_si_change() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T20:00:00.0000000Z",
                    "file_name": "2026-08-28T07:34:36.7099756Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-08-28T07:35:00.8829666Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-08-28T07:35:00.8981760Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].reason_code == (
        "coordinated_si_backdating_with_temporal_basic_info_change"
    )


def test_timestomp_accepts_usn_event_just_inside_one_second_window() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T12:00:00.0000000Z",
                    "file_name": "2026-01-01T12:00:00.0000000Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01T12:05:00.0000000Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.9999999Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert len(result.supported_subjects.subject_ids) == 1


def test_timestomp_rejects_a_one_hundred_nanosecond_usn_near_miss() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T12:00:00.1234567Z",
                    "file_name": "2026-01-01T12:00:00.1234567Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01T12:05:00.1234567Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234566Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"
    assert (
        result.assessments[0].reason_code == "temporal_basic_info_change_not_observed"
    )


def test_timestomp_normalizes_offsets_before_exact_timestamp_correlation() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T13:00:00.1234567+01:00",
                    "file_name": "2026-01-01T12:00:00.1234567Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01T13:05:00.1234567+01:00",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].outcome == "supported"


def test_timestomp_rule_v3_supports_offsets_that_differ_by_one_hundred_nanoseconds() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": (
                "2010-01-01T12:00:00.1234566Z"
                if field == "modified"
                else "2010-01-01T12:00:00.1234567Z"
            ),
            "file_name": "2026-01-01T12:00:00.1234567Z",
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01T12:05:00.1234567Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert len(result.supported_subjects.subject_ids) == 1
    assert result.assessments[0].reason_code == (
        "coordinated_si_backdating_with_temporal_basic_info_change"
    )
    assert not any(
        note.startswith("shared_offset_pattern") for note in result.assessments[0].limitations
    )
    assert not any(
        note.startswith("sub_second_zeros") for note in result.assessments[0].limitations
    )


def test_timestomp_rule_v2_reports_rewritten_last_access_without_gating() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": (
                "2026-01-01T12:43:25.0000000Z"
                if field == "accessed"
                else "2010-01-01T12:00:00.0000000Z"
            ),
            "file_name": "2026-01-01T12:00:00.0000000Z",
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01T12:05:00.0000000Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.0312500Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == (
        "coordinated_si_backdating_with_temporal_basic_info_change"
    )
    assert any("last-access" in note for note in result.assessments[0].limitations)


def test_timestomp_rule_v3_supports_unequal_created_and_modified_offsets() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": (
                "2011-06-01T12:00:00.0000000Z"
                if field == "modified"
                else "2010-01-01T12:00:00.0000000Z"
            ),
            "file_name": "2026-01-01T12:00:00.0000000Z",
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01T12:05:00.0000000Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.0000000Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == (
        "coordinated_si_backdating_with_temporal_basic_info_change"
    )
    assert not any(
        note.startswith("shared_offset_pattern") for note in result.assessments[0].limitations
    )
    assert any(
        note.startswith("sub_second_zeros") for note in result.assessments[0].limitations
    )


def test_timestomp_rule_v2_result_with_duplicate_mft_observations_is_schema_valid() -> None:

    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    fields = {
        "si_created": "2010-01-01T12:00:00.0000000Z",
        "fn_created": "2026-01-01T12:00:00.0000000Z",
        "si_modified": "2010-01-01T12:00:00.0000000Z",
        "fn_modified": "2026-01-01T12:00:00.0000000Z",
        "si_accessed": "2026-01-01T12:43:25.0000000Z",
        "fn_accessed": "2026-01-01T12:00:00.0000000Z",
        "si_record_changed": "2026-01-01T12:05:00.0000000Z",
        "mft_volume_id": "volume:test",
        "mft_entry": 42,
        "sequence_number": 3,
    }
    index = evidence_index(
        observation("time-mft-record", "ntfs.mft", "mft_file_record", path, **fields),
        observation(
            "time-mft-diff", "ntfs.mft", "si_fn_timestamp_difference", path,
            mismatch_count=3, **fields,
        ),
        observation(
            "time-usn", "ntfs.usn", "usn_basic_info_change", path,
            mft_volume_id="volume:test", file_reference_entry=42,
            file_reference_sequence=3, update_timestamp="2026-01-01T12:05:00.0312500Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert len(assessment.limitations) == len(set(assessment.limitations)) >= 1
    assert any("last-access" in note for note in assessment.limitations)


def test_timestomp_is_indeterminate_for_incompatible_timestamp_bases() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T12:00:00.1234567Z",
                    "file_name": "2026-01-01T12:00:00.1234567Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01T12:05:00.1234567",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "basic_info_change_time_incompatible"


def test_timestomp_is_indeterminate_without_exact_ntfs_entity_identity() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mismatches=[
                {
                    "field": field,
                    "standard_information": "2010-01-01T12:00:00.1234567Z",
                    "file_name": "2026-01-01T12:00:00.1234567Z",
                }
                for field in ("created", "modified", "accessed")
            ],
            record_changed_si="2026-01-01T12:05:00.1234567Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "timestamp_entity_identity_unavailable"


def test_timestomp_is_indeterminate_for_a_malformed_timestamp_pair() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": (
                "not-a-timestamp"
                if field == "accessed"
                else "2010-01-01T12:00:00.1234567Z"
            ),
            "file_name": "2026-01-01T12:00:00.1234567Z",
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01T12:05:00.1234567Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "timestamp_delta_contract_unavailable"


def test_timestomp_is_indeterminate_for_mixed_delta_comparison_bases() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {
            "field": field,
            "standard_information": (
                "2010-01-01T12:00:00.1234567"
                if field == "accessed"
                else "2010-01-01T12:00:00.1234567Z"
            ),
            "file_name": (
                "2026-01-01T12:00:00.1234567"
                if field == "accessed"
                else "2026-01-01T12:00:00.1234567Z"
            ),
        }
        for field in ("created", "modified", "accessed")
    ]
    index = evidence_index(
        observation(
            "time-mft",
            "ntfs.mft",
            "si_fn_timestamp_difference",
            path,
            mismatch_count=3,
            mft_volume_id="volume:test",
            mft_entry=42,
            sequence_number=3,
            mismatches=mismatches,
            record_changed_si="2026-01-01T12:05:00.1234567Z",
        ),
        observation(
            "time-usn",
            "ntfs.usn",
            "usn_basic_info_change",
            path,
            mft_volume_id="volume:test",
            file_reference_entry=42,
            file_reference_sequence=3,
            update_timestamp="2026-01-01T12:05:00.1234567Z",
        ),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "timestamp_delta_contract_unavailable"


@pytest.mark.parametrize(
    ("relation", "structure", "expected_outcome"),
    [
        ("equal", "consistent", "not_supported"),
        (
            "materialized_exceeds_declared",
            "declared_length_mismatch",
            "supported",
        ),
        (
            "materialized_below_declared",
            "declared_length_mismatch",
            "indeterminate",
        ),
    ],
)
def test_file_content_relation_contract(
    relation: str, structure: str, expected_outcome: str
) -> None:
    definition = techniques_for_question("Q-FILE-01")[0]
    path = r"C:\Users\alice\Documents\PhotoArchive\image.bmp"
    records = [
        observation(
            "storage",
            "ntfs.file_size_allocation",
            "logical_allocated_size_record",
            path,
            entity_id="mft:42:3",
            mft_entry=42,
            sequence_number=3,
            resident_status="nonresident",
            attribute_flags=0,
            attribute_parse_error_count=0,
            is_sparse=False,
            is_compressed=False,
            is_encrypted=False,
            mftecmd_identity_match=True,
            attribute_chain_complete=True,
            runlist_complete=True,
            lowest_vcn=0,
            stream_name="",
            logical_size=8192,
            mftecmd_file_size=8192,
        ),
        observation(
            "content",
            "collected.file.content",
            "materialized_file_content_record",
            path,
            entity_id="mft:42:3",
            mft_entry=42,
            sequence_number=3,
            materialized_size=8192,
            format_id="bmp",
            header_parse_status="complete",
            content_length_relation=relation,
            structure_validation=structure,
        ),
    ]

    result = analyze_input(
        build_analysis_input(
            evidence_index(
                *records,
                families={
                    "ntfs.file_size_allocation",
                    "ntfs.mft",
                    "collected.file.content",
                },
            ),
            definition,
        )
    )

    assert result.assessments[0].outcome == expected_outcome


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("resident_status", None),
        ("attribute_flags", []),
        ("attribute_parse_error_count", 1),
        ("is_sparse", None),
        ("is_compressed", "false"),
        ("is_encrypted", 0),
        ("mftecmd_identity_match", False),
        ("attribute_chain_complete", False),
        ("runlist_complete", False),
        ("lowest_vcn", "0"),
        ("stream_name", None),
    ],
)
def test_file_content_unknown_storage_state_is_indeterminate(
    field: str, invalid_value: object
) -> None:
    question_id, families, records = _case_from_positive(
        "bitmap_trailing_data",
        {"size": {field: invalid_value}},
        {},
        [],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "bitmap_trailing_data"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "storage_contract_unavailable"


def test_file_content_mismatch_under_resident_storage_is_indeterminate() -> None:
    question_id, families, records = _case_from_positive(
        "bitmap_trailing_data",
        {
            "size": {
                "resident_status": "resident",
                "runlist_complete": None,
            }
        },
        {},
        [],
    )
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == "bitmap_trailing_data"
    )

    result = analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert (
        result.assessments[0].reason_code == "length_mismatch_under_benign_storage_mode"
    )


def _evaluate_mutated_case(technique_id, changes):
    question_id, families, records = _case_from_positive(technique_id, changes, {}, [])
    definition = next(
        item
        for item in techniques_for_question(question_id)
        if item.technique_id == technique_id
    )
    return analyze_input(
        build_analysis_input(evidence_index(*records, families=families), definition)
    )


@pytest.mark.parametrize(
    ("technique", "changes"),
    [
        (
            "deleted_file_journal_residue",
            {"delete": {"update_reasons": "FILE_CREATE|CLOSE"}},
        ),
        (
            "deleted_file_journal_residue",
            {"delete": {"mft_active_presence_basis": "path_comparison"}},
        ),
        ("typed_path_residue", {"mru": {"value_data": r"C:\different\path"}}),
        ("typed_path_residue", {"mru": {"value_data": None}}),
        ("prefetch_missing_executable", {"prefetch": {"executable_name": "other.exe"}}),
        ("prefetch_missing_executable", {"prefetch": {"run_count": 0}}),
        ("prefetch_missing_executable", {"prefetch": {"run_count": True}}),
        ("prefetch_missing_executable", {"prefetch": {"last_run": "invalid"}}),
        ("shimcache_path_residue", {"shimcache": {"path": r"C:\other\runner.exe"}}),
        ("bitmap_trailing_data", {"content": {"declared_content_end": True}}),
        ("bitmap_trailing_data", {"content": {"declared_content_end": 53}}),
        ("bitmap_trailing_data", {"size": {"attribute_flags": 0x8000}}),
        ("i30_directory_residue", {"i30": {"parent_reference_sequence": 99}}),
        (
            "i30_directory_residue",
            {"i30": {"mft_active_presence_basis": "path_comparison"}},
        ),
        ("alternate_data_stream", {"ads": {"stream_size": -1}}),
    ],
)
def test_native_evidence_contradictions_cannot_be_overridden_by_record_classification(
    technique, changes
):
    result = _evaluate_mutated_case(technique, changes)
    assert result.supported_subjects.subject_ids == ()
    assert all(item.outcome == "indeterminate" for item in result.assessments)


def test_diagnostic_timestamp_scores_do_not_replace_native_timestamps():
    result = _evaluate_mutated_case(
        "timestamp_manipulation",
        {"time-mft": {"mismatch_count": 0, "mismatches": [], "max_gap_days": 0}},
    )
    assert len(result.supported_subjects.subject_ids) == 1
    result = _evaluate_mutated_case(
        "timestamp_manipulation", {"time-mft": {"si_created": "2026-01-01 12:00:00"}}
    )
    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "not_supported"


@pytest.mark.parametrize(
    ("si", "fn", "expected"),
    [
        ("2026-01-01T12:00:00.0000000Z", "2026-01-01T12:01:00.0000000Z", "supported"),
        ("2026-01-01T12:00:00.0000000Z", "2026-01-01T12:00:59.9999999Z", "not_supported"),
        ("2026-01-01T12:00:00.0000000Z", "2026-01-01T12:00:00.0000001Z", "not_supported"),
        (
            "2026-01-01T12:00:00.0000000Z",
            "2026-01-01T12:00:00.0000000Z",
            "not_supported",
        ),
    ],
)
def test_coordinated_backdate_preserves_positive_equal_duration_rule(si, fn, expected):
    result = _evaluate_mutated_case(
        "timestamp_manipulation",
        {
            "time-mft": {
                **{f"si_{field}": si for field in ("created", "modified", "accessed")},
                **{f"fn_{field}": fn for field in ("created", "modified", "accessed")},
                "si_record_changed": "2026-01-01T12:05:00Z",
            },
            "time-usn": {"update_timestamp": "2026-01-01T12:05:00Z"},
        },
    )
    assert result.assessments[0].outcome == expected


@pytest.mark.parametrize(
    ("declared", "expected"),
    [(54, "supported"), (8192, "not_supported"), (8193, "indeterminate")],
)
def test_bmp_numeric_lengths_override_stale_diagnostic_labels(declared, expected):
    result = _evaluate_mutated_case(
        "bitmap_trailing_data",
        {
            "content": {
                "declared_content_end": declared,
                "content_length_relation": "not-a-real-relation",
                "structure_validation": "not-a-real-verdict",
            }
        },
    )
    assert result.assessments[0].outcome == expected


def test_bmp_requires_native_declared_length_when_diagnostic_label_claims_support():
    result = _evaluate_mutated_case(
        "bitmap_trailing_data", {"content": {"declared_content_end": None}}
    )
    assert result.assessments[0].outcome == "indeterminate"


def test_same_candidate_conflicting_lookup_records_are_not_supported():
    from dataclasses import replace
    from fmb.analysis.deterministic import _absence_decision

    question, families, records = _case_from_positive(
        "prefetch_missing_executable", {}, {}, []
    )
    definition = next(
        item
        for item in techniques_for_question(question)
        if item.technique_id == "prefetch_missing_executable"
    )
    value = build_analysis_input(
        evidence_index(*records, families=families), definition
    )
    subject = value.candidate_roster.subjects[0]
    absent = value.observations[0]
    present = replace(
        absent,
        observation_id="contradiction",
        fields={**absent.fields, "mft_active_presence_status": "active_mft_present"},
    )
    decision = _absence_decision(
        value, subject, (absent, present), supported_reason="unused"
    )
    assert decision.outcome == "indeterminate"
    assert decision.reason_code == "mixed_active_mft_states"


def _backdated_without_usn(path: str) -> dict[str, object]:
    return observation(
        "time-mft",
        "ntfs.mft",
        "si_fn_timestamp_difference",
        path,
        mismatch_count=3,
        mft_volume_id="volume:test",
        mft_entry=42,
        sequence_number=3,
        mismatches=[
            {
                "field": field,
                "standard_information": "2010-01-01 12:00:00",
                "file_name": "2026-01-01 12:00:00",
            }
            for field in ("created", "modified", "accessed")
        ],
        record_changed_si="2026-01-01 12:05:00",
    )


def test_timestomp_without_usn_journal_window_is_indeterminate() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        _backdated_without_usn(path),
        families={"ntfs.mft", "ntfs.usn"},
        coverage_scopes={"ntfs_usn": None},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "usn_coverage_unavailable"


def test_timestomp_outside_retained_usn_window_is_indeterminate() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        _backdated_without_usn(path),
        families={"ntfs.mft", "ntfs.usn"},
        coverage_scopes={
            "ntfs_usn": {
                "kind": "usn_journal",
                "first_usn": 500,
                "journal_id": 123,
                "lowest_valid_usn": 0,
                "window_validity": "retained_records_within_valid_range",
                "control_identity_bound": True,
                "journal_source": "targets/F/$Extend/$J",
                "order_checked": True,
                "checked_record_count": 2,
                "timestamp_reversal_count": 0,
                "first_timestamp": "2026-02-01 00:00:00",
                "last_usn": 900,
                "last_timestamp": "2026-03-01 00:00:00",
                "window_complete": True,
            }
        },
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "usn_coverage_unavailable"
    assert any("outside the retained USN journal window" in note for note in result.assessments[0].limitations)


def test_timestomp_inside_retained_usn_window_without_change_record_is_not_supported() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    path = r"C:\Users\alice\Desktop\time.txt"
    index = evidence_index(
        _backdated_without_usn(path),
        families={"ntfs.mft", "ntfs.usn"},
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "temporal_basic_info_change_not_observed"


def _usb_input(first_install: str | None, coverage_scopes=None):
    definition = techniques_for_question("Q-MEDIA-01")[0]
    fields = {
        "serial_number": "SERIAL-1",
        "device_instance_id": r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
        "control_set": "ControlSet001",
    }
    fields["first_install"] = first_install if first_install is not None else ""
    index = evidence_index(
        observation("usb", "windows.registry.usbstor", "usb_device_seen", "USB Disk", **fields),
        families={"windows.registry.usbstor", "windows.setupapi"},
        coverage_scopes=coverage_scopes,
    )
    return build_analysis_input(index, definition)


def test_external_media_without_setupapi_window_is_indeterminate() -> None:
    result = analyze_input(_usb_input("2026-01-01 12:00:00", {"windows_setupapi": None}))

    assert result.supported_subjects.subject_ids == ()
    assert result.assessments[0].reason_code == "setupapi_coverage_unavailable"


def test_external_media_install_before_retained_setupapi_window_is_indeterminate() -> None:
    scopes = {
        "windows_setupapi": {
            "kind": "setupapi_log",
            "files": ["setupapi.dev.log"],
            "section_count": 3,
            "first_section_timestamp": "2026-03-01 00:00:00",
            "last_section_timestamp": "2026-04-01 00:00:00",
            "window_complete": True,
        }
    }
    result = analyze_input(_usb_input("2025-12-01 12:00:00", scopes))

    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "setupapi_window_excludes_install"


def test_external_media_install_inside_retained_setupapi_window_is_supported() -> None:
    result = analyze_input(_usb_input("2026-01-01 12:00:00"))

    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == "usbstor_identity_missing_from_setupapi"


def test_external_media_without_any_install_timestamp_is_unverifiable() -> None:
    result = analyze_input(_usb_input(None))

    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "setupapi_window_unverifiable"


def test_prefetch_retained_execution_survives_current_disabled_policy() -> None:
    definition = techniques_for_question("Q-EXEC-01")[0]
    path = r"C:\Users\alice\tool.exe"
    index = evidence_index(
        observation(
            "pf",
            "windows.prefetch",
            "prefetch_execution",
            path,
            mft_active_presence_check_supported=True,
            mft_active_presence_status="active_mft_absent",
        ),
        families={"windows.prefetch", "ntfs.mft"},
        coverage_scopes={
            "windows_prefetch": {
                "kind": "prefetch",
                "enable_prefetcher": 0,
                "application_prefetch_enabled": False,
                "sysmain_disabled": False,
            }
        },
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == "prefetch_execution_with_active_mft_absence"


def _timestomp_index(
    *,
    si_created: str = "2010-01-01T12:00:00.0000000Z",
    si_modified: str = "2010-01-01T12:00:00.0000000Z",
    fn_created: str = "2026-01-01T12:00:00.0000000Z",
    record_changed: str = "2026-01-01T12:05:00.0000000Z",
    usn: tuple[tuple[str, str, str], ...] = (
        ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
    ),
    logfile: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    path = r"C:\Users\alice\Desktop\time.txt"
    mismatches = [
        {"field": "created", "standard_information": si_created, "file_name": fn_created},
        {"field": "modified", "standard_information": si_modified, "file_name": fn_created},
        {"field": "accessed", "standard_information": si_created, "file_name": fn_created},
    ]
    records = [
        observation(
            "time-mft", "ntfs.mft", "si_fn_timestamp_difference", path,
            mismatch_count=3, mft_volume_id="volume:test", mft_entry=42, sequence_number=3,
            mismatches=mismatches, record_changed_si=record_changed,
        )
    ]
    for index, (observation_type, reasons, stamp) in enumerate(usn):
        records.append(
            observation(
                f"time-usn-{index}", "ntfs.usn", observation_type, path,
                mft_volume_id="volume:test", file_reference_entry=42,
                file_reference_sequence=3, update_reasons=reasons, update_timestamp=stamp,
                update_sequence_number=(index + 1) * 8192,
            )
        )
    for index, overrides in enumerate(logfile):
        fields: dict[str, object] = {
            "lsn": 3910657988 + index,
            "transaction_id": 24,
            "transaction_forgotten_lsn": 3910658069,
            "transaction_rolled_back": False,
            "transaction_committed": True,
            "redo_operation": "UpdateResidentValue",
            "mft_volume_id": "volume:test",
            "mft_entry": 42,
            "sequence_number": 3,
            "record_in_use": True,
            "record_lsn": 3910657988,
            "record_lsn_retained": True,
            "covered_fields": "created|modified|record_changed|accessed",
            "old_si_created": fn_created,
            "new_si_created": si_created,
            "old_si_modified": fn_created,
            "new_si_modified": si_modified,
            "old_si_record_changed": fn_created,
            "new_si_record_changed": record_changed,
            "old_si_accessed": fn_created,
            "new_si_accessed": si_created,
            "current_si_created": si_created,
            "current_si_modified": si_modified,
            "current_si_record_changed": record_changed,
            "current_si_accessed": si_created,
            "binding_basis": "current_mft_record",
        }
        fields.update(overrides)
        records.append(
            observation(f"time-logfile-{index}", "ntfs.logfile", "logfile_si_update", path, **fields)
        )
    families = {"ntfs.mft", "ntfs.usn"} | ({"ntfs.logfile"} if logfile else set())
    return evidence_index(*records, families=families)


def test_timestomp_logged_transition_supports_without_journal_corroboration() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(usn=(), logfile=({},))

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert assessment.reason_code == "coordinated_si_backdating_with_logged_si_transition"
    assert any("LSN 3910657988" in note and "committed" in note for note in assessment.limitations)
    assert any(note.startswith("shared_offset_pattern") for note in assessment.limitations)
    assert any("time-logfile-0" in ref for ref in assessment.evidence_refs)


def test_timestomp_logged_transition_is_cited_next_to_journal_corroboration() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(logfile=({},))

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"
    assert any("the retained $LogFile records the same-object" in note for note in assessment.limitations)


def test_logged_transition_near_creation_still_proves_the_timestamp_transition() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        usn=(),
        record_changed="2026-01-01T12:00:01.5000000Z",
        logfile=({"new_si_record_changed": "2026-01-01T12:00:01.5000000Z"},),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert assessment.reason_code == "coordinated_si_backdating_with_logged_si_transition"
    assert any("purpose remain indistinguishable" in note for note in assessment.limitations)


def test_timestomp_logged_transition_requires_commit_and_current_values() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    uncommitted = {"transaction_committed": False, "transaction_forgotten_lsn": None}
    superseded = {"new_si_created": "2009-01-01T12:00:00.0000000Z"}
    small = {
        "old_si_created": "2010-01-01T12:00:30.0000000Z",
        "old_si_modified": "2010-01-01T12:00:30.0000000Z",
    }

    for overrides in (uncommitted, superseded, small):
        assessment = analyze_input(
            build_analysis_input(_timestomp_index(usn=(), logfile=(overrides,)), definition)
        ).assessments[0]
        assert assessment.outcome == "not_supported"
        assert assessment.reason_code == "temporal_basic_info_change_not_observed"
    for overrides, marker in ((uncommitted, "logfile_transition_uncommitted"), (superseded, "logfile_transition_superseded")):
        assessment = analyze_input(
            build_analysis_input(_timestomp_index(logfile=(overrides,)), definition)
        ).assessments[0]
        assert assessment.reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"
        assert any(note.startswith(marker) for note in assessment.limitations)
        assert not any("the retained $LogFile records the same-object" in note for note in assessment.limitations)


def test_timestomp_logged_access_rewrite_from_backdated_value_is_a_signature() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        logfile=(
            {
                "covered_fields": "accessed",
                "old_si_created": None, "new_si_created": None,
                "old_si_modified": None, "new_si_modified": None,
                "old_si_record_changed": None, "new_si_record_changed": None,
                "old_si_accessed": "2010-01-01T12:00:00.0000000Z",
                "new_si_accessed": "2026-01-01T12:07:00.0000000Z",
            },
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert assessment.reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"
    assert any(
        note.startswith("logfile_access_rewrite_from_backdated_value") for note in assessment.limitations
    )
    silent = _timestomp_index(
        usn=(),
        logfile=(
            {
                "covered_fields": "accessed",
                "old_si_created": None, "new_si_created": None,
                "old_si_modified": None, "new_si_modified": None,
                "old_si_record_changed": None, "new_si_record_changed": None,
                "old_si_accessed": "2010-01-01T12:00:00.0000000Z",
                "new_si_accessed": "2026-01-01T12:07:00.0000000Z",
            },
        ),
    )
    assert analyze_input(build_analysis_input(silent, definition)).assessments[0].outcome == "not_supported"


def test_timestomp_logged_record_change_backdating_is_reported() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        usn=(),
        record_changed="2010-01-01T12:00:00.0000000Z",
        logfile=({"new_si_record_changed": "2010-01-01T12:00:00.0000000Z"},),
    )

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.outcome == "supported"
    assert any(note.startswith("logfile_record_change_backdated") for note in assessment.limitations)


def test_timestomp_rule_v3_reports_shared_offset_and_whole_seconds_as_signatures() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]

    result = analyze_input(build_analysis_input(_timestomp_index(), definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert any(note.startswith("shared_offset_pattern") for note in assessment.limitations)
    assert any(
        note.startswith("sub_second_zeros: SI created and modified")
        for note in assessment.limitations
    )


def test_timestomp_rule_v3_requires_at_least_one_minute_of_backdating() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        si_created="2026-01-01T11:59:30.0000000Z",
        si_modified="2026-01-01T11:59:30.0000000Z",
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "coordinated_si_backdating_not_observed"


def test_timestamp_indicator_does_not_attribute_a_create_and_set_record() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        fn_created="2026-01-01T12:05:00.0000000Z",
        record_changed="2026-01-01T12:05:00.0000000Z",
        usn=(
            ("usn_filesystem_activity", "FILE_CREATE", "2026-01-01T12:05:00.0000000Z"),
            ("usn_filesystem_activity", "DATA_EXTEND|FILE_CREATE", "2026-01-01T12:05:00.0000000Z"),
            (
                "usn_basic_info_change",
                "DATA_EXTEND|FILE_CREATE|BASIC_INFO_CHANGE|CLOSE",
                "2026-01-01T12:05:00.0312500Z",
            ),
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "supported"
    assert result.assessments[0].reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"
    assert any("ordinary copying/restoration" in note for note in result.assessments[0].limitations)


def test_timestamp_indicator_includes_restoration_after_a_separate_creation() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        fn_created="2026-01-01T12:04:59.0000000Z",
        record_changed="2026-01-01T12:05:00.0000000Z",
        usn=(
            ("usn_filesystem_activity", "FILE_CREATE|DATA_EXTEND|CLOSE", "2026-01-01T12:04:59.0000000Z"),
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"


def test_timestomp_rule_v3_keeps_supporting_a_stomp_of_an_existing_object() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        usn=(
            ("usn_filesystem_activity", "FILE_CREATE|DATA_EXTEND|CLOSE", "2026-01-01T12:00:00.0000000Z"),
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "supported"


def test_timestomp_rule_v3_supports_a_late_last_basic_info_change() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        record_changed="2010-01-01T12:00:00.0000000Z",
        usn=(
            ("usn_filesystem_activity", "FILE_CREATE|DATA_EXTEND|CLOSE", "2026-01-01T12:00:00.0000000Z"),
            ("usn_basic_info_change", "BASIC_INFO_CHANGE", "2026-01-01T12:05:00.0312500Z"),
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assessment = result.assessments[0]
    assert assessment.outcome == "supported"
    assert assessment.reason_code == "si_fn_backdating_with_later_basic_info_change"
    assert any("does not prove that record-change was rewritten" in note for note in assessment.limitations)


def test_timestomp_rule_v3_late_basic_info_change_must_be_the_last_journal_record() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        record_changed="2010-01-01T12:00:00.0000000Z",
        usn=(
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
            ("usn_filesystem_activity", "DATA_OVERWRITE|CLOSE", "2026-01-01T12:09:00.0000000Z"),
        ),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "temporal_basic_info_change_not_observed"


def test_timestomp_rule_v3_late_branch_needs_a_full_minute() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        record_changed="2026-01-01T12:04:01.0000000Z",
        usn=(("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0000000Z"),),
    )

    result = analyze_input(build_analysis_input(index, definition))

    assert result.assessments[0].outcome == "not_supported"
    assert result.assessments[0].reason_code == "temporal_basic_info_change_not_observed"
