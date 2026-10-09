from __future__ import annotations
from copy import deepcopy


import json


from pathlib import Path


import pytest


from fmb.analysis.catalog import techniques_for_question


from fmb.analysis.inputs import build_analysis_input


from fmb.analysis.shared_evidence import EvidenceBundle, EVIDENCE_BUNDLE_VERSION, SHARED_RESPONSE_SCHEMA, prepare_evidence_bundles, pack_event_records, unpack_event_records


from fmb.analysis.shared_rules import analyze_evidence_bundle


from fmb.analysis.factual_contract import upgrade_factual_bundle


from fmb.analysis.questions import broad_question


from paper_fixtures import prepare_analysis_inputs


from fmb.core.json_io import load_json


def time_bundle():
    path = (
        Path(__file__).resolve().parents[2]
        / "tests/fixtures/assessment/case_time_01.evidence_index.json"
    )
    return prepare_evidence_bundles(
        prepare_analysis_inputs(load_json(path), question_id="Q-TIME-01")
    )[0]


def bundle_for(question_id, fields, *, kind, family, identity=None, families=None):
    question = broad_question(question_id)
    identity = identity or {"object_id": "event-log:fixture"}
    families = families or [family]
    return EvidenceBundle.from_payload(
        {
            "schema_version": EVIDENCE_BUNDLE_VERSION,
            "task": "assess_candidate_roster",
            "question": {
                "question_id": question_id,
                "title": question.title,
                "question_text": question.question_text,
            },
            "coverage": [
                {"artifact_family": f, "status": "complete"} for f in families
            ],
            "candidate_roster": [
                {
                    "subject_id": "subject:fixture",
                    "subject_type": "file",
                    "display_name": "fixture",
                    "identity": identity,
                    "coverage": [
                        {"artifact_family": f, "collection_status": "complete"}
                        for f in families
                    ],
                    "evidence_records": [
                        {
                            "artifact_family": family,
                            "record_type": kind,
                            "subject_ref": "fixture",
                            "source_record_ref": "source:fixture",
                            "fields": fields,
                        }
                    ],
                }
            ],
            "response_schema": SHARED_RESPONSE_SCHEMA,
        }
    )


@pytest.mark.parametrize(
    "name",
    [
        "claim_boundary",
        "internal_gap_count",
        "native_identity_consistent",
        "classification",
    ],
)
def test_bundle_rejects_derived_findings(name):
    value = time_bundle().payload
    value["candidate_roster"][0]["evidence_records"][0]["fields"][name] = "supported"
    with pytest.raises(ValueError):
        EvidenceBundle.from_payload(value)


def test_unknown_fact_and_conflicting_physical_record_are_rejected():
    value = time_bundle().payload
    record = value["candidate_roster"][0]["evidence_records"][0]
    record["fields"]["answer_hint"] = "yes"
    with pytest.raises(ValueError, match="unregistered"):
        EvidenceBundle.from_payload(value)
    record["fields"].pop("answer_hint")
    duplicate = deepcopy(record)
    duplicate["fields"]["si_created"] = "2001-01-01T00:00:00Z"
    value["candidate_roster"][0]["evidence_records"].append(duplicate)
    with pytest.raises(ValueError, match="disagree"):
        EvidenceBundle.from_payload(value)


def log_bundle(ids, *, event_ids=None, complete=True):
    event_ids = event_ids or [4624] * len(ids)
    fields = {
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_log_scope_id": "event-log:fixture",
        "record_count": len(ids),
        "first_event_record_id": min(ids),
        "last_event_record_id": max(ids),
        "native_record_projection_complete": complete,
        "retained_event_records_complete": complete,
        "collection_scope": "complete_retained_native_log",
        "retained_event_records": [
            {
                "event_record_id": rid,
                "event_id": eid,
                "channel": "Security",
                "provider": "Microsoft-Windows-Eventlog"
                if eid in (1101, 1102)
                else "Microsoft-Windows-Security-Auditing",
                "time_created": "2026-09-12T10:00:00Z",
                "source_file": "Security.evtx",
                "source_record_ref": f"Security.csv:row={i}",
            }
            for i, (rid, eid) in enumerate(zip(ids, event_ids))
        ],
    }
    fields["retained_event_records"] = pack_event_records(
        fields["retained_event_records"]
    )
    return bundle_for(
        "BQ-LOG-01",
        fields,
        kind="retained_security_event_inventory",
        family="windows.event_log.record_sequence",
        families=["windows.event_log.record_sequence", "windows.event_log.security"],
    )


@pytest.mark.parametrize(
    "ids,events,expected",
    [
        ([100, 101, 102, 103], None, "not_supported"),
        ([100, 101, 103, 104], None, "supported"),
        ([100, 101, 103, 104], [4624, 1101, 4624, 4624], "supported"),
        ([100, 101, 102, 103], [4624, 4624, 1102, 4624], "supported"),
    ],
)
def test_log_inventory_exposes_normal_and_anomalous_headers_equally(
    ids, events, expected
):
    bundle = log_bundle(ids, event_ids=events)
    assert (
        len(
            unpack_event_records(
                bundle.payload["candidate_roster"][0]["evidence_records"][0]["fields"][
                    "retained_event_records"
                ]
            )
        )
        == 4
    )
    assert analyze_evidence_bundle(upgrade_factual_bundle(bundle)).assessments[0].outcome == expected


def test_event_table_compression_is_lossless_across_dates_and_ordinary_records():
    rows = [
        {
            "event_id": 4624 + i % 2,
            "event_record_id": 100 + i,
            "channel": "Security",
            "provider": "provider-" + str(i % 2),
            "time_created": f"{2020 + i % 2}-09-12 12:00:00.{i:07d}",
            "source_file": "Security.evtx",
            "source_record_ref": f"events.csv:row={i + 1}",
        }
        for i in range(100)
    ]
    packed = pack_event_records(rows)
    assert unpack_event_records(packed) == rows
    assert packed["column_encodings"]["time_created"]["kind"] == "prefix_dictionary"
    assert len(json.dumps(packed)) < len(json.dumps(rows))
    broken = deepcopy(packed)
    index = broken["columns"].index("provider")
    broken["rows"][0][index] = -1
    with pytest.raises(ValueError, match="position"):
        unpack_event_records(broken)


def test_legacy_event_summaries_are_insufficient_without_ordinary_records():
    assert (
        analyze_evidence_bundle(upgrade_factual_bundle(log_bundle([100, 101, 103], complete=False)))
        .assessments[0]
        .outcome
        == "indeterminate"
    )


@pytest.mark.parametrize("defect", ["identity", "provider", "source_file"])
def test_security_records_require_the_exact_log_identity_and_clear_provider(defect):
    payload = log_bundle([100, 101, 102], event_ids=[4624, 1102, 4624]).payload
    if defect == "identity":
        payload["candidate_roster"][0]["identity"]["object_id"] = "event-log:other"
    else:
        fields = payload["candidate_roster"][0]["evidence_records"][0]["fields"]
        rows = unpack_event_records(fields["retained_event_records"])
        if defect == "provider":
            rows[1]["provider"] = "Other-Provider"
        else:
            rows[1]["source_file"] = r"D:\Recovered\Security.evtx"
        fields["retained_event_records"] = pack_event_records(rows)
    assert (
        analyze_evidence_bundle(upgrade_factual_bundle(EvidenceBundle.from_payload(payload)))
        .assessments[0]
        .outcome
        == "indeterminate"
    )


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "uncommitted",
        "rolled_back",
        "different_sequence",
        "unbound",
        "not_current",
        "access_only",
    ],
)
def test_single_field_native_backdating_needs_a_committed_current_object_transition(
    defect,
):
    payload = time_bundle().payload
    card = payload["candidate_roster"][0]
    payload["candidate_roster"] = [card]
    current = next(
        r for r in card["evidence_records"] if r["record_type"] == "mft_record"
    )
    for prefix in ("si_", "fn_"):
        for name in ("created", "modified", "record_changed", "accessed"):
            current["fields"][prefix + name] = "2026-09-12T12:00:00.0000000Z"
    fields = {k: current["fields"][k] for k in ("mft_volume_id", "sequence_number")}
    fields.update(
        mft_entry=current["fields"].get(
            "mft_entry", current["fields"].get("entry_number")
        ),
        lsn=123,
        transaction_id=10,
        transaction_committed=True,
        transaction_rolled_back=False,
        binding_basis="current_mft_record",
        covered_fields="modified",
        old_si_modified="2026-09-12T12:00:00.0000001Z",
        new_si_modified="2026-09-12T12:00:00.0000000Z",
    )
    if defect == "uncommitted":
        fields["transaction_committed"] = False
    elif defect == "rolled_back":
        fields["transaction_rolled_back"] = True
    elif defect == "different_sequence":
        fields["sequence_number"] += 1
    elif defect == "unbound":
        fields["binding_basis"] = "unbound"
    elif defect == "not_current":
        fields["new_si_modified"] = "2020-09-12T12:00:00.0000000Z"
    elif defect == "access_only":
        fields["covered_fields"] = "accessed"
        fields["old_si_accessed"] = fields.pop("old_si_modified")
        fields["new_si_accessed"] = fields.pop("new_si_modified")
    card["evidence_records"] = [
        current,
        {
            "record_type": "logfile_si_update",
            "artifact_family": "ntfs.logfile",
            "subject_ref": current["subject_ref"],
            "source_record_ref": "LogFile:lsn=123",
            "fields": fields,
        },
    ]
    result = analyze_evidence_bundle(upgrade_factual_bundle(EvidenceBundle.from_payload(payload)))
    assert result.assessments[0].outcome == (
        "supported" if defect is None else "not_supported"
    )


def test_raw_usb_directory_rows_reach_both_engines_and_change_the_result():
    from test_usb_volume import facts
    from fmb.analysis.shared_evidence import _record
    from fmb.analysis.domain import Observation

    fields = facts()
    raw = {
        "observation_id": "obs:usb",
        "artifact_family": "usb_volume",
        "observation_type": "usb_volume_reference_history",
        "subject_ref": fields["device_instance_id"],
        "fields": fields,
        "source_record_ref": "source:fixture",
    }
    index = {
        "schema_version": "evidence_index.v1",
        "run_id": "fixture",
        "parser_runs": [
            {
                "parser_kind": "native_usb_volume",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": [raw],
            }
        ],
    }
    definition = next(
        t
        for t in techniques_for_question("Q-MEDIA-01")
        if t.technique_id == "usb_volume_activity_gap"
    )
    value = build_analysis_input(index, definition)
    subject = value.candidate_roster.subjects[0]
    projected = _record(value, Observation(**raw), subject)
    original = bundle_for(
        "BQ-USB-01",
        projected["fields"],
        kind="native_usb_reference_history",
        family="usb_volume",
        identity=subject.identity,
    )
    changed = original.payload
    raw_fields = changed["candidate_roster"][0]["evidence_records"][0]["fields"]
    assert "original_path_lookup" not in raw_fields
    raw_fields["companion_directory_rows"].append({
        "mft_entry": 40, "sequence_number": 2, "in_use": True,
        "path": raw_fields["link_target_path"][2:],
    })
    raw_fields["companion_directory_scope"]["row_count"] = len(raw_fields["companion_directory_rows"])
    changed = EvidenceBundle.from_payload(changed)
    assert analyze_evidence_bundle(upgrade_factual_bundle(original)).assessments[0].outcome == "supported"
    assert analyze_evidence_bundle(upgrade_factual_bundle(changed)).assessments[0].outcome == "not_supported"
    assert original.sha256 != changed.sha256
    assert original.payload != changed.payload
    wrong = original.payload
    wrong["candidate_roster"][0]["identity"]["serial_number"] = "another-device"
    assert (
        analyze_evidence_bundle(upgrade_factual_bundle(EvidenceBundle.from_payload(wrong)))
        .assessments[0]
        .outcome
        == "indeterminate"
    )


def test_native_bmp_size_is_preserved_and_not_recomputed_from_eof():
    from test_file_content_adapter import bmp_bytes
    from fmb.index.adapters.file_content import bmp_content_observation

    native = bmp_content_observation(
        content=bmp_bytes(trailing=b"padding"),
        subject_ref=r"C:\Users\alice\sample.bmp",
        volume_id="volume-c",
        mft_entry=42,
        sequence_number=3,
    )
    assert native["fields"]["bmp_header_file_size"] == 58
    assert native["fields"]["materialized_size"] == 65


def test_subminute_backdating_is_not_a_hidden_negative_label():
    bundle = time_bundle()
    original = analyze_evidence_bundle(upgrade_factual_bundle(bundle))
    payload = bundle.payload
    from datetime import datetime, timedelta

    for card in payload["candidate_roster"]:
        if card["subject_id"] not in original.supported_subjects.subject_ids:
            continue
        for record in card["evidence_records"]:
            if record["record_type"] == "mft_record":
                for name in ("created", "modified"):
                    fn = datetime.fromisoformat(
                        record["fields"]["fn_" + name].replace("Z", "+00:00")
                    )
                    record["fields"]["si_" + name] = (
                        fn - timedelta(seconds=2)
                    ).isoformat()
    changed = analyze_evidence_bundle(upgrade_factual_bundle(EvidenceBundle.from_payload(payload)))
    assert changed.supported_subjects == original.supported_subjects


