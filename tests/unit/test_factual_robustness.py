from __future__ import annotations
from copy import deepcopy


import pytest


from fmb.analysis.factual_contract import COMPONENT_TARGETS, upgrade_factual_bundle, validate_factual_response


from fmb.analysis.questions import BROAD_QUESTIONS


from fmb.analysis.shared_rules import analyze_evidence_bundle


from fmb.analysis.shared_evidence import EvidenceBundle, build_evidence_bundle


from fmb.index.support.windows_identity import volume_is_comparable


from test_prefetch_identity_policy import _input, _parse


from paper_fixtures import log_bundle, time_bundle


@pytest.mark.parametrize("active", [True, False])
def test_foreign_volume_is_unknown_even_when_its_suffix_exists_locally(tmp_path, active):
    from rule_helpers import analyze_input
    run = _parse(tmp_path, [r"\VOLUME{01dc111111111111-deadbeef}\Present\RUNNER.EXE"], active=active)
    assert analyze_input(_input(run)).assessments[0].outcome == "indeterminate"


def test_native_volume_token_needs_exact_source_membership():
    token = "volume{01dc111111111111-deadbeef}"
    assert not volume_is_comparable(token, {"c"})
    assert volume_is_comparable(token, {token})
    assert not volume_is_comparable("volume{other}", {token})


def test_response_targets_cover_every_component_without_expected_labels():
    assert set(COMPONENT_TARGETS) == {t for q in BROAD_QUESTIONS for t in q.technique_ids}


def test_factual_upgrade_preserves_cards_and_historical_input():
    old = time_bundle()
    before = old.canonical
    new = upgrade_factual_bundle(old)
    assert old.canonical == before
    assert old.payload["candidate_roster"] == new.payload["candidate_roster"]
    assert old.payload["question"] == new.payload["question"]
    assert old.sha256 != new.sha256


def test_component_response_cannot_hide_gap_miss_behind_1102():
    bundle = upgrade_factual_bundle(log_bundle([100, 103], event_ids=[1102, 4624]))
    sid = bundle.subject_ids[0]
    item = {"status": "supported", "evidence_refs": [], "related_object_ids": [], "statement": "Retained event."}
    response = {"assessments": {sid: {t: deepcopy(item) for t in ("security_log_clear_event", "event_record_sequence_gap")}}}
    response["assessments"][sid]["event_record_sequence_gap"]["status"] = "not_supported"
    projection = validate_factual_response(bundle, response)
    assert projection["supported_subject_ids"] == [sid]
    assert len(response["assessments"][sid]) == 2
    assert projection["supported_without_citation"] == [{"subject_id": sid, "component": "security_log_clear_event"}]
    response["assessments"][sid]["security_log_clear_event"]["evidence_refs"] = ["invented"]
    assert validate_factual_response(bundle, response)["citation_errors"]
    del response["assessments"][sid]["event_record_sequence_gap"]
    with pytest.raises(Exception, match="required property"):
        validate_factual_response(bundle, response)


@pytest.mark.parametrize("defect", [None, "different_generation", "rolled_back", "uncommitted", "unretained_current_lsn"])
@pytest.mark.parametrize("fragment", [False, True])
def test_historical_backdate_survives_later_forward_update_only_with_binding(defect, fragment):
    payload = time_bundle().payload
    card = payload["candidate_roster"][0]
    payload["candidate_roster"] = [card]
    current = next(r for r in card["evidence_records"] if r["record_type"] == "mft_record")
    for prefix in ("si_", "fn_"):
        for field in ("created", "modified", "record_changed", "accessed"):
            current["fields"][prefix + field] = "2026-09-12T12:00:00.0000000Z"
    fields = {k: current["fields"][k] for k in ("mft_volume_id", "sequence_number")}
    fields.update(mft_entry=current["fields"].get("mft_entry", current["fields"].get("entry_number")),
                  lsn=123, record_lsn=140, record_lsn_retained=True, record_in_use=True,
                  transaction_id=10, transaction_committed=True, transaction_rolled_back=False,
                  binding_basis="current_mft_record", covered_fields="modified",
                  old_si_modified="2026-09-12T11:00:00.0000000Z",
                  new_si_modified="2020-09-12T11:00:00.0000000Z")
    if fragment:
        fields.pop("old_si_modified")
        fields.pop("new_si_modified")
        fields["covered_fields"] = ""
        fields["si_timestamp_fragments"] = [{"field": "modified", "byte_order": "little",
            "field_width_bytes": 8, "offset_in_field": 1,
            "undo_hex": "c827773145dd01", "redo_hex": "08be4c6844dd01"}]
    if defect == "different_generation":
        fields["sequence_number"] += 1
    elif defect == "rolled_back":
        fields["transaction_rolled_back"] = True
    elif defect == "uncommitted":
        fields["transaction_committed"] = False
    elif defect == "unretained_current_lsn":
        fields["record_lsn_retained"] = False
    card["evidence_records"] = [current, {
        "record_type": "logfile_si_update", "artifact_family": "ntfs.logfile",
        "subject_ref": current["subject_ref"], "source_record_ref": "LogFile:lsn=123", "fields": fields,
    }]
    new = upgrade_factual_bundle(EvidenceBundle.from_payload(payload))
    assert analyze_evidence_bundle(new).assessments[0].outcome == ("supported" if defect is None else "not_supported")


@pytest.mark.parametrize("has_clear", [True, False])
def test_incomplete_export_can_prove_retained_clear_but_not_internal_gap(has_clear):
    payload = log_bundle([100, 103], event_ids=[1102 if has_clear else 4624, 4624]).payload
    card = payload["candidate_roster"][0]
    for coverage in card["coverage"]:
        coverage["collection_status"] = "partial"
    fields = card["evidence_records"][0]["fields"]
    fields["retained_event_records_complete"] = False
    fields["collection_scope"] = "partial_retained_native_log"
    new = upgrade_factual_bundle(EvidenceBundle.from_payload(payload))
    result = analyze_evidence_bundle(new)
    parts = result.analyzer_metadata["component_assessments"][new.subject_ids[0]]
    assert parts["security_log_clear_event"]["outcome"] == ("supported" if has_clear else "indeterminate")
    assert parts["event_record_sequence_gap"]["outcome"] == "indeterminate"


def test_positive_stream_not_suppressed_by_an_unreadable_sibling():
    from fmb.analysis.catalog import technique_definition
    from fmb.analysis.inputs import build_analysis_input
    from test_stefan_analysis import ads_records, pe_bytes
    records = ads_records(pe_bytes())
    sibling = deepcopy(ads_records(b"ordinary metadata", content_complete=False))
    for row in sibling:
        row["fields"]["stream_name"] = "second_stream"
        row["observation_id"] += "2"
        row["source_record_ref"] += "2"
    index = {"schema_version": "evidence_index.v1", "run_id": "mixed-native-streams",
             "parser_runs": [{"parser_kind": "ntfs_ads", "status": "consumed", "coverage_status": "complete",
                              "observations": records + sibling}]}
    value = build_analysis_input(index, technique_definition("alternate_data_stream"))
    bundle = upgrade_factual_bundle(build_evidence_bundle([value], "BQ-STREAM-01"))
    assert analyze_evidence_bundle(bundle).assessments[0].outcome == "supported"


@pytest.mark.parametrize("data", [b"MZ\x00\x01demo", b"PK\x03\x04demo", b"MZ" + b"\x00" * 60])
@pytest.mark.parametrize("complete", [True, False])
def test_native_complete_short_signature_is_a_decoy_but_partial_extraction_is_unknown(data, complete):
    from fmb.analysis.catalog import technique_definition
    from fmb.analysis.inputs import build_analysis_input
    from test_stefan_analysis import ads_records
    index = {"schema_version": "evidence_index.v1", "run_id": "native-signature-decoy",
             "artifact_coverage": [{"artifact_family": f, "status": "complete"} for f in ("ntfs.ads", "ntfs.mft")],
             "parser_runs": [{"parser_kind": "ntfs_ads", "status": "consumed", "coverage_status": "complete",
                              "observations": ads_records(data, content_complete=complete)}]}
    value = build_analysis_input(index, technique_definition("alternate_data_stream"))
    bundle = upgrade_factual_bundle(build_evidence_bundle([value], "BQ-STREAM-01"))
    assert analyze_evidence_bundle(bundle).assessments[0].outcome == ("not_supported" if complete else "indeterminate")


@pytest.mark.parametrize("sequence,live,path,complete,expected", [
    (3, True, r"C:\Work\renamed.txt", True, "not_supported"),
    (4, True, r"C:\Work\old.txt", True, "supported"),
    (3, False, r"C:\Work\old.txt", True, "supported"),
    (4, True, r"C:\Work\old.txt", False, "indeterminate"),
])
def test_comparison_assessor_distinguishes_original_object_from_path_replacement(sequence, live, path, complete, expected):
    from fmb.analysis.catalog import techniques_for_question
    from fmb.analysis.inputs import build_analysis_input
    from fmb.analysis.mft_comparison import with_comparison_pool
    from test_deterministic_analysis import observation

    record = observation("historical", "ntfs.usn", "usn_file_delete", r"C:\Work\old.txt",
                         mft_active_presence_status="active_mft_absent", mft_active_presence_check_supported=True)
    index = {"schema_version": "evidence_index.v1", "run_id": "comparison-fixture",
             "artifact_coverage": [{"artifact_family": f, "status": "complete"} for f in ("ntfs.usn", "ntfs.mft")],
             "parser_runs": [{"parser_kind": "ntfs_usn", "status": "consumed", "coverage_status": "complete", "observations": [record]}]}
    value = build_analysis_input(index, techniques_for_question("Q-DEL-01")[0])
    other = build_analysis_input(index, techniques_for_question("Q-DEL-02")[0])
    base = upgrade_factual_bundle(build_evidence_bundle([value, other], "BQ-DELETE-01"))
    pool = {"mft_volume_id": "volume:test", "source_record_ref": "mft:scan", "source_sha256": "a" * 64,
            "reference_complete": complete, "path_complete": complete, "volume_aliases": ["c"], "native_volume_observations": [],
            "entry_intervals": [{"first": 32, "last": 63}], "path_prefixes": ["work\\"],
            "records": [{"entry": 42, "sequence": sequence, "in_use": live, "path": path, "source_record_ref": "mft:42"},
                        {"entry": 43, "sequence": 1, "in_use": True, "path": r"C:\Work\other.txt", "source_record_ref": "mft:43"}]}
    old_payload = base.payload
    for card in old_payload["candidate_roster"]:
        for coverage in card["coverage"]:
            if coverage["artifact_family"] == "ntfs.mft":
                coverage["collection_status"] = "partial"
    bundle = with_comparison_pool(EvidenceBundle.from_payload(old_payload), pool)
    assert "active_mft_lookup" not in str(bundle.payload["candidate_roster"])
    assert len(bundle.payload["current_mft_pools"][0]["records"]) == 2
    assert analyze_evidence_bundle(bundle).assessments[0].outcome == expected


@pytest.mark.parametrize("vdl,expected", [(0, "not_supported"), (4097, "not_supported"), (4098, "supported"), (None, "indeterminate")])
def test_native_valid_data_length_is_not_confused_with_allocation_rounding(vdl, expected):
    from paper_fixtures import bundle_for
    from test_stefan_analysis import allocation_fields
    fields = allocation_fields(valid_data_length=vdl, total_clusters=1000,
                               data_runs=[{"vcn": 0, "lcn": 50, "cluster_count": 2}])
    fields.pop("runlist_in_volume")
    fields.pop("runlist_physical_overlap")
    bundle = bundle_for("BQ-FILE-01", fields, kind="ntfs_allocation_attribute", family="ntfs.file_size_allocation",
                        identity={"object_id": "ntfs:volume:test:42:3"}, families=["ntfs.mft", "ntfs.file_size_allocation"])
    assert analyze_evidence_bundle(upgrade_factual_bundle(bundle)).assessments[0].outcome == expected


