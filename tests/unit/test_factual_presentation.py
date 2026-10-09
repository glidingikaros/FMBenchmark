from copy import deepcopy

import pytest

from fmb.analysis.factual_contract import (
    deterministic_factual_response,
    upgrade_factual_bundle,
    validate_factual_response,
)
from fmb.analysis.factual_presentation import (
    expand_payload,
    filetime_decimal,
    normalized_payload,
    present_bundle,
    translate_response,
)
from fmb.analysis.shared_evidence import EvidenceBundle
from fmb.index.adapters.mft import _matching_raw_mft_file_name
from paper_fixtures import log_bundle, time_bundle


def native_time_bundle():
    payload = time_bundle().payload
    card = payload["candidate_roster"][0]
    card["evidence_records"].append(
        {
            "record_type": "logfile_si_update",
            "artifact_family": "ntfs.logfile",
            "subject_ref": card["display_name"],
            "source_record_ref": "native:LogFile:lsn=123",
            "fields": {
                "old_si_modified": "2026-09-15T16:44:24.5792971Z",
                "new_si_modified": "2026-09-15T16:44:24.5792970Z",
            },
        }
    )
    return EvidenceBundle.from_payload(payload)


@pytest.mark.parametrize(
    "source", [time_bundle, lambda: log_bundle([100, 103], event_ids=[1102, 4624])]
)
def test_encoding_retains_all_facts_provenance_and_factual_decisions(source):
    old = upgrade_factual_bundle(source())
    before = old.canonical
    new = present_bundle(old)
    assert old.canonical == before
    assert expand_payload(new.payload) == normalized_payload(old.payload)
    expected = deterministic_factual_response(old)
    actual = deterministic_factual_response(new)
    assert translate_response(new, actual, to_original=True) == expected


def test_native_precision_is_not_rounded_and_numeric_fields_are_strings():
    assert filetime_decimal("2026-09-15T16:44:24.5792971Z") == "134339642645792971"
    assert filetime_decimal("2026-09-15T16:44:24.579297Z") == "134339642645792970"
    assert filetime_decimal(None) is None
    new = present_bundle(upgrade_factual_bundle(native_time_bundle()))
    record = next(
        r
        for c in new.payload["candidate_roster"]
        for r in c["evidence_records"]
        if r["record_type"] == "logfile_si_update"
    )
    for row in record["fields"]["timestamp_updates"]:
        for key, value in row.items():
            if key.endswith("_filetime_decimal"):
                assert value is None or isinstance(value, str)


def test_changed_numeric_encoding_or_annotation_is_rejected():
    new = present_bundle(upgrade_factual_bundle(native_time_bundle()))
    payload = new.payload
    row = next(
        r
        for c in payload["candidate_roster"]
        for r in c["evidence_records"]
        if r["record_type"] == "logfile_si_update"
    )["fields"]["timestamp_updates"][0]
    row["before_filetime_decimal"] = "1"
    with pytest.raises(ValueError, match="disagree"):
        EvidenceBundle.from_payload(payload)
    payload = new.payload
    payload["presentation"]["answer_hint"] = "positive"
    with pytest.raises(ValueError, match="annotations"):
        EvidenceBundle.from_payload(payload)


def test_compact_response_still_requires_every_subject_and_component():
    new = present_bundle(
        upgrade_factual_bundle(log_bundle([100, 103], event_ids=[1102, 4624]))
    )
    response = deterministic_factual_response(new)
    sid = new.subject_ids[0]
    del response["assessments"][sid]["event_record_sequence_gap"]
    with pytest.raises(Exception, match="required property"):
        validate_factual_response(new, response)


def test_short_references_resolve_but_invented_references_remain_errors():
    old = upgrade_factual_bundle(log_bundle([100, 103], event_ids=[1102, 4624]))
    new = present_bundle(old)
    response = deterministic_factual_response(new)
    assert not validate_factual_response(new, response)["citation_errors"]
    component = response["assessments"][new.subject_ids[0]]["event_record_sequence_gap"]
    assert all(
        ref in new.payload["source_reference_map"] for ref in component["evidence_refs"]
    )
    component["evidence_refs"].append("r99999")
    assert validate_factual_response(new, response)["citation_errors"]


def test_stream_filename_binds_to_host_only_with_native_named_data():
    native_name = {
        "name": "host.txt",
        "namespace_name": "win32",
        "parent_inode": 5,
        "parent_sequence": 2,
    }
    parsed = {
        "file_name_attributes": [native_name],
        "data_attributes": [{"is_named_stream": True, "stream_name": "notes"}],
    }
    fields = {
        "file_name": "host.txt:notes",
        "parent_entry_number": 5,
        "parent_sequence_number": 2,
    }
    assert _matching_raw_mft_file_name(parsed, fields) is native_name
    for change in ("wrong_stream", "wrong_host", "wrong_parent", "no_native_stream"):
        p, f = deepcopy(parsed), deepcopy(fields)
        if change == "wrong_stream":
            f["file_name"] = "host.txt:missing"
        if change == "wrong_host":
            f["file_name"] = "other.txt:notes"
        if change == "wrong_parent":
            f["parent_sequence_number"] = 3
        if change == "no_native_stream":
            p["data_attributes"] = []
        with pytest.raises(ValueError):
            _matching_raw_mft_file_name(p, f)


