from copy import deepcopy
import json

import jsonschema
import pytest

from fmb.core.case_contract import (
    SYSTEM_PROMPT, PHENOMENA, _localize_pools, prepare_case, bundle_from_case,
    response_schema,
    target_catalog, validate_response,
)
from fmb.assessment.rules import assess as deterministic_response
from paper_fixtures import log_bundle, score_case


@pytest.mark.parametrize("ids,events,count", [
    ([100, 101], [1102, 4624], 1),
    ([100, 103], [4624, 4624], 1),
    ([100, 101], [4624, 4624], 0),
    ([100, 103], [1102, 4624], 2),
])
def test_log_findings_remain_separate_and_input_is_unchanged(ids, events, count):
    case = prepare_case(log_bundle(ids, event_ids=events))
    frozen = deepcopy(case)
    prediction = deterministic_response(case)
    assert len(prediction["supported_findings"]) == count
    assert not prediction["insufficient_findings"]
    assert case == frozen
    assert len(target_catalog(case)) == 2


def test_subject_hit_cannot_hide_an_extra_or_missing_target():
    case = prepare_case(log_bundle([100, 101], event_ids=[1102, 4624]))
    correct = deterministic_response(case)
    expected = set(correct["supported_findings"])
    extra = set(target_catalog(case)) - expected
    incorrect = {"supported_findings": sorted(expected | extra), "insufficient_findings": []}
    score = score_case(case, incorrect, expected)
    assert score["finding_counts"]["tp"] == 3 and score["finding_counts"]["fp"] == 3
    assert score["exact_question_passes"] == 0
    score = score_case(case, correct, expected | extra)
    assert score["finding_counts"]["fn"] == 3 and score["exact_question_passes"] == 0


def test_negative_abstention_is_visible_and_positive_abstention_is_a_miss():
    case = prepare_case(log_bundle([100, 101], event_ids=[1102, 4624]))
    ids = sorted(target_catalog(case))
    response = {"supported_findings": [], "insufficient_findings": ids}
    expected = set(deterministic_response(case)["supported_findings"])
    score = score_case(case, response, expected)
    assert score["finding_counts"]["fn"] == 3 and score["finding_counts"]["tn"] == 0
    assert score["finding_counts"]["unresolved"] == 3 and score["exact_question_passes"] == 0


def test_ambiguous_invalid_or_invented_ids_are_not_silently_scored():
    case = prepare_case(log_bundle([100, 103], event_ids=[1102, 4624]))
    response = deterministic_response(case)
    response["insufficient_findings"] = response["supported_findings"][:1]
    with pytest.raises(ValueError, match="supported and unresolved"):
        validate_response(case, response)
    response = {"supported_findings": ["finding:invented"], "insufficient_findings": []}
    with pytest.raises(jsonschema.ValidationError):
        validate_response(case, response)


def test_task_and_schema_name_targets_without_detection_procedures():
    case = prepare_case(log_bundle([100, 103], event_ids=[1102, 4624]))
    text = SYSTEM_PROMPT + json.dumps(response_schema(case)) + json.dumps(list(PHENOMENA.values()))
    for recipe in ("1102", "event_record_sequence_gap", "$MFT", "$LogFile", "threshold", "expected_count"):
        assert recipe not in text
    assert "response_schema" not in case and "record_field_defaults" not in case
    modified = deepcopy(case)
    modified["expected_count"] = 2
    with pytest.raises(ValueError):
        bundle_from_case(modified)


def test_query_keeps_reused_and_free_entries_without_marking_a_finding():
    pool = {"mft_volume_id": "volume-a", "volume_aliases": ["c"],
            "reference_complete": False, "path_complete": True,
            "entry_intervals": [{"first": 0, "last": 127}], "path_prefixes": ["\\folder\\"],
            "records": [{"entry": 45, "sequence": 9, "in_use": True, "path": r"C:\new"},
                        {"entry": 45, "sequence": 2, "in_use": False, "path": r"C:\old"},
                        {"entry": 46, "sequence": 2, "in_use": True, "path": r"C:\neighbour"},
                        {"entry": 95, "sequence": 1, "in_use": True, "path": r"C:\folder\target\child"}]}
    value = {"current_mft_pools": [pool], "candidate_roster": [
        {"identity": {"object_id": "ntfs:volume-a:45:2"},
         "evidence_records": [{"subject_ref": r"C:\folder\target"}]}]}
    from fmb.index.support.windows_identity import windows_compare_path_parts
    pool["path_prefixes"] = [windows_compare_path_parts(r"C:\folder\target")[1].rsplit("\\", 1)[0] + "\\"]
    _localize_pools(value)
    assert pool["entry_intervals"] == [{"first": 45, "last": 45}]
    assert [r["entry"] for r in pool["records"]] == [45, 45, 95]
    assert pool["reference_complete"] is False
    assert "status" not in pool


def test_one_log_finding_cannot_hide_another_missed_finding():
    case = prepare_case(log_bundle([100, 103], event_ids=[1102, 4624]))
    response = deterministic_response(case)
    expected = set(target_catalog(case))
    assert len(expected) == 2
    response['supported_findings'] = response['supported_findings'][:1]
    score = score_case(case, response, expected)
    assert (score['finding_counts']['tp'], score['finding_counts']['fn']) == (3, 3)
    assert score['exact_question_passes'] == 0
    assert score['f1'] == pytest.approx(2 / 3)


def test_reusing_a_case_cannot_hide_changed_input_or_payload_mutation():
    case = prepare_case(log_bundle([100, 103]))
    first = bundle_from_case(case)
    first.payload['candidate_roster'].clear()
    assert bundle_from_case(case).subject_ids == first.subject_ids
    case['question']['question_text'] = 'Changed task'
    with pytest.raises(ValueError, match='question/scope'):
        bundle_from_case(case)
