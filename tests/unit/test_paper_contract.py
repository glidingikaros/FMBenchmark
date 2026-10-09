from copy import deepcopy
import jsonschema
import pytest
from fmb.core import paper_contract as contract


CASE = {
    "candidate_roster": [{"assessment_targets": [{"finding_id": "finding:sample"}]}]
}
VALID = {
    "supported_findings": [],
    "insufficient_findings": [],
    "reasons": {
        "finding:sample": "No supporting record within the supplied complete scope."
    },
}


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "type",
        "extra",
        "missing_finding",
        "wrong_reason",
        "unknown",
        "duplicate",
        "overlap",
    ],
)
def test_invalid_original_response_is_not_made_valid_by_projection(change):
    response = deepcopy(VALID)
    if change == "missing":
        del response["reasons"]
    elif change == "type":
        response["reasons"] = 42
    elif change == "extra":
        response["unexpected"] = True
    elif change == "missing_finding":
        response["reasons"] = {}
    elif change == "wrong_reason":
        response["reasons"]["finding:sample"] = []
    elif change == "unknown":
        response["supported_findings"] = ["finding:alien"]
    elif change == "duplicate":
        response["supported_findings"] = ["finding:sample"] * 2
    else:
        response["supported_findings"] = response["insufficient_findings"] = [
            "finding:sample"
        ]
    with pytest.raises((ValueError, jsonschema.ValidationError)):
        contract.to_two_list(CASE, response, {"stated_reasons": True})


def test_valid_empty_support_remains_negative():
    assert contract.to_two_list(CASE, VALID, {"stated_reasons": True}) == {
        "supported_findings": [],
        "insufficient_findings": [],
    }


@pytest.mark.parametrize(
    "options",
    [
        {"withhold": ["stream_no_parser_fields"]},
        {"prompt_variant": "sp_v2"},
        {"views": ["cp_reasoning_hint"]},
    ],
)
def test_exploratory_options_are_not_accepted(options):
    with pytest.raises(ValueError):
        contract.validate_options(options)


def test_reused_schema_still_validates_each_response_and_schema_change():
    from fmb.core.schemas import validate_response_schema
    schema = {'type': 'integer'}
    validate_response_schema(1, schema)
    with pytest.raises(jsonschema.ValidationError):
        validate_response_schema('not an integer', schema)
    schema['type'] = 'string'
    validate_response_schema('now valid', schema)
    with pytest.raises(jsonschema.ValidationError):
        validate_response_schema(1, schema)
    schema['type'] = 'unknown-type'
    with pytest.raises(jsonschema.SchemaError):
        validate_response_schema(1, schema)
