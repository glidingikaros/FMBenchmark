import json

import jsonschema
import pytest

from fmb.analysis.inputs import canonical_sha256
from fmb.analysis.population_binding import (
    BOUNDED_POPULATION_CONTRACT_SHA256,
    _verified_generation_manifest,
    verify_population_manifest,
)
from fmb.core.paths import PROJECT_ROOT

VALID = ["full_scale", "timestomp", "mine", "lab_2026_q3", "a" * 32]
INVALID = ["Full_Scale", "9lives", "_lab", "lab-2026", "a" * 33, "", None, 7]


def _population(experiment):
    body = {"schema_version": "population_manifest.v1", "experiment": experiment, "population_seed": 1,
            "contract_sha256": BOUNDED_POPULATION_CONTRACT_SHA256, "declared_count": 1,
            "expected_completeness": "complete", "scenarios": {"scenario": {"members": []}}}
    return {**body, "manifest_sha256": canonical_sha256(body)}


def _generation(experiment):
    return {"schema_version": "generation_manifest.v1", "scenario": "mine", "artifacts": [], "experiment": experiment,
            "cleanup": {"schema_version": "generation_cleanup.v1", "provider": "qemu", "status": "destroyed",
                        "provider_state_remaining": False}}


def _schemas():
    schemas = PROJECT_ROOT / "contracts" / "schemas"
    evidence = json.loads((schemas / "evidence.schema.json").read_text())
    reference = json.loads((schemas / "generation_finding_reference.schema.json").read_text())
    return [*(evidence["$defs"][name]["properties"]["experiment"]
              for name in ("generation_manifest", "generation_ground_truth", "populationManifest")),
            reference["properties"]["experiment"]]


@pytest.mark.parametrize("experiment", VALID)
def test_any_lowercase_experiment_identifier_is_accepted(experiment):
    assert verify_population_manifest(_population(experiment))["experiment"] == experiment
    assert _verified_generation_manifest(_generation(experiment))["experiment"] == experiment
    for schema in _schemas():
        jsonschema.validate(experiment, schema)


@pytest.mark.parametrize("experiment", INVALID)
def test_an_experiment_that_is_not_a_lowercase_identifier_is_refused(experiment):
    with pytest.raises(ValueError, match="experiment must be a lowercase identifier"):
        verify_population_manifest(_population(experiment))
    if experiment is not None:
        with pytest.raises(ValueError, match="generation manifest experiment is invalid"):
            _verified_generation_manifest(_generation(experiment))
    for schema in _schemas():
        assert not jsonschema.Draft202012Validator(schema).is_valid(experiment)
