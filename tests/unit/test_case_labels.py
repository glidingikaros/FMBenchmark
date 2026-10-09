import json

import jsonschema
import pytest

from fmb.core.errors import SchemaValidationError
from fmb.core.paths import PROJECT_ROOT
from fmb.paper.presentation import build
from fmb.pipeline.gates import write_gate
from fmb.pipeline.report import _image

VALID = ["I1", "I1-01", "mine-a-b", "lab_7-x1-2026-final", "a" * 32 + "-" + "b" * 12]
INVALID = ["I1-a-b-c-d", "1abc", "I1--a", "I1-", "I1-abcdefghijklm", "a" * 33, "I1-a_b", ""]


def _g5(label):
    return {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": label,
            "admission": {"status": "passed", "certificates": []}, "scores": {}}


def test_the_gate_schema_allows_up_to_three_label_suffixes():
    schema = json.loads((PROJECT_ROOT / "contracts" / "schemas" / "pipeline_gates.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema["$defs"]["case_label"])
    assert all(validator.is_valid(label) for label in VALID)
    assert not any(validator.is_valid(label) for label in INVALID)


def test_gates_carry_a_three_suffix_label_and_refuse_a_fourth(tmp_path):
    write_gate(tmp_path / "ok", "G5", _g5("mine-a-b-c"))
    with pytest.raises(SchemaValidationError):
        write_gate(tmp_path / "too-long", "G5", _g5("mine-a-b-c-d"))


@pytest.mark.parametrize("label", ["mine-a-b-c", "I1-01"])
def test_the_card_build_accepts_up_to_three_suffixes(tmp_path, label):
    with pytest.raises(ValueError, match="question_scope must be hidden or shown"):
        build(prepared=tmp_path, analysis=tmp_path, image=label, output=tmp_path / "cards", question_scope="bogus")
    with pytest.raises(ValueError, match="invalid image label"):
        build(prepared=tmp_path, analysis=tmp_path, image=label + "-d" * (4 - label.count("-")), output=tmp_path / "x")


def test_the_image_name_is_the_label_before_its_first_suffix():
    assert [_image(label) for label in ("I1", "I1-01", "mine-a-b-c")] == ["I1", "I1", "mine"]
