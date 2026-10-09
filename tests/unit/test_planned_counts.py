import pytest

from fmb.core.case_contract import QIDS
from fmb.core.paper_protocol import paper_protocol
from fmb.preparation.native import _planned_counts


@pytest.mark.parametrize("image", ["I1", "I2", "I3"])
def test_the_paper_counts_bind_all_nine_questions_as_before(image):
    planned = paper_protocol()["images"][image]["planned_counts"]
    expected = {qid: tuple(value) for qid, value in planned.items()}
    assert _planned_counts(planned, list(QIDS)) == expected
    assert _planned_counts(planned, ["BQ-LOG-01", "BQ-USB-01"]) == expected


def test_a_question_subset_needs_counts_for_its_own_questions_only():
    assert _planned_counts({"BQ-LOG-01": [1, 2]}, ["BQ-LOG-01"]) == {"BQ-LOG-01": (1, 2)}
    assert _planned_counts(None, ["BQ-LOG-01"]) is None
    assert _planned_counts(None, list(QIDS)) is None


@pytest.mark.parametrize("counts,selected", [
    ({"BQ-LOG-01": [1, 2]}, ["BQ-LOG-01", "BQ-USB-01"]),
    ({"BQ-LOG-01": [1, 2], "BQ-MADE-UP-01": [1, 1]}, ["BQ-LOG-01"]),
    ({"BQ-LOG-01": [1, 2, 3]}, ["BQ-LOG-01"]),
    ({"BQ-LOG-01": [1, 2.0]}, ["BQ-LOG-01"]),
    ({"BQ-LOG-01": [True, 2]}, ["BQ-LOG-01"]),
    ({"BQ-LOG-01": [1, 2], "BQ-USB-01": [3]}, ["BQ-LOG-01"]),
    ({}, ["BQ-LOG-01"]),
])
def test_missing_unknown_or_malformed_counts_are_refused(counts, selected):
    with pytest.raises(ValueError, match="for every selected question"):
        _planned_counts(counts, selected)
