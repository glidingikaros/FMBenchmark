import pytest

from fmb.pipeline.evaluation import cited_keys
from fmb.preparation.cards import REF, compact_refs, one_card_case


@pytest.mark.parametrize("key,valid", [("r00001", True), ("r99999", True), ("r100000", True), ("r1234567", True),
                                       ("r1234", False), ("r12a45", False), ("xr00001", False), ("r00001 ", False)])
def test_reference_keys_have_five_or_more_digits(key, valid):
    assert bool(REF.match(key)) is valid


def test_one_card_keeps_the_keys_beyond_r99999_that_it_cites():
    case = {"candidate_roster": [{"evidence_records": [{"source_record_ref": "r99999"},
                                                       {"source_record_ref": "r100000"}]},
                                 {"evidence_records": [{"source_record_ref": "r100001"}]}],
            "source_reference_map": {"r99999": "a.csv:row=1", "r100000": "a.csv:row=2", "r100001": "a.csv:row=3"}}
    assert one_card_case(case, 0)["source_reference_map"] == {"r99999": "a.csv:row=1", "r100000": "a.csv:row=2"}
    assert one_card_case(case, 1)["source_reference_map"] == {"r100001": "a.csv:row=3"}


def test_compacted_keys_grow_past_five_digits_and_stay_readable():
    refs = [f"a.csv:row={n}" for n in range(100001)]
    case = {"candidate_roster": [{"evidence_records": [{"record_type": "usn_record", "source_record_ref": ref,
                                                        "fields": {}} for ref in refs]}]}
    compacted = compact_refs(case)
    keys = [row["source_record_ref"] for row in compacted["candidate_roster"][0]["evidence_records"]]
    assert {len(key) for key in keys} == {6, 7} and all(REF.match(key) for key in keys)
    assert one_card_case(compacted, 0)["source_reference_map"] == compacted["source_reference_map"]


def test_cited_keys_read_keys_as_long_as_the_request_uses():
    reason = "rests on r00001, r00003 and r123456; see also xr00002"
    assert cited_keys(reason, {"r00001", "r00002"}) == ["r00001", "r00003"]
    assert cited_keys(reason, set()) == ["r00001", "r00003"]
    assert cited_keys("r100000, r99999 and r1000000", {"r99999", "r100000"}) == ["r100000", "r99999"]
