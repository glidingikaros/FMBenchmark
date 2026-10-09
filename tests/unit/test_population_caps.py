import json

import pytest

from fmb.analysis.catalog import technique_definition
from fmb.analysis.inputs import _build_roster, canonical_sha256
from fmb.analysis.population_binding import BOUNDED_POPULATION_CONTRACT_SHA256, verify_population_manifest
from fmb.collection import ntfs_surfaces
from fmb.core.errors import SchemaValidationError
from fmb.core.limits import MAX_POPULATION_SUBJECTS, MAX_SCENARIO_SUBJECTS
from fmb.core.paths import PROJECT_ROOT
from fmb.core.schemas import validate_payload
from fmb.index.adapters import file_content

SCHEMAS = PROJECT_ROOT / "contracts" / "schemas"


def _manifest(members: int, declared: int | None = None):
    body = {"schema_version": "population_manifest.v1", "experiment": "mine", "population_seed": 1,
            "contract_sha256": BOUNDED_POPULATION_CONTRACT_SHA256, "declared_count": declared or members,
            "expected_completeness": "complete", "scenarios": {"files": {
                "question_id": "Q-TIME-01", "technique_id": "timestamp_manipulation", "subject_type": "file",
                "declared_count": members, "expected_completeness": "complete",
                "members": [{"candidate_id": f"candidate:{n}", "subject_type": "file",
                             "subject_ref": f"C:\\Users\\me\\{n}.txt",
                             "identity_hint": {"canonical_path": f"C:\\Users\\me\\{n}.txt"}}
                            for n in range(members)]}}}
    return {**body, "manifest_sha256": canonical_sha256(body)}


def test_the_schemas_carry_the_shared_population_bounds():
    evidence = json.loads((SCHEMAS / "evidence.schema.json").read_text())["$defs"]
    scenario = evidence["populationManifestScenario"]["properties"]
    assert scenario["declared_count"]["maximum"] == scenario["members"]["maxItems"] == MAX_SCENARIO_SUBJECTS
    assert evidence["populationManifest"]["properties"]["declared_count"]["maximum"] == MAX_POPULATION_SUBJECTS
    for name in ("shared_evidence", "shared_factual_evidence", "shared_factual_presentation"):
        schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
        assert schema["properties"]["candidate_roster"]["maxItems"] == MAX_POPULATION_SUBJECTS


def test_a_scenario_may_hold_up_to_the_scenario_bound():
    validate_payload(_manifest(MAX_SCENARIO_SUBJECTS), "population_manifest.schema.json")
    with pytest.raises(SchemaValidationError):
        validate_payload(_manifest(MAX_SCENARIO_SUBJECTS + 1), "population_manifest.schema.json")


def test_a_population_may_declare_up_to_the_population_bound():
    assert verify_population_manifest(_manifest(1, MAX_POPULATION_SUBJECTS))["declared_count"] == MAX_POPULATION_SUBJECTS
    with pytest.raises(ValueError, match="declared_count is outside the supported bound"):
        verify_population_manifest(_manifest(1, MAX_POPULATION_SUBJECTS + 1))


def test_a_roster_may_hold_up_to_the_scenario_bound():
    definition = technique_definition("timestamp_manipulation")

    def roster(count):
        subjects = [{"identity": {"canonical_path": f"C:\\Users\\me\\{n}.txt"}, "subject_ref": f"{n}.txt",
                     "observation_ids": []} for n in range(count)]
        return _build_roster(definition=definition, observations=(), index_id="index", index_hash="0" * 64,
                             coverage_status="complete", population={"subjects": subjects})

    assert len(roster(6000).subjects) == 6000
    with pytest.raises(ValueError, match=f"exceeds limit of {MAX_SCENARIO_SUBJECTS} subjects"):
        roster(MAX_SCENARIO_SUBJECTS + 1)


def test_native_ntfs_surfaces_accept_more_than_two_thousand_records(tmp_path, monkeypatch):
    def reached(*args, **kwargs):
        raise LookupError("the image was opened")

    monkeypatch.setattr(ntfs_surfaces, "open_image", reached)
    record = {"mft_entry": 64, "sequence_number": 1}
    with pytest.raises(LookupError, match="the image was opened"):
        ntfs_surfaces.collect_ntfs_surfaces(evidence_image=tmp_path / "disk.raw", raw_mft_path=tmp_path / "$MFT",
                                            records=[record] * 2001, output_dir=tmp_path / "native")
    with pytest.raises(ValueError, match=f"exceeds {MAX_POPULATION_SUBJECTS}-member bound"):
        ntfs_surfaces.collect_ntfs_surfaces(evidence_image=tmp_path / "disk.raw", raw_mft_path=tmp_path / "$MFT",
                                            records=[record] * (MAX_POPULATION_SUBJECTS + 1),
                                            output_dir=tmp_path / "native")


def test_more_than_five_hundred_content_subjects_may_be_materialized(tmp_path):
    target = tmp_path / "targets" / "C" / "Users" / "alice" / "Pictures"
    target.mkdir(parents=True)
    for index in range(600):
        (target / f"picture-{index:03d}.bmp").write_bytes(b"BM" + bytes(52))
    assert len(file_content.collected_bmp_paths(tmp_path, max_subjects=600)) == 600
    with pytest.raises(ValueError, match="subject count exceeds"):
        file_content.collected_bmp_paths(tmp_path, max_subjects=599)
    with pytest.raises(ValueError, match=f"must be from 1 to {MAX_POPULATION_SUBJECTS}"):
        file_content.collected_bmp_paths(tmp_path, max_subjects=MAX_POPULATION_SUBJECTS + 1)


def test_reference_scoped_ads_keeps_more_than_five_thousand_population_streams(tmp_path):
    from fmb.index.adapters.ntfs_files import mftecmd_ads_reference_parser_run
    from fmb.index.adapters.parser_output import source_scope_id

    hosts = range(100, 5101)
    rows = ["EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,IsDirectory,HasAds,IsAds"]
    for entry in hosts:
        rows += [f"{entry},1,True,.\\Users\\alice,file{entry}.txt,10,False,True,False",
                 f"{entry},1,True,.\\Users\\alice,file{entry}.txt:payload,5,False,True,True"]
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    (tmp_path / "normalized").mkdir()
    run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path, normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}}, references={(entry, 1) for entry in hosts},
        filesystem_scope_id=f"mft-source:{source_scope_id(csv_path)}")
    assert len(run["observations"]) == len(hosts)
    assert run["selection_scope"]["status"] == "complete"
