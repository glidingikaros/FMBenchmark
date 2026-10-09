from __future__ import annotations
import json


from copy import deepcopy


import pytest


from fmb.collection.factual_challenge import _populations, load_public_population


from fmb.core.hashing import sha256_file


def public_image(tmp_path, public):
    image = tmp_path / "full_scale.vmdk"
    image.write_bytes(b"test-image")
    path = tmp_path / "factual-challenge-population.json"
    path.write_text(json.dumps(public))
    (tmp_path / "manifest.json").write_text(json.dumps({"artifacts": [{
        "file": path.name, "sha256": sha256_file(path), "size_bytes": path.stat().st_size}]}))
    return image


def public_population():
    return {"schema_version": "factual_challenge_population.v1", "profile": "pilot_min.v1",
            "root": "C:\\Users\\vagrant\\Documents\\r_123", "members": [
                {"question_id": "BQ-DELETE-01", "path": "C:\\Users\\vagrant\\Documents\\r_123\\a.txt"}]}


def test_public_membership_requires_binding_and_excludes_operation_labels(tmp_path):
    public = public_population()
    image = public_image(tmp_path, public)
    assert load_public_population(image) == public
    (tmp_path / "factual-challenge-population.json").write_text('{}')
    with pytest.raises(ValueError, match="binding"):
        load_public_population(image)
    public["members"][0]["operation_class"] = "deleted"
    image = public_image(tmp_path, public)
    with pytest.raises(ValueError, match="unregistered"):
        load_public_population(image)


def test_nonpaper_public_profile_is_rejected(tmp_path):
    public = public_population()
    public["profile"] = "simple_poc.v1"
    image = public_image(tmp_path, public)
    with pytest.raises(ValueError, match="contract"):
        load_public_population(image)


def test_missing_manifest_registration_is_not_silently_ignored(tmp_path):
    image = public_image(tmp_path, public_population())
    (tmp_path / "manifest.json").write_text('{"artifacts": []}')
    with pytest.raises(ValueError, match="not bound"):
        load_public_population(image)


def test_generation_binding_accepts_only_registered_checkpoint_subpaths():
    from fmb.analysis.population_binding import _artifact_record
    image = {"file": "full_scale.vmdk", "sha256": "a" * 64, "size_bytes": 1}
    checkpoint = {"file": "factual-checkpoints/checkpoint-01.evtx", "sha256": "b" * 64, "size_bytes": 2}
    manifest = {"artifacts": [image, checkpoint]}
    assert _artifact_record(manifest, filename=image["file"]) == image
    for path in ("factual-checkpoints/../outside.evtx", "factual-checkpoints/arbitrary.evtx", r"..\outside.evtx"):
        checkpoint["file"] = path
        with pytest.raises(ValueError, match="unsafe"):
            _artifact_record(manifest, filename=image["file"])


def test_reused_path_keeps_both_native_object_generations_without_outcomes():
    public = public_population()
    path = public["members"][0]["path"]
    observations = [{"observation_id": f"obs:{sequence}", "artifact_family": "ntfs.usn",
        "observation_type": "usn_journal_record", "subject_ref": path,
        "fields": {"file_reference_entry": 100, "file_reference_sequence": sequence,
                   "mft_volume_id": "mft-source:test", "update_reasons": "FILE_CREATE"},
        "source_record_ref": f"$J:offset={sequence * 100}"} for sequence in (7, 8)]
    base = [{"population_id": "population:base", "question_id": "Q-DEL-01",
             "technique_id": "deleted_file_journal_residue", "subject_type": "file",
             "coverage_status": "complete", "subjects": []}]
    index = {"parser_runs": [{"observations": observations}]}
    populations = _populations(index, base, public)
    assert len(populations[0]["subjects"]) == 2
    assert all(s["observation_ids"] for s in populations[0]["subjects"])
    assert base[0]["subjects"] == []
    assert "outcome" not in json.dumps(populations)
    changed = deepcopy(index)
    changed["parser_runs"][0]["observations"][0]["fields"]["update_reasons"] = "FILE_DELETE"
    assert [s["identity"] for s in _populations(changed, base, public)[0]["subjects"]] == [s["identity"] for s in populations[0]["subjects"]]


def test_shellbag_ancestry_keeps_historical_path_after_move_or_record_reuse():
    from fmb.index.adapters.registry import shellbag_ancestry_paths

    rows = [
        {"ShellType": "Directory", "AbsolutePath": r"Desktop\Documents\work",
         "BagPath": r"BagMRU\2", "Slot": "0", "MFTEntry": "40", "MFTSequenceNumber": "3"},
        {"ShellType": "Directory", "AbsolutePath": r"Desktop\Documents\work\folder",
         "BagPath": r"BagMRU\2\0", "Slot": "0", "MFTEntry": "41", "MFTSequenceNumber": "2"},
    ]
    context = {"directory_paths_by_ref": {(40, 3): r"C:\Users\u\Documents\work",
                                          (41, 2): r"C:\elsewhere\folder"}}
    assert shellbag_ancestry_paths(rows, context)[2]["path"] == r"C:\Users\u\Documents\work\folder"
    del context["directory_paths_by_ref"][(41, 2)]
    assert shellbag_ancestry_paths(rows, context)[2]["path"] == r"C:\Users\u\Documents\work\folder"
    context["directory_paths_by_ref"][(40, 3)] = r"C:\Users\u\Documents\renamed"
    assert shellbag_ancestry_paths(rows, context) == {}


def test_shellbag_namespace_requires_matching_bagmru_parent_and_name():
    from fmb.index.adapters.registry import shellbag_ancestry_paths

    rows = [
        {"ShellType": "Directory", "AbsolutePath": r"Desktop\Documents\work",
         "BagPath": r"BagMRU\2", "Slot": "0", "MFTEntry": "40", "MFTSequenceNumber": "3"},
        {"ShellType": "Directory", "AbsolutePath": r"Desktop\other\child",
         "BagPath": r"BagMRU\2\0", "Slot": "0", "MFTEntry": "41", "MFTSequenceNumber": "2"},
    ]
    context = {"directory_paths_by_ref": {(40, 3): r"C:\Users\u\Documents\work"}}
    assert 2 not in shellbag_ancestry_paths(rows, context)


