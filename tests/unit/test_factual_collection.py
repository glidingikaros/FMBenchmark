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




def test_a_membership_scan_that_finds_no_member_record_is_an_empty_run(tmp_path, monkeypatch):
    # A random image whose BQ-DELETE-01 members are only typed paths and that has no BQ-TIME-01 files: the journal
    # holds no record of a member, which once stopped the whole collection.
    import fmb.collection.analysis as analysis
    from fmb.collection.factual_challenge import _membership_usn_run

    journal = tmp_path / "$J"
    journal.write_bytes(b"\0" * 4096)
    mft = tmp_path / "MFT.csv"
    mft.write_text("header\n")
    monkeypatch.setattr(analysis, "_raw_usn_journal_path", lambda index: journal)
    run = _membership_usn_run({"collector_runs": [{"collector": "kape", "provenance": {}}]}, public_population(),
                              tmp_path, {"source_paths": [str(mft)]})
    assert run["observation_count"] == 0 and run["observation_families"] == []
    assert run["coverage_status"] == "partial" and run["coverage_families"] == ["ntfs.usn"]


def _populations_comparing_everything(index, base_populations, public):
    # _populations as it compared every member and every subject with every observation.
    from fmb.analysis.catalog import TECHNIQUES
    from fmb.analysis.inputs import canonical_sha256, candidate_identity, iter_observations, observation_matches_technique
    from fmb.collection.factual_challenge import _eligible_techniques
    from fmb.index.support.windows_identity import normalize_windows_compare_path

    observations = tuple(iter_observations(index))
    definitions = {t.technique_id: t for t in TECHNIQUES}
    seed = {p["technique_id"]: deepcopy(p) for p in base_populations}
    for member in public["members"]:
        for technique in _eligible_techniques(member):
            if technique not in seed:
                continue
            definition = definitions[technique]
            matches = [o for o in observations
                if o.artifact_family in definition.candidate_artifact_families
                and observation_matches_technique(definition, o)
                and normalize_windows_compare_path(o.subject_ref) == normalize_windows_compare_path(member["path"])
                and (technique != "timestamp_manipulation" or o.artifact_family == "ntfs.mft")
                and (technique != "deleted_file_journal_residue" or o.artifact_family == "ntfs.usn")
                and (technique != "prefetch_missing_executable" or o.artifact_family == "windows.prefetch")
                and (technique != "shellbag_missing_directory" or o.artifact_family == "windows.registry.shellbag")
                and (technique != "bitmap_trailing_data" or o.observation_type == "logical_allocated_size_record")
                and (technique != "ntfs_allocation_inconsistency" or o.observation_type == "ntfs_allocation_record")]
            identities = {}
            for observation in matches:
                display, identity = candidate_identity(definition, observation)
                identities[canonical_sha256(identity)] = {"subject_ref": display, "identity": identity, "observation_ids": []}
            if not identities:
                raise ValueError(f"native public membership is missing for {technique}: {member['path']}")
            if technique != "deleted_file_journal_residue" and len(identities) != 1:
                raise ValueError(f"public path is ambiguous for {technique}: {member['path']}")
            seed[technique]["subjects"].extend(identities.values())
    result = []
    for technique, population in seed.items():
        definition = definitions[technique]
        subjects = {}
        for subject in population["subjects"]:
            matches = [o.observation_id for o in observations
                       if o.artifact_family in definition.projected_artifact_families
                       and observation_matches_technique(definition, o)
                       and candidate_identity(definition, o)[1] == subject["identity"]]
            if not matches:
                raise ValueError(f"no retained observations for a declared {technique} subject")
            subjects[canonical_sha256(subject["identity"])] = {**subject, "observation_ids": sorted(matches)}
        population.update(population_id="population:" + canonical_sha256({
            "public": public, "base_id": population["population_id"], "technique": technique})[:24],
            subjects=[subjects[k] for k in sorted(subjects)], coverage_status="complete")
        result.append(population)
    return result


def test_members_and_subjects_take_exactly_the_observations_comparing_everything_gives():
    import random

    from fmb.analysis.catalog import TECHNIQUES
    from fmb.analysis.inputs import candidate_identity, iter_observations, observation_matches_technique

    rng = random.Random(20261012)
    spellings = ["C:\\Users\\vagrant\\Documents\\r_1\\{}", "c:/users/VAGRANT/documents/r_1/{}",
                 "\\\\?\\C:\\Users\\vagrant\\Documents\\r_1\\{}", "C:\\Users\\vagrant\\Documents\\r_2\\{}"]
    names = ["a.txt", "b.exe", "c.dll", "d.bmp", "A.TXT"]
    kinds = [("ntfs.usn", "usn_journal_record"), ("ntfs.usn", "usn_file_delete"), ("ntfs.mft", "mft_file_record"),
             ("ntfs.mft", "si_fn_timestamp_difference"), ("windows.prefetch", "prefetch_execution"),
             ("ntfs.logfile", "logfile_si_update"), ("ntfs.ads", "named_data_stream"),
             ("windows.registry.typed_paths", "typed_path_seen"), ("windows.registry.typed_paths", "key_seen")]
    observations = []
    for number in range(600):
        family, observation_type = rng.choice(kinds)
        name = rng.choice(names)
        path = rng.choice(spellings).format(name)
        fields = {"file_name": name, "update_reasons": rng.choice(["FILE_DELETE|CLOSE", "FILE_CREATE", "CLOSE"]),
                  "executable_name": name.upper(), "source_key": rng.choice([
                      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
                      "HKCU\\Software\\Other"])}
        if rng.random() < 0.6:
            fields.update(mft_volume_id="mft-source:test", mft_entry=rng.randrange(40, 46),
                          sequence_number=rng.randrange(1, 3))
        if family == "ntfs.ads":
            fields.update(base_path=path, stream_name="Zone.Identifier")
            path += ":Zone.Identifier"
        observations.append({"observation_id": f"obs:{number:04d}", "artifact_family": family,
                             "observation_type": observation_type, "subject_ref": path, "fields": fields,
                             "source_record_ref": f"record:{number}"})
    index = {"parser_runs": [{"observations": observations}]}
    definitions = {t.technique_id: t for t in TECHNIQUES}
    base = []
    for technique in ("deleted_file_journal_residue", "timestamp_manipulation", "prefetch_missing_executable",
                      "alternate_data_stream", "typed_path_residue"):
        definition = definitions[technique]
        identities = [candidate_identity(definition, o)[1] for o in iter_observations(index)
                      if o.artifact_family in definition.projected_artifact_families
                      and observation_matches_technique(definition, o)]
        subjects = [{"subject_ref": "subject", "identity": identity, "observation_ids": []}
                    for identity in rng.sample(identities, min(len(identities), 6))]
        base.append({"population_id": f"population:{technique}", "question_id": "Q", "technique_id": technique,
                     "subject_type": "file", "coverage_status": "complete", "subjects": subjects})

    def outcome(populations, public):
        try:
            return json.dumps(populations(index, base, public))
        except ValueError as error:
            return str(error)

    found = []
    for question in ("BQ-DELETE-01", "BQ-TIME-01", "BQ-EXEC-01", "BQ-STREAM-01"):
        for spelling in spellings:
            for name in names:
                public = {"members": [{"question_id": question, "path": spelling.format(name)}]}
                expected = outcome(_populations_comparing_everything, public)
                assert outcome(_populations, public) == expected
                found += public["members"] if expected.startswith("[") else []
    public = {"members": found}
    expected = outcome(_populations_comparing_everything, public)
    assert len(found) >= 10 and expected.startswith("[") and outcome(_populations, public) == expected
