import hashlib
import json
from pathlib import Path

import pytest

from fmb import studies
from fmb.analysis import population_binding
from fmb.cli.app import main
from fmb.core import paper_integrity, population_contracts
from fmb.core.hashing import sha256_file
from fmb.generation import population, recipe
from fmb.generation.pipeline import GenerationPipeline
from fmb.replication import run

PAPER_I3 = Path(__file__).resolve().parents[2] / "src/fmb/generation/populations.pilot-i3-20260918.json"


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(population_contracts, "_REGISTERED", {})
    monkeypatch.setattr(paper_integrity, "_MODIFIED_PERMITTED", False)


def timestamp_heavy(contract: dict) -> dict:
    contract["scenarios"]["timestomp_01"].update(configured_count=12, manipulation_count=4, assignment_pool_count=4,
                                                 restore_stratum_end_indexes=[2, 4, 8, 10, 12])
    contract["native_pilot_parameters"]["case_classes"] = {"BQ-TIME-01": ["same_year", "forward", "access_only"]}
    return contract


def write_study(folder: Path, contract: dict, *, label="T1", seed=4242, **overrides) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "population.json").write_text(json.dumps(contract))
    study = {"schema_version": studies.SCHEMA, "name": "timestamps",
             "images": {label: {"seed": seed, "population": "population.json"}}} | overrides
    (folder / "study.json").write_text(json.dumps(study))
    return folder


def test_a_new_study_starts_as_a_copy_of_a_paper_image(tmp_path):
    studies.scaffold(tmp_path / "mine", template="I2", label="U1", seed=7)
    study = studies.load(tmp_path / "mine")
    paper = population.load_population_contract(PAPER_I3.with_name("populations.pilot-i2-20260918.json"))
    assert study.name == "mine" and list(study.images) == ["U1"] and study.images["U1"].seed == 7
    assert study.images["U1"].contract["scenarios"] == paper["scenarios"]
    [row] = studies.check(study)
    assert row["supplement"] == paper["native_pilot_parameters"]["case_classes"]


def test_check_builds_a_changed_population_offline(tmp_path):
    study = studies.load(write_study(tmp_path, timestamp_heavy(json.loads(PAPER_I3.read_text()))))
    [row] = studies.check(study)
    assert row["scenarios"]["timestomp_01"] == (12, 4)
    assert row["supplement"] == {"BQ-TIME-01": ["same_year", "forward", "access_only"]}


def remove_scenario(contract):
    contract["experiments"]["full_scale"].remove("ads_injection_01")


def more_drives(contract):
    contract["scenarios"]["usb_volume_activity_gap_01"]["configured_count"] = 5


def without_native_profile(contract):
    del contract["native_pilot_profile"], contract["native_pilot_parameters"]


def oversized_supplement(contract):
    contract["native_pilot_parameters"]["case_classes"]["BQ-EXEC-01"] = ["renamed", "renamed"]


@pytest.mark.parametrize("edit,message", [
    (remove_scenario, "keeps all 14 scenarios"),
    (more_drives, "three virtual USB drives"),
    (without_native_profile, "native profile"),
    (oversized_supplement, "exceeds the released construction"),
])
def test_a_population_the_native_profile_cannot_build_is_refused(tmp_path, edit, message):
    contract = json.loads(PAPER_I3.read_text())
    edit(contract)
    with pytest.raises(ValueError, match=message):
        studies.load(write_study(tmp_path, contract))


@pytest.mark.parametrize("label,seed,population,message", [
    ("I1", 1, "population.json", "are the paper's"),
    ("my-image", 1, "population.json", "starts with a letter"),
    ("T1", -1, "population.json", "non-negative"),
    ("T1", True, "population.json", "non-negative"),
    ("T1", 1, "../population.json", "no population file"),
    ("T1", 1, "missing.json", "no population file"),
])
def test_a_study_names_its_own_images_seeds_and_files(tmp_path, label, seed, population, message):
    folder = write_study(tmp_path / "study", json.loads(PAPER_I3.read_text()))
    (tmp_path / "population.json").write_text(PAPER_I3.read_text())
    (folder / "study.json").write_text(json.dumps({"schema_version": studies.SCHEMA, "name": "s",
                                                    "images": {label: {"seed": seed, "population": population}}}))
    with pytest.raises(ValueError, match=message):
        studies.load(folder)


def test_a_study_image_changes_only_its_seed_and_population():
    contract = timestamp_heavy(json.loads(PAPER_I3.read_text()))
    config = recipe.study_config(4242, contract)
    assert recipe.resolved_contract(config) == contract
    assert recipe.resolved_contract(recipe.study_config(4242, contract, "qemu", "fmb/windows-11-x64")) == contract
    with pytest.raises(ValueError, match="only its seed and population"):
        recipe.resolved_contract(config | {"activity_count": 36})
    assert recipe.validate_paper_config(recipe.paper_config("I2")) == "I2"
    assert "population_contract" not in recipe.paper_config("I2")


def test_a_frozen_study_image_validates_against_its_own_population():
    contract = timestamp_heavy(json.loads(PAPER_I3.read_text()))
    config = recipe.study_config(4242, contract)
    manifest = population.build_public_manifest(experiment="full_scale", seed=4242, contract=contract)
    population.register_population_contract(contract)
    assignment = population.select_private_assignment(manifest, entropy=bytes(32))
    plan = population.build_guest_plan(manifest, assignment, case="positive")
    recipe.validate_resolved_inputs(config, manifest, assignment, plan)
    with pytest.raises(ValueError, match="differs from its configuration"):
        recipe.validate_resolved_inputs(recipe.study_config(4243, contract), manifest, assignment, plan)


def test_analysis_accepts_a_study_population_once_its_contract_is_registered():
    contract = timestamp_heavy(json.loads(PAPER_I3.read_text()))
    manifest = population.build_public_manifest(experiment="full_scale", seed=4242, contract=contract)
    with pytest.raises(ValueError, match="contract hash is not supported"):
        population_binding.verify_population_manifest(manifest)
    population.register_population_contract(contract)
    assert population_binding.verify_population_manifest(manifest)["contract_sha256"] == manifest["contract_sha256"]


def test_the_generator_takes_a_study_seed_only_with_a_study_population(tmp_path):
    arguments = dict(experiment="full_scale", population_seed=4242, case="positive",
                     windows_box="fmb/windows-11-arm64", vmware_bridge=None)
    with pytest.raises(ValueError, match="fixed paper configuration"):
        GenerationPipeline("vmware_desktop", "baseline", "vmdk", False, False, output_root=tmp_path / "a",
                           **arguments)
    contract = timestamp_heavy(json.loads(PAPER_I3.read_text()))
    generator = GenerationPipeline("vmware_desktop", "baseline", "vmdk", False, False, output_root=tmp_path / "b",
                                   population_contract=contract, **arguments)
    try:
        manifest = generator.prepare_population()
    finally:
        generator.cleanup_population_inputs()
    assert manifest["population_seed"] == 4242
    assert manifest["scenarios"]["timestomp_01"]["declared_count"] == 12


def test_activating_a_study_recipe_registers_its_population_and_permits_changed_code(monkeypatch, tmp_path):
    contract = timestamp_heavy(json.loads(PAPER_I3.read_text()))
    configs = {"paper": recipe.paper_config("I1"), "study": recipe.study_config(4242, contract)}
    monkeypatch.setattr(recipe, "inspect_recipe", lambda path: {"recipe": {"config": configs[Path(path).name]}})
    assert studies.activate(tmp_path / "paper") is False
    assert paper_integrity._MODIFIED_PERMITTED is False and not population_contracts.registered_hashes()
    assert studies.activate(tmp_path / "study") is True
    assert paper_integrity._MODIFIED_PERMITTED is True and len(population_contracts.registered_hashes()) == 1


def sealed_package(root: Path) -> dict:
    root.mkdir()
    (root / "rules.py").write_text("RULE = 1\n")
    record = {"schema_version": "paper_source_manifest.v1", "implementation_version": "test",
              "files": {"package/rules.py": sha256_file(root / "rules.py")}}
    (root / "paper-source-manifest.json").write_bytes(paper_integrity.record_bytes(record))
    return {"package": root}


def test_changed_code_is_recorded_by_hash_only_where_permitted(monkeypatch, tmp_path):
    roots = sealed_package(tmp_path / "fmb")
    monkeypatch.setattr(paper_integrity, "source_roots", lambda: roots)
    (roots["package"] / "rules.py").write_text("RULE = 2\n")
    assert paper_integrity.modified_files() == ["package/rules.py"]
    with pytest.raises(ValueError, match="paper implementation changed: package/rules.py"):
        paper_integrity.source_manifest_sha256()
    paper_integrity.permit_modified_sources()
    resealed = paper_integrity.current_record()
    assert paper_integrity.source_manifest_sha256() == hashlib.sha256(paper_integrity.record_bytes(resealed)).hexdigest()
    assert resealed["files"]["package/rules.py"] == sha256_file(roots["package"] / "rules.py")


def test_replication_refuses_changed_code_and_a_study_records_it(monkeypatch, tmp_path):
    monkeypatch.setattr(paper_integrity, "modified_files", lambda roots=None: ["package/analysis/shared_rules.py"])
    with pytest.raises(SystemExit, match="fmb study run"):
        run.images(["I1"], tmp_path / "replication", 1)
    assert not (tmp_path / "replication").exists()
    study = studies.load(write_study(tmp_path / "study", json.loads(PAPER_I3.read_text())))
    assert run.implementation(study) == {"study": "timestamps", "implementation": "modified",
                                         "changed_files": ["package/analysis/shared_rules.py"]}


def test_the_study_command_starts_and_checks_a_study(tmp_path, capsys):
    assert main(["study", "new", str(tmp_path / "mine"), "--from", "I1", "--image", "A1", "--seed", "5"]) == 0
    assert main(["study", "check", str(tmp_path / "mine")]) == 0
    output = capsys.readouterr().out
    assert "A1 (seed 5)" in output and "supplement BQ-TIME-01" in output and "ready to run" in output
    assert main(["study", "new", str(tmp_path / "mine")]) != 0
