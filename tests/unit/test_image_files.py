import hashlib
import json
from pathlib import Path

import pytest

from fmb.analysis import population_binding
from fmb.cli.app import main
from fmb.core import paper_integrity, population_contracts
from fmb.core.hashing import sha256_file
from fmb.generation import population, recipe
from fmb.generation.pipeline import GenerationPipeline
from fmb.replication import image_files, run

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "images/decoys.json"
PAPER_I3 = ROOT / "src/fmb/generation/populations.pilot-i3-20260918.json"


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(population_contracts, "_REGISTERED", {})
    monkeypatch.setattr(paper_integrity, "_MODIFIED_PERMITTED", False)


def example() -> dict:
    value = json.loads(EXAMPLE.read_text())
    value.pop("seed")
    return value


def write_image(path: Path, contract: dict, seed=4242) -> Path:
    path.write_text(json.dumps({"seed": seed, **contract} if seed is not None else contract))
    return path


def test_the_example_is_i3_with_more_decoys_around_the_same_manipulations():
    image = image_files.load(EXAMPLE)
    paper = population.load_population_contract(PAPER_I3)
    added = {key: item["configured_count"] - paper["scenarios"][key]["configured_count"]
             for key, item in image.contract["scenarios"].items()}
    assert (image.name, image.seed) == ("decoys", 4242)
    assert {key: count for key, count in added.items() if count} == {
        "ads_injection_01": 7, "usn_journal_01": 6, "shimcache_path_residue_01": 3, "typed_path_residue_01": 5}
    assert image_files.check(image) == "decoys: seed 4242, 77 objects, 18 manipulated, 23 supplementary cases"


def test_a_paper_population_with_a_seed_is_an_image(tmp_path):
    image = image_files.load(write_image(tmp_path / "copy.json", population.load_population_contract(PAPER_I3), 7))
    assert image_files.check(image) == "copy: seed 7, 56 objects, 18 manipulated, 23 supplementary cases"


def remove_scenario(contract):
    contract["experiments"]["full_scale"].remove("ads_injection_01")


def more_drives(contract):
    contract["scenarios"]["usb_volume_activity_gap_01"]["configured_count"] = 5


def more_timestomping(contract):
    contract["scenarios"]["timestomp_01"].update(manipulation_count=4, assignment_pool_count=4)


def fewer_streams(contract):
    contract["scenarios"]["ads_injection_01"]["manipulation_count"] = 1


def without_native_profile(contract):
    del contract["native_pilot_profile"], contract["native_pilot_parameters"]


def oversized_supplement(contract):
    contract["native_pilot_parameters"]["case_classes"]["BQ-EXEC-01"] = ["renamed", "renamed"]


def fewer_child_directories(contract):
    contract["scenarios"]["directory_cleaning_i30_01"]["directory_child_counts"] = [4, 4]


@pytest.mark.parametrize("edit,message", [
    (remove_scenario, "keeps all 14 scenarios"),
    (more_drives, "three virtual USB drives"),
    (more_timestomping, "timestomp_01 manipulates 2 object"),
    (fewer_streams, "ads_injection_01 manipulates 2 object"),
    (without_native_profile, "native profile"),
    (oversized_supplement, "exceeds the released construction"),
    (fewer_child_directories, "child-count strata"),
])
def test_a_population_the_native_profile_cannot_build_is_refused(tmp_path, edit, message):
    contract = example()
    edit(contract)
    with pytest.raises(ValueError, match=message):
        image_files.load(write_image(tmp_path / "mine.json", contract))


@pytest.mark.parametrize("name,seed,message", [
    ("I1.json", 1, "are the paper's"),
    ("my-image.json", 1, "the file name is the image's name"),
    ("mine.json", -1, "seed"),
    ("mine.json", True, "seed"),
    ("mine.json", None, "seed"),
])
def test_an_image_file_is_named_like_an_image_and_has_a_seed(tmp_path, name, seed, message):
    with pytest.raises(ValueError, match=message):
        image_files.load(write_image(tmp_path / name, example(), seed))


def test_an_image_of_your_own_changes_only_its_seed_and_population():
    contract = example()
    config = recipe.image_config(4242, contract)
    assert recipe.resolved_contract(config) == contract
    assert recipe.resolved_contract(recipe.image_config(4242, contract, "qemu", "fmb/windows-11-x64")) == contract
    with pytest.raises(ValueError, match="only its seed and population"):
        recipe.resolved_contract(config | {"activity_count": 36})
    assert recipe.validate_paper_config(recipe.paper_config("I2")) == "I2"
    assert "population_contract" not in recipe.paper_config("I2")


def test_a_frozen_image_validates_against_its_own_population():
    contract = example()
    config = recipe.image_config(4242, contract)
    manifest = population.build_public_manifest(experiment="full_scale", seed=4242, contract=contract)
    population.register_population_contract(contract)
    assignment = population.select_private_assignment(manifest, entropy=bytes(32))
    plan = population.build_guest_plan(manifest, assignment, case="positive")
    recipe.validate_resolved_inputs(config, manifest, assignment, plan)
    with pytest.raises(ValueError, match="differs from its configuration"):
        recipe.validate_resolved_inputs(recipe.image_config(4243, contract), manifest, assignment, plan)


def test_analysis_accepts_a_population_once_its_contract_is_registered():
    contract = example()
    manifest = population.build_public_manifest(experiment="full_scale", seed=4242, contract=contract)
    with pytest.raises(ValueError, match="contract hash is not supported"):
        population_binding.verify_population_manifest(manifest)
    population.register_population_contract(contract)
    assert population_binding.verify_population_manifest(manifest)["contract_sha256"] == manifest["contract_sha256"]


def test_the_generator_takes_another_seed_only_with_its_population(tmp_path):
    arguments = dict(experiment="full_scale", population_seed=4242, case="positive",
                     windows_box="fmb/windows-11-arm64", vmware_bridge=None)
    with pytest.raises(ValueError, match="fixed paper configuration"):
        GenerationPipeline("vmware_desktop", "baseline", "vmdk", False, False, output_root=tmp_path / "a",
                           **arguments)
    generator = GenerationPipeline("vmware_desktop", "baseline", "vmdk", False, False, output_root=tmp_path / "b",
                                   population_contract=example(), **arguments)
    try:
        manifest = generator.prepare_population()
    finally:
        generator.cleanup_population_inputs()
    assert manifest["population_seed"] == 4242
    assert manifest["scenarios"]["ads_injection_01"]["declared_count"] == 14


def test_activating_a_recipe_of_your_own_registers_its_population_and_permits_changed_code(monkeypatch, tmp_path):
    configs = {"paper": recipe.paper_config("I1"), "own": recipe.image_config(4242, example())}
    monkeypatch.setattr(recipe, "inspect_recipe", lambda path: {"recipe": {"config": configs[Path(path).name]}})
    assert image_files.activate(tmp_path / "paper") is False
    assert paper_integrity._MODIFIED_PERMITTED is False and not population_contracts.registered_hashes()
    assert image_files.activate(tmp_path / "own") is True
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


def test_paper_images_refuse_changed_code_and_your_own_record_it(monkeypatch, tmp_path):
    monkeypatch.setattr(paper_integrity, "modified_files", lambda roots=None: ["package/analysis/shared_rules.py"])
    with pytest.raises(SystemExit, match="released code only"):
        run.images(["I1", str(EXAMPLE)], tmp_path / "replication", 1)
    assert not (tmp_path / "replication").exists()
    assert run.implementation([]) == {"implementation": "modified",
                                      "changed_files": ["package/analysis/shared_rules.py"]}


def test_run_checks_image_files_before_anything_starts(tmp_path):
    broken = example()
    more_drives(broken)
    with pytest.raises(ValueError, match="three virtual USB drives"):
        run.images([str(write_image(tmp_path / "mine.json", broken))], tmp_path / "replication", 1)
    with pytest.raises(SystemExit, match="same name"):
        run.images([str(EXAMPLE), str(write_image(tmp_path / "decoys.json", example()))], tmp_path / "out", 1)
    with pytest.raises(SystemExit, match="name I1, I2, I3 or an image file ending in .json"):
        main(["replicate", "run", "I4"])
    assert not (tmp_path / "replication").exists() and not (tmp_path / "out").exists()


def test_new_list_and_run_name_images_and_engines(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engines").mkdir()
    (tmp_path / "engines" / "mine.py").write_text("def decide(case):\n    return None\n")
    assert main(["new", "small", "--from", "I1", "--seed", "5"]) == 0
    assert image_files.load(tmp_path / "images/small.json").seed == 5
    assert main(["new", "small"]) != 0
    assert main(["list"]) == 0
    listed = capsys.readouterr().out
    assert all(name in listed for name in ("I1", "I3", "small", "rules", "mine"))
    calls = []
    monkeypatch.setattr(run, "images", lambda names, output, attempts, engine=None: calls.append((names, engine)) or 0)
    assert main(["run", "small", "I2", "--s3", "mine"]) == 0
    assert main(["run", "I1"]) == 0
    assert calls == [(["images/small.json", "I2"], Path("engines/mine.py")), (["I1"], None)]
    assert main(["run", "missing"]) != 0 and main(["run", "small", "--s3", "other"]) != 0
    with pytest.raises(SystemExit, match="name the images"):
        main(["run"])


def test_the_chosen_engine_reaches_the_analysis_step(tmp_path, monkeypatch):
    steps = []
    monkeypatch.setattr(run, "step", lambda name, **arguments: steps.append((name, arguments)) or 0)
    monkeypatch.setattr(run.host, "toolchain_root", lambda: tmp_path / "toolchain")
    row = run.analyse("small", tmp_path / "generation", tmp_path, Path("engines/mine.py"))
    config = json.loads((tmp_path / "pipeline.json").read_text())
    assert config["stages"] == {"s3": {"engine": "mine"}} and row["admission"] == "not reached"
    assert steps[0][1]["engine_file"] == Path("engines/mine.py").resolve()
    run.analyse("small", tmp_path / "generation", tmp_path)
    assert "stages" not in json.loads((tmp_path / "pipeline.json").read_text())
