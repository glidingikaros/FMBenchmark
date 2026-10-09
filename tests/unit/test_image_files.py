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
EXAMPLE = ROOT / "tests/fixtures/images/decoys.json"
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


def half_a_question(contract):
    contract["experiments"]["full_scale"].remove("usn_journal_01")
    del contract["scenarios"]["usn_journal_01"]


def two_changed_drives(contract):
    contract["scenarios"]["usbstor_setupapi_discrepancy_01"]["manipulation_count"] = 2


def without_native_profile(contract):
    del contract["native_pilot_profile"], contract["native_pilot_parameters"]


def oversized_supplement(contract):
    contract["native_pilot_parameters"]["case_classes"]["BQ-EXEC-01"] = ["renamed", "renamed"]


def fewer_child_directories(contract):
    contract["scenarios"]["directory_cleaning_i30_01"]["directory_child_counts"] = [4, 4]


@pytest.mark.parametrize("edit,message", [
    (remove_scenario, "experiments.full_scale lists the scenarios of the image"),
    (more_drives, "2 to 4 virtual drives"),
    (half_a_question, "BQ-DELETE-01 lists all of its scenarios"),
    (two_changed_drives, "each changes one drive"),
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
    ("I1.json", 1, "differs from the paper's I1"),
    ("template.json", 1, "not template"),
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
    with pytest.raises(ValueError, match="only its seed, population"):
        recipe.resolved_contract(config | {"experiment": "timestomp"})
    with pytest.raises(ValueError, match="activity_count is an integer from 1 to 500"):
        recipe.resolved_contract(config | {"activity_count": 501})
    assert recipe.resolved_contract(config | {"activity_count": 36}) == contract
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


def test_the_paper_images_and_the_template_are_files_in_images():
    for name in ("I1", "I2", "I3"):
        image = image_files.load(ROOT / "images" / f"{name}.json")
        assert image.paper and json.loads((ROOT / "images" / f"{name}.json").read_text()) == image_files.paper_definition(name)
    template = json.loads((ROOT / "images/template.json").read_text())
    assert {key: value for key, value in template.items() if key != "seed"}["scenarios"] == \
        image_files.paper_definition("I3")["scenarios"]


def test_paper_images_refuse_changed_code_and_your_own_record_it(monkeypatch, tmp_path):
    monkeypatch.setattr(paper_integrity, "modified_files", lambda roots=None: ["package/analysis/shared_rules.py"])
    with pytest.raises(SystemExit, match="released code only"):
        run.generate_images([ROOT / "images/I1.json", EXAMPLE], 1, tmp_path / "generated")
    assert not (tmp_path / "generated").exists()
    assert run.implementation([]) == {"implementation": "modified",
                                      "changed_files": ["package/analysis/shared_rules.py"]}


def test_generate_checks_image_files_before_anything_starts(tmp_path, monkeypatch):
    broken = example()
    more_drives(broken)
    with pytest.raises(ValueError, match="2 to 4 virtual drives"):
        run.generate_images([write_image(tmp_path / "mine.json", broken)], 1, tmp_path / "generated")
    with pytest.raises(SystemExit, match="same name"):
        run.generate_images([EXAMPLE, write_image(tmp_path / "decoys.json", example())], 1, tmp_path / "generated")
    monkeypatch.chdir(tmp_path)
    assert main(["generate", "missing"]) != 0
    assert not (tmp_path / "generated").exists()


def test_generate_and_run_take_names_stages_and_llm_conditions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    (tmp_path / "images").mkdir()
    write_image(tmp_path / "images/small.json", example(), 5)
    (tmp_path / "images/I1.json").write_text((ROOT / "images/I1.json").read_text())
    generated, analysed = [], []
    monkeypatch.setattr(run, "generate_images", lambda paths, attempts: generated.append(paths) or 0)
    monkeypatch.setattr(run, "run_images", lambda names, llm: analysed.append((names, llm)) or 0)
    assert main(["generate", "small", "I1"]) == 0
    assert generated == [[Path("images/small.json"), Path("images/I1.json")]]
    assert main(["run", "small", "--compare", "S3", "--llm", "sonnet5-high", "--cap-usd", "20"]) == 0
    assert main(["run", "small"]) == 0
    assert analysed == [(["small"], {
        "conditions": ["sonnet5-high"],
        "dispatch": {"execute": True, "cap_usd": "20.0", "rates": {"sonnet5-high": {"input": "2.000", "output": "10.000"}}}}),
        (["small"], None)]
    with pytest.raises(SystemExit, match="needs --llm"):
        main(["run", "small", "--compare", "S3"])
    with pytest.raises(SystemExit):
        main(["run", "small", "--compare", "S1"])
    for command in ("generate", "run"):
        with pytest.raises(SystemExit, match=f"name the images to {command}"):
            main([command])
    assert [name for name, _ in image_files.available()] == ["I1", "small"]


@pytest.mark.parametrize("conditions,cap,prices,message", [
    (["sonnet5-high"], None, [], "needs --cap-usd"),
    ([], 5, [], "go with --llm"),
    (["luna-high"], 5, [], "no recorded price"),
    (["luna-high"], 5, ["luna-high=1.25,10"], "set OPENAI_API_KEY"),
    (["sonnet5-high"], 5, ["sonnet5-high=cheap"], "NAME=INPUT,OUTPUT"),
    (["nobody"], 5, [], "no LLM condition nobody"),
])
def test_llm_runs_need_a_cap_a_price_and_a_key(conditions, cap, prices, message):
    with pytest.raises(ValueError, match=message):
        image_files.llm_dispatch(conditions, cap, prices, {"OPENROUTER_API_KEY": "test"})


def test_llm_conditions_reach_the_analysis_and_the_summary(tmp_path, monkeypatch):
    steps = []
    monkeypatch.setattr(run, "step", lambda name, **arguments: steps.append((name, arguments)) or 0)
    monkeypatch.setattr(run.host, "toolchain_root", lambda: tmp_path / "toolchain")
    llm = {"conditions": ["sonnet5-high"], "dispatch": {"execute": True, "cap_usd": "20", "rates": {}}}
    (tmp_path / "recipe").mkdir()
    (tmp_path / "recipe/recipe.json").write_text(json.dumps({"config": recipe.paper_config("I1")}))
    assert run.analyse("small", tmp_path / "generation", tmp_path / "recipe", tmp_path, llm)["admission"] == "not reached"
    config = json.loads((tmp_path / "pipeline.json").read_text())
    assert config["conditions"] == ["sonnet5-high"] and config["dispatch"] == llm["dispatch"]
    assert steps[0][1]["recipe"] == tmp_path / "recipe"
    run.analyse("small", tmp_path / "generation", tmp_path / "recipe", tmp_path)
    config = json.loads((tmp_path / "pipeline.json").read_text())
    assert config["conditions"] == ["luna-high"] and "dispatch" not in config
    gate = tmp_path / "G5.json"
    question = {"exact": True}
    gate.write_text(json.dumps({"admission": {"status": "passed"}, "comparison": {
        "rules": {"f1": 1.0, "finding_counts": {}, "per_question": {"BQ-TIME-01": question}},
        "conditions": {"sonnet5-high": {"passes": {"1": {}, "2": {}, "3": {}},
                                        "spread": {"exact_min": 0, "exact_max": 1, "f1_min": 0.5, "f1_max": 0.8}}}}}))
    assert run.summary("small", gate)["llm"] == {"sonnet5-high": {"exact": [0, 1], "f1": [0.5, 0.8], "passes": 3}}


def test_an_image_may_set_its_clock_bias_activity_and_seeds(tmp_path):
    from datetime import datetime, timezone

    summer, winter = datetime(2026, 7, 1, tzinfo=timezone.utc), datetime(2026, 1, 15, tzinfo=timezone.utc)
    assert (recipe.auto_clock_bias(summer), recipe.auto_clock_bias(winter)) == (422, 482)
    settings = {"clock_bias_minutes": "auto", "activity_count": 40, "activity_seed": 7, "hardware_seed": 8}
    image = image_files.load(write_image(tmp_path / "busy.json", {**example(), "generation": settings}))
    assert image.settings == settings and image.contract == example()
    config = recipe.image_config(image.seed, image.contract, settings=image.settings, now=summer)
    assert (config["vmware_boot_clock_bias_minutes"], config["activity_count"]) == (422, 40)
    assert recipe.declared_seeds(config) == (7, 8) and recipe.resolved_contract(config) == image.contract
    assert recipe.declared_seeds(recipe.paper_config("I1")) == (2026091811, 2026091811)
    for bad, message in (({"clock_bias_minutes": 900}, "-840 to 840"), ({"activity_count": 0}, "1 to 500"),
                         ({"noise": 1}, "generation takes only"), ({"hardware_seed": -1}, "hardware_seed")):
        with pytest.raises(ValueError, match=message):
            image_files.load(write_image(tmp_path / "bad.json", {**example(), "generation": bad}))
