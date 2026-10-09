from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from fmb.generation import pilot_profile, population, recipe
from fmb.replication import image_files
from test_file_content_adapter import bmp_bytes
from test_generation_scenario_truth_blindness import render_public_helper_lookups

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks"
STRESS = ROOT / "tests/fixtures/images/stress.json"


def _plan(path=STRESS):
    image = image_files.load(path)
    contract = recipe.resolved_contract(recipe.image_config(image.seed, image.contract))
    manifest = population.build_public_manifest(experiment="full_scale", seed=image.seed, contract=contract)
    assignment = population.select_private_assignment(manifest, entropy=bytes(range(32)))
    return image, manifest, assignment, population.build_guest_plan(manifest, assignment, case="positive")


def _guest(name: str) -> str:
    return render_public_helper_lookups(yaml.safe_load((TASKS / name).read_text())[0]["ansible.windows.win_shell"])


def _run(tmp_path, name: str, inputs: dict) -> subprocess.CompletedProcess:
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell not installed")
    script = tmp_path / "guest.ps1"
    script.write_text(_guest(name))
    return subprocess.run([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                          input=json.dumps(inputs), capture_output=True, text=True, timeout=60)


def test_each_scenario_manipulates_the_count_the_image_declares():
    image, manifest, assignment, plan = _plan()
    for scenario_id, item in image.contract["scenarios"].items():
        assert len(assignment["bindings"][scenario_id]) == item["manipulation_count"], scenario_id
        assert len(manifest["scenarios"][scenario_id]["members"]) == item["configured_count"], scenario_id
        if scenario_id != "security_log_clear_event_01":
            assert plan["scenario_inputs"][scenario_id]["expected_operation_count"] == item["manipulation_count"]
    inputs = plan["scenario_inputs"]
    assert [op["mode"] for op in inputs["bitmap_trailing_data_01"]["bitmap_operations"]] == [
        "append", "truncate", "append"]
    assert [kind for kind, _ in population.ads_streams(inputs["ads_injection_01"], 3)] == ["pe", "zip", "pe"]
    assert len(inputs["timestomp_01"]["timestamps"]) == 3
    assert inputs["timestomp_01"]["timestamps"][:2] == pilot_profile.PILOT_TIMESTAMPS
    directory = inputs["directory_cleaning_i30_01"]
    assert [case["child_count"] for case in directory["directory_cases"]] == [100, 40, 4]
    assert len(directory["leaf_names"]) == len(directory["creation_order"]) == 100
    assert sorted(directory["creation_order"]) == list(range(100))
    media = inputs["usbstor_setupapi_discrepancy_01"]["media"]
    assert [(row["unit"], row["port"]) for row in media] == [(8, 5), (9, 3), (10, 2), (11, 1)]
    assert sum(row["installation_discrepancy"] for row in media) == 1
    assert sum(row["history_discrepancy"] for row in media) == 1
    assert not any(row["installation_discrepancy"] and row["history_discrepancy"] for row in media)
    typed = inputs["typed_path_residue_01"]
    assert typed["recreated_path"] not in typed["operation_refs"]
    schema = json.loads((ROOT / "src/fmb/contracts/schemas/generation_recipe.schema.json").read_text())
    validator = Draft202012Validator(
        schema["$defs"]["generation_inputs"]["properties"]["scenario_inputs"]["additionalProperties"])
    for scenario_id, item in inputs.items():
        validator.validate(item)


def test_the_paper_counts_keep_the_paper_layout():
    _, _, _, plan = _plan(ROOT / "images/I3.json")
    inputs = plan["scenario_inputs"]
    assert [op["mode"] for op in inputs["bitmap_trailing_data_01"]["bitmap_operations"]] == ["append", "truncate"]
    assert "extra_stream_names" not in inputs["ads_injection_01"]
    assert len(inputs["directory_cleaning_i30_01"]["leaf_names"]) == 80
    assert pilot_profile.media_layout(7) == pilot_profile.media_layout(7, 3)
    assert [row["port"] for row in inputs["usbstor_setupapi_discrepancy_01"]["media"]] == [5, 3, 2]


@pytest.mark.parametrize(("scenario_id", "change", "message"), [
    ("typed_path_residue_01", {"configured_count": 26}, "at most 25"),
    ("typed_path_residue_01", {"configured_count": 3, "manipulation_count": 3}, "one folder that is not deleted"),
    ("ntfs_allocation_01", {"configured_count": 101, "storage_modes": ["ordinary"] * 101}, "at most 100"),
    ("directory_cleaning_i30_01", {"directory_child_counts": [201, 40, 4]}, "child-count"),
    ("directory_cleaning_i30_01", {"directory_child_counts": [21, 40, 4]}, "child-count"),
    ("usbstor_setupapi_discrepancy_01", {"configured_count": 5}, "2 to 4 virtual drives"),
    ("usb_volume_activity_gap_01", {"manipulation_count": 2}, "each changes one drive"),
])
def test_the_generator_refuses_counts_it_cannot_build(tmp_path, scenario_id, change, message):
    value = json.loads(STRESS.read_text())
    value["scenarios"][scenario_id].update(change)
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match=message):
        image_files.load(path)


def test_a_security_log_image_keeps_one_log(tmp_path):
    value = json.loads(STRESS.read_text())
    value["scenarios"]["event_record_sequence_gap_01"]["configured_count"] = 2
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="one Security log"):
        image_files.load(path)


@pytest.mark.pwsh
def test_the_bitmap_guest_applies_one_operation_to_each_target(tmp_path):
    paths = [str(tmp_path / f"Public{index}.bmp") for index in range(5)]
    for path in paths:
        Path(path).write_bytes(bmp_bytes())
    operations = [{"mode": "append", "byte_count": 1024}, {"mode": "truncate", "length": 54},
                  {"mode": "append", "byte_count": 1024}]
    inputs = {"case": "positive", "population_paths": paths, "expected_population_count": 5,
              "native_pilot_profile": pilot_profile.PROFILE, "expected_operation_count": 3,
              "operation_refs": paths[:3], "bitmap_operations": operations}
    completed = _run(tmp_path, "pilot_bitmap_trailing_data_01.yml", inputs)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    plan = {"schema_version": "generation_inputs.v1", "scenario_inputs": {"bitmap_trailing_data_01": inputs}}
    assert population.validate_guest_receipts(plan, [receipt], case="positive") == [receipt]
    assert [Path(path).stat().st_size for path in paths] == [1082, 54, 1082, 58, 58]
    wrong = deepcopy(inputs) | {"bitmap_operations": operations[:2]}
    assert _run(tmp_path, "pilot_bitmap_trailing_data_01.yml", wrong).returncode != 0


@pytest.mark.pwsh
def test_the_directory_guest_builds_folders_of_any_size(tmp_path):
    _, _, _, plan = _plan()
    inputs = deepcopy(plan["scenario_inputs"]["directory_cleaning_i30_01"])
    local = {}
    for case in inputs["directory_cases"]:
        local[case["path"]] = tmp_path / Path(case["path"].replace("\\", "/")).name
        local[case["path"]].mkdir()
        case["path"] = str(local[case["path"]])
    inputs["population_paths"] = [str(local[path]) for path in inputs["population_paths"]]
    inputs["operation_refs"] = [str(local[path]) for path in inputs["operation_refs"]]
    completed = _run(tmp_path, "directory_cleaning_i30_01.yml", inputs)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    plan = {"schema_version": "generation_inputs.v1", "scenario_inputs": {"directory_cleaning_i30_01": inputs}}
    assert population.validate_guest_receipts(plan, [receipt], case="positive") == [receipt]
    counts = {Path(case["path"]).name: len(list(Path(case["path"]).iterdir())) for case in inputs["directory_cases"]}
    targets = {Path(path).name for path in inputs["operation_refs"]}
    assert sorted(counts.values()) == sorted(case["child_count"] - 4 * (Path(case["path"]).name in targets)
                                             for case in inputs["directory_cases"])


@pytest.mark.pwsh
@pytest.mark.parametrize(("extra", "stage"), [(1, "zone_stream_write"), (0, "validate_input")])
def test_the_stream_guest_accepts_one_name_for_each_target(tmp_path, extra, stage):
    _, _, _, plan = _plan()
    inputs = deepcopy(plan["scenario_inputs"]["ads_injection_01"])
    inputs["extra_stream_names"] = inputs["extra_stream_names"][:extra]
    if not extra:
        del inputs["extra_stream_names"]
    completed = _run(tmp_path, "ads_injection_01.yml", inputs)
    assert json.loads(completed.stdout)["failure_stage"] == stage


@pytest.mark.pwsh
@pytest.mark.parametrize(("operations", "stage"), [(2, "preallocation_set_api"), (0, "validate_input")])
def test_the_allocation_guest_accepts_any_number_of_files(tmp_path, operations, stage):
    _, _, _, plan = _plan()
    inputs = deepcopy(plan["scenario_inputs"]["ntfs_allocation_01"])
    local = {path: str(tmp_path / f"control{index}.bin") for index, path in enumerate(inputs["population_paths"])}
    inputs["population_paths"] = [local[path] for path in inputs["population_paths"]]
    inputs["operation_refs"] = list(inputs["population_paths"][:operations])
    inputs["expected_operation_count"] = operations
    for case in inputs["storage_cases"]:
        case["path"] = local[case["path"]]
    completed = _run(tmp_path, "pilot_ntfs_allocation_01.yml", inputs)
    assert json.loads(completed.stdout)["failure_stage"] == stage


SUBSET = ROOT / "tests/fixtures/images/subset.json"


def test_an_image_asks_the_questions_whose_scenarios_it_has(tmp_path):
    image, manifest, assignment, plan = _plan(SUBSET)
    assert set(image_files.questions(image.contract)) == {
        "BQ-DELETE-01", "BQ-EXEC-01", "BQ-DIRECTORY-01", "BQ-STREAM-01", "BQ-FILE-01", "BQ-LOG-01"}
    assert set(plan["scenario_inputs"]) == set(image.contract["experiments"]["full_scale"])
    challenge = recipe._factual_challenge_plan(recipe.image_config(image.seed, image.contract), plan, manifest)
    assert {member["question_id"] for member in challenge["members"]} == {
        "BQ-DELETE-01", "BQ-EXEC-01", "BQ-DIRECTORY-01", "BQ-STREAM-01", "BQ-FILE-01"}
    assert challenge["shellbag_helper"]["visit_budgets"] == population.validate_visit_budgets(
        population.SHELLBAG_VISIT_BUDGETS)
    receipts = [{"scenario_id": sid, "receipt": {"postcondition_verified": True}} for sid in plan["scenario_inputs"]]
    truth = {"schema_version": "generation_ground_truth.v1", "population_manifest_sha256": manifest["manifest_sha256"],
             "experiment": "full_scale", "case": "positive",
             "scenarios": [{"scenario_id": sid, "candidate_ids": [m["candidate_id"] for m in assignment["bindings"][sid]],
                            "receipt": row["receipt"]} for sid, row in zip(plan["scenario_inputs"], receipts)]}
    reference = population.build_finding_reference(manifest, truth)
    assert "archive_receipt_payload_sha256" not in reference
    with pytest.raises(population.PopulationError, match="exactly when the image has timestomp_01"):
        population.build_finding_reference(manifest, truth, {"records": []})
    recipe_dir = tmp_path / "recipe"
    recipe_dir.mkdir()
    (recipe_dir / "recipe.json").write_text(json.dumps({"config": recipe.image_config(image.seed, image.contract)}))
    from fmb.replication import run
    assert run.asked(recipe_dir) == image_files.questions(image.contract)
    (recipe_dir / "recipe.json").write_text(json.dumps({"config": recipe.paper_config("I3")}))
    assert run.asked(recipe_dir) is None


@pytest.mark.parametrize(("edit", "message"), [
    (lambda value: value["native_pilot_parameters"]["case_classes"].update({"BQ-TIME-01": ["forward"]}),
     "BQ-TIME-01, which the image does not ask"),
    (lambda value: (value["experiments"]["full_scale"].append("usb_volume_activity_gap_01"),
                    value["scenarios"].update(usb_volume_activity_gap_01={
                        "configured_count": 3, "manipulation_count": 1, "object_kind": "native_usb_device",
                        "media_layout": pilot_profile.PROFILE})),
     "usb_volume_activity_gap_01 needs usbstor_setupapi_discrepancy_01"),
])
def test_a_subset_keeps_whole_questions(tmp_path, edit, message):
    value = json.loads(SUBSET.read_text())
    edit(value)
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match=message):
        image_files.load(path)
