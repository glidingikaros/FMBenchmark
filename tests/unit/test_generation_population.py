from __future__ import annotations

import importlib.util
import hashlib
import re
from copy import deepcopy
from collections.abc import Mapping
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def walk_keys(value):
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield str(key).casefold()
            yield from walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_keys(nested)


def load_population_module():
    module_path = PROJECT_ROOT / "src/fmb/generation" / "population.py"
    spec = importlib.util.spec_from_file_location("generation_population", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.POPULATION_CONTRACT_PATH = Path(__file__).resolve().parents[1] / "fixtures/generation/populations.v1.json"
    module.load_population_contract.__defaults__ = (module.POPULATION_CONTRACT_PATH,)
    return module


def test_versioned_population_contract_defines_active_experiments() -> None:
    population = load_population_module()

    contract = population.load_population_contract()

    assert contract["schema_version"] == "bounded_population.v1"
    assert tuple(contract["experiments"]) == ("timestomp", "full_scale")
    assert contract["experiments"]["timestomp"] == ["timestomp_01"]
    assert contract["experiments"]["full_scale"] == [
        "timestomp_01",
        "ads_injection_01",
        "prefetch_wipe_01",
        "security_log_clear_event_01",
        "usn_journal_01",
        "shimcache_path_residue_01",
        "typed_path_residue_01",
        "shellbag_path_residue_01",
        "ntfs_allocation_01",
        "bitmap_trailing_data_01",
        "directory_cleaning_i30_01",
        "usbstor_setupapi_discrepancy_01",
        "usb_volume_activity_gap_01",
        "event_record_sequence_gap_01",
    ]

    expected = {
        "timestomp_01": (55, 2),
        "ads_injection_01": (130, 2),
        "prefetch_wipe_01": (9, 1),
        "security_log_clear_event_01": (1, 1),
        "usn_journal_01": (17, 1),
        "shimcache_path_residue_01": (9, 1),
        "typed_path_residue_01": (16, 1),
        "shellbag_path_residue_01": (16, 1),
        "bitmap_trailing_data_01": (190, 2),
        "ntfs_allocation_01": (10, 2),
        "event_record_sequence_gap_01": (1, 1),
        "usb_volume_activity_gap_01": (1, 1),
        "directory_cleaning_i30_01": (17, 2),
        "usbstor_setupapi_discrepancy_01": (1, 1),
    }
    assert {
        scenario_id: (item["configured_count"], item["manipulation_count"])
        for scenario_id, item in contract["scenarios"].items()
    } == expected


def test_public_manifest_is_seeded_bounded_and_role_free() -> None:
    population = load_population_module()

    first = population.build_public_manifest(experiment="full_scale", seed=20260826)
    repeated = population.build_public_manifest(experiment="full_scale", seed=20260826)
    changed = population.build_public_manifest(experiment="full_scale", seed=20260827)

    assert first == repeated
    assert first != changed
    assert first["schema_version"] == "population_manifest.v1"
    assert first["declared_count"] == 473
    assert first["expected_completeness"] == "complete"
    assert population.verify_public_manifest(first) == first
    assert len(first["scenarios"]["timestomp_01"]["members"]) == 55
    assert len(first["scenarios"]["bitmap_trailing_data_01"]["members"]) == 190
    assert first["scenarios"]["ads_injection_01"]["subject_type"] == "file"
    assert {
        member["subject_type"]
        for member in first["scenarios"]["ads_injection_01"]["members"]
    } == {"file"}

    banned_keys = {
        "answer",
        "expected",
        "ground_truth",
        "is_target",
        "manipulation_count",
        "offender",
        "role",
        "selected",
        "target",
    }
    for scenario in first["scenarios"].values():
        assert banned_keys.isdisjoint(scenario)
        assert scenario["declared_count"] == len(scenario["members"])
        assert scenario["expected_completeness"] == "complete"
        for member in scenario["members"]:
            assert set(member) == {
                "candidate_id",
                "subject_type",
                "subject_ref",
                "identity_hint",
            }
            assert banned_keys.isdisjoint(member)
            assert member["candidate_id"].startswith("candidate:")
            if member["subject_type"] not in {"event_log", "device"}:
                assert re.search(
                    r"[fdx]_[0-9a-f]{12}(?:\.[a-z]+)?$",
                    member["subject_ref"].casefold(),
                )

    qmedia = first["scenarios"]["usbstor_setupapi_discrepancy_01"]
    assert (
        len(population.canonical_json_bytes(qmedia))
        <= 4096
    )


def test_shimcache_population_materializes_dynamic_executables() -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=20260827)
    assert population.verify_public_manifest(manifest) == manifest
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"shimcache-executable-contract" * 2,
    )

    members = manifest["scenarios"]["shimcache_path_residue_01"]["members"]
    assert len(members) == 9
    assert all(
        re.fullmatch(r"x_[0-9a-f]{12}\.exe", member["subject_ref"])
        for member in members
    )

    member_paths = {member["identity_hint"]["canonical_path"] for member in members}
    guest_plan = population.build_guest_plan(manifest, assignment)
    executable_paths = {
        member["path"].casefold()
        for member in guest_plan["population_members"]
        if member["object_kind"] == "executable"
    }
    assert member_paths.issubset(executable_paths)


def test_private_assignment_produces_an_identity_free_guest_plan() -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)

    assignment = population.select_private_assignment(
        manifest,
        entropy=b"a" * 32,
    )
    repeated = population.select_private_assignment(
        manifest,
        entropy=b"a" * 32,
    )
    changed = population.select_private_assignment(
        manifest,
        entropy=b"b" * 32,
    )

    assert assignment == repeated
    assert assignment != changed
    assert {
        scenario_id: len(members)
        for scenario_id, members in assignment["bindings"].items()
    } == {
        "timestomp_01": 2,
        "ads_injection_01": 2,
        "prefetch_wipe_01": 1,
        "security_log_clear_event_01": 1,
        "usn_journal_01": 1,
        "shimcache_path_residue_01": 1,
        "typed_path_residue_01": 1,
        "shellbag_path_residue_01": 1,
        "bitmap_trailing_data_01": 2,
        "ntfs_allocation_01": 2,
        "event_record_sequence_gap_01": 1,
        "usb_volume_activity_gap_01": 1,
        "directory_cleaning_i30_01": 2,
        "usbstor_setupapi_discrepancy_01": 1,
    }

    for scenario_id in ("timestomp_01", "bitmap_trailing_data_01"):
        parents = {
            member["identity_hint"]["canonical_path"].rsplit("\\", 1)[0]
            for member in assignment["bindings"][scenario_id]
        }
        assert parents == {
            r"c:\users\vagrant\desktop",
            r"c:\users\vagrant\documents",
        }

    guest_plan = population.build_guest_plan(manifest, assignment)
    assert guest_plan["schema_version"] == "generation_inputs.v1"
    assert len(guest_plan["population_members"]) == 469
    assert all(
        set(member) == {"object_kind", "path"}
        for member in guest_plan["population_members"]
    )
    assert set(guest_plan["scenario_inputs"]) == set(manifest["scenarios"])
    assert (
        len(guest_plan["scenario_inputs"]["directory_cleaning_i30_01"]["leaf_names"])
        == 80
    )
    banned_keys = {
        "answer",
        "candidate_id",
        "expected",
        "ground_truth",
        "is_target",
        "offender",
        "role",
        "selected",
        "subject_id",
        "target",
    }
    assert banned_keys.isdisjoint(set(walk_keys(guest_plan)))
    guest_bytes = population.canonical_json_bytes(guest_plan)
    assert all(
        member["candidate_id"].encode() not in guest_bytes
        for scenario in manifest["scenarios"].values()
        for member in scenario["members"]
    )


def test_benign_full_scale_keeps_the_public_population_and_projects_control_inputs() -> (
    None
):
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"benign-control-assignment" * 2,
    )

    guest_plan = population.build_guest_plan(manifest, assignment, case="benign")

    assert manifest["declared_count"] == 473
    assert len(guest_plan["population_members"]) == 469
    assert all(
        inputs["case"] == "benign" for inputs in guest_plan["scenario_inputs"].values()
    )
    assert {
        scenario_id: len(inputs["operation_refs"])
        for scenario_id, inputs in guest_plan["scenario_inputs"].items()
    } == {
        "timestomp_01": 0,
        "ads_injection_01": 0,
        "prefetch_wipe_01": 0,
        "security_log_clear_event_01": 0,
        "usn_journal_01": 0,
        "shimcache_path_residue_01": 0,
        "typed_path_residue_01": 0,
        "shellbag_path_residue_01": 0,
        "bitmap_trailing_data_01": 0,
        "ntfs_allocation_01": 0,
        "event_record_sequence_gap_01": 0,
        "usb_volume_activity_gap_01": 0,
        "directory_cleaning_i30_01": 0,
        "usbstor_setupapi_discrepancy_01": 0,
    }
    assert "candidate_id" not in population.canonical_json_bytes(guest_plan).decode()


def test_ground_truth_is_built_only_from_verified_guest_receipts(
    verified_receipts,
) -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"receipt-test-entropy" * 2,
    )
    guest_plan = population.build_guest_plan(manifest, assignment)
    receipts = verified_receipts(population, guest_plan, case="positive")

    ground_truth = population.build_ground_truth(manifest, assignment, receipts)

    assert ground_truth["schema_version"] == "generation_ground_truth.v1"
    assert ground_truth["experiment"] == "full_scale"
    assert ground_truth["population_manifest_sha256"] == manifest["manifest_sha256"]
    assert sum(len(item["candidate_ids"]) for item in ground_truth["scenarios"]) == 19
    assert all(
        item["receipt"]["postcondition_verified"] for item in ground_truth["scenarios"]
    )
    assert all(
        item["receipt"]["operation_refs"]
        == guest_plan["scenario_inputs"][item["scenario_id"]]["operation_refs"]
        for item in ground_truth["scenarios"]
    )
    assert "candidate_ids" not in population.canonical_json_bytes(manifest).decode()

    incomplete = [dict(item) for item in receipts]
    incomplete[0]["postcondition_verified"] = False
    with pytest.raises(population.PopulationError, match="postcondition"):
        population.build_ground_truth(manifest, assignment, incomplete)

    wrong_count = [dict(item) for item in receipts]
    wrong_count[0]["operation_count"] = 99
    with pytest.raises(population.PopulationError, match="operation count"):
        population.build_ground_truth(manifest, assignment, wrong_count)

    wrong_digest = [dict(item) for item in receipts]
    wrong_digest[0]["operation_refs_sha256"] = "0" * 64
    with pytest.raises(population.PopulationError, match="operation-reference digest"):
        population.build_ground_truth(manifest, assignment, wrong_digest)

    impossible_metrics = [dict(item) for item in receipts]
    prefetch_receipt = next(
        item for item in impossible_metrics if item["scenario_id"] == "prefetch_wipe_01"
    )
    prefetch_receipt.update(population_count=-1, prefetch_count=0)
    with pytest.raises(population.PopulationError, match="receipt fields"):
        population.build_ground_truth(manifest, assignment, impossible_metrics)


@pytest.mark.parametrize(
    ("scenario_id", "field", "invalid_value"),
    (
        ("timestomp_01", "assigned_timestamp", "1999-01-01T00:00:00+00:00"),
        ("bitmap_trailing_data_01", "materialized_length", 58),
    ),
)
def test_fileless_guest_instances_still_require_ordered_postconditions(
    verified_receipts,
    scenario_id: str,
    field: str,
    invalid_value: object,
) -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"fileless-receipt-postconditions" * 2,
    )
    guest_plan = population.build_guest_plan(manifest, assignment)
    receipts = verified_receipts(population, guest_plan, case="positive")
    receipt = next(item for item in receipts if item["scenario_id"] == scenario_id)
    assert all("file" not in instance for instance in receipt["instances"])
    receipt["instances"][0][field] = invalid_value

    with pytest.raises(population.PopulationError, match="invalid .*instances|bitmap content-operation postcondition is invalid"):
        population.build_ground_truth(manifest, assignment, receipts)


def test_benign_ground_truth_keeps_v1_and_contains_no_positive_candidate_ids(
    verified_receipts,
) -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"benign-receipt-assignment" * 2,
    )
    guest_plan = population.build_guest_plan(manifest, assignment, case="benign")
    receipts = verified_receipts(population, guest_plan, case="benign")

    ground_truth = population.build_ground_truth(
        manifest,
        assignment,
        receipts,
        case="benign",
    )

    assert ground_truth["schema_version"] == "generation_ground_truth.v1"
    assert ground_truth["experiment"] == "full_scale"
    assert ground_truth["case"] == "benign"
    assert all(not item["candidate_ids"] for item in ground_truth["scenarios"])

    wrong_case = [dict(item) for item in receipts]
    wrong_case[0]["case"] = "positive"
    with pytest.raises(population.PopulationError, match="generation case"):
        population.build_ground_truth(
            manifest,
            assignment,
            wrong_case,
            case="benign",
        )


def test_public_manifest_rejects_rehashed_contract_drift() -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    mutated = deepcopy(manifest)
    mutated["scenarios"]["timestomp_01"]["subject_type"] = "registry_path"
    body = dict(mutated)
    body.pop("manifest_sha256")
    mutated["manifest_sha256"] = hashlib.sha256(
        population.canonical_json_bytes(body)
    ).hexdigest()

    with pytest.raises(population.PopulationError, match="analysis contract"):
        population.verify_public_manifest(mutated)


def test_private_assignment_rejects_member_substitution() -> None:
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="timestomp", seed=84)
    assignment = population.select_private_assignment(
        manifest,
        entropy=b"assignment-integrity" * 2,
    )
    mutated = deepcopy(assignment)
    mutated["bindings"]["timestomp_01"][0]["subject_ref"] = r"C:\unrelated.txt"

    with pytest.raises(population.PopulationError, match="candidate membership"):
        population.build_guest_plan(manifest, mutated)


def test_shellbag_receipt_rejects_unverified_native_window(verified_receipts):
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(manifest, entropy=b"x" * 32)
    plan = population.build_guest_plan(manifest, assignment)
    receipts = verified_receipts(population, plan, case="positive")
    receipt = next(row for row in receipts if row["scenario_id"] == "shellbag_path_residue_01")
    receipt["native_receipts"][0]["exact_target_window_matched"] = False
    with pytest.raises(population.PopulationError, match="native Explorer"):
        population.validate_guest_receipts(plan, receipts, case="positive")


def test_ads_controls_are_identical_across_cases_and_not_content_targets():
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    assignment = population.select_private_assignment(manifest, entropy=b"x" * 32)
    plans = [population.build_guest_plan(manifest, assignment, case=case) for case in ("positive", "benign")]
    positive, benign = [plan["scenario_inputs"]["ads_injection_01"] for plan in plans]
    for key in ("benign_stream_name", "benign_stream_path", "benign_stream_content", "population_paths"):
        assert positive[key] == benign[key]
    assert positive["content_kind"] == "native_windows_pe_zip.v2"
    assert len(positive["operation_refs"]) == 2
    assert not benign["operation_refs"]
    assert positive["benign_stream_path"] not in positive["operation_refs"]


def test_ads_control_never_lands_on_a_target():
    population = load_population_module()
    for seed in (1, 84, 2026):
        manifest = population.build_public_manifest(experiment="full_scale", seed=seed)
        for entropy in (b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32):
            assignment = population.select_private_assignment(manifest, entropy=entropy)
            item = population.build_guest_plan(manifest, assignment)["scenario_inputs"]["ads_injection_01"]
            assert item["benign_stream_path"] not in item["operation_refs"]


def test_allocation_interventions_exclude_native_mode_confounders():
    population = load_population_module()
    manifest = population.build_public_manifest(experiment="full_scale", seed=84)
    for entropy in (b"a" * 32, b"b" * 32, b"c" * 32):
        assignment = population.select_private_assignment(manifest, entropy=entropy)
        plan = population.build_guest_plan(manifest, assignment)
        item = plan["scenario_inputs"]["ntfs_allocation_01"]
        modes = {row["path"]: row["storage_mode"] for row in item["storage_cases"]}
        assert set(modes.values()) == {"ordinary", "resident", "preallocation_request_then_close"}
        assert len(item["operation_refs"]) == 2
        assert all(modes[path] == "ordinary" for path in item["operation_refs"])
        i30 = plan["scenario_inputs"]["directory_cleaning_i30_01"]
        child_counts = {row["path"]: row["child_count"] for row in i30["directory_cases"]}
        assert {child_counts[path] for path in i30["operation_refs"]} == {80}
        assert i30["delete_leaf_indexes"] == [13, 14, 15, 16]
        assert i30["leaf_names"] == sorted(i30["leaf_names"], key=str.upper)
        assert all(len(name) == 54 for name in i30["leaf_names"])
        order = i30["creation_order"]
        assert order[:22] == list(range(22)) and sorted(order) == list(range(80))
        assert order[22:] != list(range(22, 80))


