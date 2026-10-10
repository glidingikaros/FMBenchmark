from copy import deepcopy
import json
from pathlib import Path

import pytest

from fmb.generation import pilot_profile
from fmb.generation.factual_challenge import build_plan, validate_receipt
from fmb.generation.population import (
    PopulationError,
    SHELLBAG_VISIT_BUDGETS,
    build_guest_plan,
    build_public_manifest,
    load_population_contract,
    select_private_assignment,
)
from fmb.generation.recipe import validate_resolved_inputs

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {"i1": 1, "i2": 12, "i3": 23}
SHELLBAG = {"visit_budgets": SHELLBAG_VISIT_BUDGETS}
EPOCH_2026_09_16 = 134_340_692_126_102_719


def contract_for(image):
    return load_population_contract(
        ROOT / f"src/fmb/generation/populations.pilot-{image}-20260918.json"
    )


def plan_for(image, seed=2026091801):
    return build_plan(
        seed,
        shellbag_input=SHELLBAG,
        profile="pilot_min.v1",
        pilot_parameters=contract_for(image)["native_pilot_parameters"],
    )


def test_absent_or_empty_parameters_keep_the_released_construction():
    released = build_plan(2026091707, shellbag_input=SHELLBAG, profile="pilot_min.v1")
    empty = build_plan(
        2026091707,
        shellbag_input=SHELLBAG,
        profile="pilot_min.v1",
        pilot_parameters={"schema_version": pilot_profile.PARAMETERS_SCHEMA},
    )
    assert released == empty
    directory = next(
        m for m in released["members"] if m["question_id"] == "BQ-DIRECTORY-01"
    )
    assert (
        len(directory["child_names"]) == 80 and directory["child_operation_index"] == 13
    )
    forward = next(m for m in released["members"] if m["operation_class"] == "forward")
    assert forward["timestamp_deltas"] == {
        "modified_filetime": pilot_profile.DAY_FILETIME
    }


@pytest.mark.parametrize("image,count", sorted(IMAGES.items()))
def test_image_contracts_resolve_to_bounded_selections(image, count):
    contract = contract_for(image)
    plan = plan_for(image)
    assert plan["profile"] == "pilot_min.v1" and len(plan["members"]) == count
    classes = contract["native_pilot_parameters"]["case_classes"]
    assert [(m["question_id"], m["operation_class"]) for m in plan["members"]] == [
        (qid, kind) for qid, kinds in classes.items() for kind in kinds
    ]
    for member in plan["members"]:
        released = pilot_profile.CASE_CLASSES[member["question_id"]]
        assert member["operation_class"] in released
        if member["question_id"] == "BQ-DIRECTORY-01":
            expected_children = (
                80 if image == "i3" else 24
            )
            assert (
                len(member["child_names"])
                == expected_children
                == len(set(member["child_names"]))
            )
            assert (
                member["child_names"] == sorted(member["child_names"])
                and member["child_operation_index"] == 13
            )
        if member["operation_class"] == "forward":
            assert member["timestamp_deltas"] == {"modified_filetime": 1_200_000_100}
        if member["operation_class"] == "access_only":
            assert member["timestamp_deltas"] == {"access_filetime": -864_000_000_001}
        if member["operation_class"] == "same_year":
            assert (
                member["timestamp_deltas"]["creation_filetime"]
                == -14 * pilot_profile.DAY_FILETIME - 1
            )
    assert all(
        set(row) == {"question_id", "path"}
        for row in plan["public_manifest"]["members"]
    )


@pytest.mark.parametrize("image", sorted(IMAGES))
def test_image_contracts_freeze_like_the_released_pilot(image):
    from fmb.generation.recipe import paper_config
    config = paper_config(image.upper())
    seed = config["population_seed"]
    contract = contract_for(image)
    public = build_public_manifest(
        experiment="full_scale", seed=seed, contract=contract
    )
    assignment = select_private_assignment(
        public, entropy=b"i-series-offline-check-20260918"
    )
    guest_plan = build_guest_plan(public, assignment)
    validate_resolved_inputs(config, public, assignment, guest_plan)
    assert (
        pilot_profile.parameters_for_manifest(public)
        == contract["native_pilot_parameters"]
    )


@pytest.mark.parametrize(
    "change",
    [
        {"case_classes": {"BQ-TIME-01": ["coordinated"]}},
        {"case_classes": {"BQ-TIME-01": ["same_year", "same_year"]}},
        {"case_classes": {"BQ-USB-01": ["renamed"]}},
        {"case_classes": {"BQ-TIME-01": []}},
        {"directory_child_count": 21},
        {"directory_child_count": 81},
        {"directory_child_count": True},
        {"timestamp_deltas": {"forward": {"modified_filetime": 864_000_000_000}}},
        {"timestamp_deltas": {"forward": {"modified_filetime": -1_200_000_100}}},
        {"timestamp_deltas": {"access_only": {"access_filetime": 864_000_000_001}}},
        {"timestamp_deltas": {"same_year": {"creation_filetime": -1}}},
        {"timestamp_deltas": {"forward": {"creation_filetime": 1_200_000_100}}},
        {"unregistered": 1},
    ],
)
def test_parameters_outside_the_released_construction_are_refused(tmp_path, change):
    value = {"schema_version": pilot_profile.PARAMETERS_SCHEMA, **change}
    with pytest.raises(ValueError):
        pilot_profile.validate_parameters(value)
    contract = json.loads(
        (ROOT / "src/fmb/generation/populations.pilot-i3-20260918.json").read_text()
    )
    contract["native_pilot_parameters"] = value
    path = tmp_path / "populations.refused.json"
    path.write_text(json.dumps(contract))
    with pytest.raises(PopulationError):
        load_population_contract(path)


def test_parameters_require_the_pilot_profile(tmp_path):
    contract = json.loads(
        (ROOT / "src/fmb/generation/populations.pilot-i1-20260918.json").read_text()
    )
    del contract["native_pilot_profile"]
    path = tmp_path / "populations.refused.json"
    path.write_text(json.dumps(contract))
    with pytest.raises(PopulationError):
        load_population_contract(path)
    with pytest.raises(ValueError):
        build_plan(
            1,
            shellbag_input=SHELLBAG,
            profile="simple_poc.v1",
            pilot_parameters={"schema_version": pilot_profile.PARAMETERS_SCHEMA},
        )


def _state(
    path,
    reference,
    *,
    exists=True,
    created=EPOCH_2026_09_16,
    modified=EPOCH_2026_09_16,
    access=EPOCH_2026_09_16 + 5,
    length=17,
    sha="ab" * 32,
):
    if not exists:
        return {"exists": False, "path": path}
    return {
        "exists": True,
        "path": path,
        "file_reference": f"9a2b3c4d:{reference:016x}",
        "creation_filetime": created,
        "modified_filetime": modified,
        "change_filetime": created,
        "access_filetime": access,
        "sha256": sha,
        "length": length,
    }


def synthetic_receipt(plan):
    rows = []
    for number, member in enumerate(plan["members"], 1):
        kind, qid, path, alt = (
            member["operation_class"],
            member["question_id"],
            member["path"],
            member["alternative_path"],
        )
        reference = (3 << 48) | (1000 + number)
        before = _state(path, reference)
        after, alternative = deepcopy(before), _state(alt, 0, exists=False)
        witnesses, reuse, transition, source = [], None, None, None
        if kind in {"deleted", "entry_reused"}:
            after = _state(path, 0, exists=False)
        if kind == "renamed":
            after, alternative = _state(path, 0, exists=False), _state(alt, reference)
        if kind == "recreated":
            after = _state(path, (3 << 48) | (5000 + number))
        if kind == "entry_reused":
            reuse = {
                **_state(alt + "_r_004", (4 << 48) | (1000 + number)),
                "attempt": 4,
            }
        if qid == "BQ-TIME-01":
            if kind == "old_copy":
                old = 133_000_000_000_000_000
                before = _state(path, reference, modified=old)
                after = deepcopy(before)
                source = {
                    **_state(member["copy_source"], 77, modified=old),
                    "path": member["copy_source"],
                }
            for field, delta in member["timestamp_deltas"].items():
                after[field] = before[field] + delta
        if qid == "BQ-FILE-01" and kind == "append_four":
            after["length"] = before["length"] + 4
        if qid == "BQ-DIRECTORY-01":
            witnesses = [
                _state(path + "\\" + name, (3 << 48) | (20000 + 100 * number + n))
                for n, name in enumerate(member["child_names"])
            ]
            old = witnesses[member["child_operation_index"]]
            if kind == "recreated_children":
                transition = {
                    "before": old,
                    "after": _state(old["path"], (3 << 48) | 90000 + number),
                    "alternative": _state(alt + ".txt", 0, exists=False),
                }
            else:
                moved = {**old, "path": alt + ".txt"}
                transition = {
                    "before": old,
                    "after": _state(old["path"], 0, exists=False),
                    "alternative": moved,
                }
        if qid == "BQ-STREAM-01":
            lengths = {
                "second_pe": [14, 40960],
                "signature_decoy": [8],
                "empty_zip": [22],
            }[kind]
            witnesses = [
                {"stream_name": name, "length": length, "sha256": "cd" * 32}
                for name, length in zip(member["stream_names"], lengths)
            ]
        rows.append(
            {
                "question_id": qid,
                "path": path,
                "operation_class": kind,
                "before": before,
                "after": after,
                "alternative": alternative,
                "witnesses": witnesses,
                "copy_source": source,
                "reuse": reuse,
                "child_transition": transition,
                "completed": True,
            }
        )
    return {
        "schema_version": "factual_challenge_receipt.v1",
        "public_manifest_sha256": plan["public_manifest_sha256"],
        "members": rows,
    }


@pytest.mark.parametrize("image", [None, *sorted(IMAGES)])
def test_receipts_are_validated_from_the_frozen_plan(image):
    plan = (
        build_plan(2026091707, shellbag_input=SHELLBAG, profile="pilot_min.v1")
        if image is None
        else plan_for(image)
    )
    receipt = synthetic_receipt(plan)
    validate_receipt(plan, receipt)
    directories = [
        row for row in receipt["members"] if row["question_id"] == "BQ-DIRECTORY-01"
    ]
    if directories:
        broken = deepcopy(receipt)
        next(
            row for row in broken["members"] if row["question_id"] == "BQ-DIRECTORY-01"
        )["witnesses"].pop()
        with pytest.raises(ValueError, match="child identities"):
            validate_receipt(plan, broken)
    forward = [row for row in receipt["members"] if row["operation_class"] == "forward"]
    if forward:
        broken = deepcopy(receipt)
        row = next(
            row for row in broken["members"] if row["operation_class"] == "forward"
        )
        row["after"]["modified_filetime"] += 1
        with pytest.raises(ValueError, match="frozen delta"):
            validate_receipt(plan, broken)


def materialization_for(plan, receipt):
    return {
        "schema_version": "native_pilot_materialization.v1",
        "public_manifest_sha256": plan["public_manifest_sha256"],
        "members": [
            {"path": row["path"], "state": deepcopy(row["before"]),
             "copy_source": deepcopy(row["copy_source"])}
            for row in receipt["members"]
        ],
    }


@pytest.mark.parametrize("kind", ["access_only", "old_copy"])
@pytest.mark.parametrize("field,delta", [
    ("creation_filetime", -1), ("creation_filetime", 1),
    ("modified_filetime", -1), ("modified_filetime", 1),
    ("change_filetime", -1),
])
def test_negative_timestamp_control_rejects_unplanned_changes(kind, field, delta):
    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    row = next(row for row in receipt["members"] if row["operation_class"] == kind)
    row["after"][field] += delta
    with pytest.raises(ValueError, match="negative timestamp control"):
        validate_receipt(plan, receipt)


@pytest.mark.parametrize("kind", ["access_only", "old_copy"])
@pytest.mark.parametrize("field", ["creation_filetime", "modified_filetime", "change_filetime"])
@pytest.mark.parametrize("value", [None, True])
def test_negative_timestamp_control_requires_native_integer_times(kind, field, value):
    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    row = next(row for row in receipt["members"] if row["operation_class"] == kind)
    row["before"][field] = row["after"][field] = value
    with pytest.raises(ValueError, match="complete native times"):
        validate_receipt(plan, receipt)


@pytest.mark.parametrize("kind,field", [
    ("access_only", "creation_filetime"), ("access_only", "modified_filetime"),
    ("old_copy", "creation_filetime"), ("access_only", "change_filetime"),
    ("old_copy", "change_filetime"),
])
def test_negative_timestamp_control_binds_to_initial_materialization(kind, field):
    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    initial = materialization_for(plan, receipt)
    row = next(row for row in receipt["members"] if row["operation_class"] == kind)
    row["before"][field] -= pilot_profile.DAY_FILETIME
    row["after"][field] -= pilot_profile.DAY_FILETIME
    validate_receipt(plan, receipt)
    with pytest.raises(ValueError, match="negative timestamp control"):
        pilot_profile.validate_materialization(plan, initial, receipt)


@pytest.mark.parametrize("kind", ["access_only", "old_copy"])
def test_negative_timestamp_control_requires_initial_metadata_time(kind):
    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    initial = materialization_for(plan, receipt)
    row = next(row for row in receipt["members"] if row["operation_class"] == kind)
    state = next(item["state"] for item in initial["members"] if item["path"] == row["path"])
    del state["change_filetime"]
    with pytest.raises(ValueError, match="complete native times"):
        pilot_profile.validate_materialization(plan, initial, receipt)


@pytest.mark.parametrize("kind", ["access_only", "old_copy"])
def test_negative_timestamp_control_allows_inherited_times_and_native_advances(kind):
    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    row = next(row for row in receipt["members"] if row["operation_class"] == kind)
    for snapshot in (row["before"], row["after"]):
        snapshot["modified_filetime"] = 133_000_000_000_000_000
        snapshot["change_filetime"] = 133_000_000_000_000_001
    initial = materialization_for(plan, receipt)
    row["before"]["change_filetime"] += 1
    row["after"]["change_filetime"] += 2
    row["before"]["access_filetime"] += 17
    row["after"]["access_filetime"] += 17 if kind == "access_only" else 19
    validate_receipt(plan, receipt)
    pilot_profile.validate_materialization(plan, initial, receipt)


@pytest.mark.parametrize(
    "delta", [1_200_000_100, -864_000_000_001, -14 * 864_000_000_000 - 1]
)
def test_control_deltas_change_the_lowest_stored_byte_for_every_start(delta):
    for start in range(EPOCH_2026_09_16, EPOCH_2026_09_16 + 256):
        assert (start + delta) & 0xFF != start & 0xFF


@pytest.mark.parametrize("image", ["i1", "i2"])
def test_directory_residue_gate_has_no_subject_without_a_recreated_child_folder(
    tmp_path, image
):
    from fmb.generation.pipeline import GenerationPipeline

    plan = plan_for(image)
    (tmp_path / "factual-challenge-plan.json").write_text(json.dumps(plan))
    (tmp_path / "factual-challenge-receipt.json").write_text(
        json.dumps(synthetic_receipt(plan))
    )
    pipeline = GenerationPipeline.__new__(GenerationPipeline)
    pipeline.output_dir, pipeline.work_dir = tmp_path, ROOT / "src/fmb/generation"
    result = pipeline.verify_pilot_directory_residue(tmp_path / "absent-image.vmdk")
    assert (
        result["postcondition_verified"] is True
        and result["directories"] == []
        and "not_applicable" in result
    )
    assert json.loads((tmp_path / "pilot-i30-retention.json").read_text()) == result


def test_directory_residue_gate_refuses_a_receipt_that_differs_from_its_plan(tmp_path):
    from fmb.generation.pipeline import GenerationPipeline

    plan = plan_for("i3")
    receipt = synthetic_receipt(plan)
    receipt["members"] = [
        row
        for row in receipt["members"]
        if row["operation_class"] != "recreated_children"
    ]
    (tmp_path / "factual-challenge-plan.json").write_text(json.dumps(plan))
    (tmp_path / "factual-challenge-receipt.json").write_text(json.dumps(receipt))
    pipeline = GenerationPipeline.__new__(GenerationPipeline)
    pipeline.output_dir, pipeline.work_dir = tmp_path, ROOT / "src/fmb/generation"
    with pytest.raises(ValueError, match="planned recreated-child"):
        pipeline.verify_pilot_directory_residue(tmp_path / "absent-image.vmdk")
