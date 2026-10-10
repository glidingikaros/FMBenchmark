from __future__ import annotations

import copy
import json
import importlib.util
from pathlib import Path

import os

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "src/fmb/generation"
spec = importlib.util.spec_from_file_location("generation_pipeline_recipe_test", SOURCE / "pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
recipe = pipeline.recipe_support
build_guest_plan = pipeline.build_guest_plan
build_public_manifest = pipeline.build_public_manifest
select_private_assignment = pipeline.select_private_assignment

FULL_SCALE_EXECUTION_ORDER = (
    "ads_injection_01,prefetch_wipe_01,security_log_clear_event_01,"
    "usn_journal_01,shimcache_path_residue_01,typed_path_residue_01,"
    "shellbag_path_residue_01,ntfs_allocation_01,bitmap_trailing_data_01,"
    "directory_cleaning_i30_01,usbstor_setupapi_discrepancy_01,"
    "usb_volume_activity_gap_01,event_record_sequence_gap_01,timestomp_01"
)


@pytest.fixture
def locked_recipe(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    vmx = base / "box.vmx"
    vmx.write_text('nvme0:0.fileName = "disk.vmdk"\n')
    descriptor = base / "disk.vmdk"
    descriptor.write_text('# Disk DescriptorFile\nparentCID=ffffffff\nRW 1 FLAT "disk-flat.vmdk" 0\n')
    extent = base / "disk-flat.vmdk"
    extent.write_bytes(b"retained disk extent")
    artifacts = []
    def add(path, role):
        artifacts.append({"path": str(path), "role": role, "size_bytes": path.stat().st_size,
                          "sha256": recipe.file_digest(path)})
    for path in [vmx, descriptor, extent]:
        add(path, "base")
    tools = {}
    for name in sorted(recipe.REQUIRED_TOOLS):
        path = tmp_path / name
        path.write_text("test dependency " + name)
        add(path, "provider" if name == "vmrun" else "runtime")
        tools[name] = {"path": str(path), "version": "test-1"}
    collection = tmp_path / "collection.py"
    collection.write_text("test collection")
    add(collection, "ansible_collection")
    lock = {"schema_version": recipe.LOCK_SCHEMA,
            "base": {"provider": "vmware_desktop", "box": "fmb/windows-11-arm64", "version": "0",
                     "vmx_path": str(vmx)},
            "guest": {"windows_build": "26100", "timezone": "UTC", "locale": "en-US"},
            "tools": tools, "artifacts": artifacts}
    config = recipe.paper_config("I1")
    public = build_public_manifest(experiment="full_scale", seed=config["population_seed"])
    assignment = select_private_assignment(public, entropy=b"a" * 32)
    private_plan = build_guest_plan(public, assignment, case="positive")
    destination = tmp_path / "recipe"
    recipe.freeze_recipe(destination, source_root=SOURCE, config=config, population=public,
                         assignment=assignment, guest_plan=private_plan, dependency_lock=lock,
                         activity_seed=config["population_seed"], hardware_seed=config["population_seed"])
    return destination, lock, config, public, assignment, private_plan


def test_recipe_retains_exact_private_assignment_and_source(locked_recipe):
    directory, lock, config, public, assignment, plan = locked_recipe
    loaded = recipe.load_recipe(directory, source_root=SOURCE)
    assert loaded["private"]["assignment"] == assignment
    assert loaded["private"]["guest_plan"] == plan
    assert loaded["private"]["population_manifest"] == public
    assert "new_realization" in loaded["recipe"]["regeneration_claim"]
    assert os.name == "nt" or (directory / "private-generation.json").stat().st_mode & 0o777 == 0o600
    assert (directory / "source/pipeline.py").read_bytes() == (SOURCE / "pipeline.py").read_bytes()


@pytest.mark.parametrize("remove", [False, True])
def test_frozen_recipe_binds_the_host_clock_action_plugin(locked_recipe, remove):
    directory, *_ = locked_recipe
    executing_source = directory / "source"
    plugin = executing_source / "ansible/action_plugins/fmb_clock.py"
    assert plugin.read_bytes() == (SOURCE / "ansible/action_plugins/fmb_clock.py").read_bytes()
    recipe.load_recipe(directory, source_root=executing_source)
    if remove:
        plugin.unlink()
    else:
        plugin.write_bytes(plugin.read_bytes() + b"\n# changed host clock action\n")
    with pytest.raises(ValueError, match="executing generation source differs"):
        recipe.load_recipe(directory, source_root=executing_source)


def test_same_recipe_prepares_same_targets_without_new_entropy(locked_recipe, monkeypatch, tmp_path):
    directory, lock, config, public, assignment, plan = locked_recipe
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    first = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', case='positive', population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None, recipe=directory, output_root=tmp_path / 'out')
    def no_selection(*args, **kwargs):
        raise AssertionError("replay must not select new targets")
    monkeypatch.setattr(pipeline, "select_private_assignment", no_selection)
    first.prepare_population()
    try:
        payload = json.loads(first.population_inputs_path.read_text())
        assert first.private_population_assignment == assignment
        assert payload["generation_inputs"] == plan
        assert payload["fmb_activity_plan"] == recipe.resolved_activity(config["population_seed"], count=12)
        assert payload["fmb_hardware"] == recipe.resolved_hardware(config["population_seed"])
        assert "assignment" not in payload
        assert "candidate_ids" not in payload
        assert first.vagrant_environment()["FMB_BOX_VERSION"] == "0"
        assert first.vagrant_environment()["FMB_RECIPE_MODE"] == "1"
    finally:
        first.cleanup_population_inputs()
    assert (directory / "private-generation.json").is_file()
    assert first.population_inputs_path is None


@pytest.mark.parametrize("policy", ["host_sync_then_service_stopped"])
def test_frozen_clock_policy_reaches_execution_without_an_override(
    locked_recipe, monkeypatch, tmp_path, policy
):
    from fmb.replication import steps

    _, lock, config, public, assignment, plan = locked_recipe
    directory = tmp_path / "clock-recipe"
    recipe.freeze_recipe(
        directory, source_root=SOURCE, config={**config, "clock_policy": policy},
        population=public, assignment=assignment, guest_plan=plan,
        dependency_lock=lock, activity_seed=config["population_seed"], hardware_seed=config["population_seed"],
    )
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    observed = []

    def run_without_vm(instance):
        instance.prepare_population()
        try:
            observed.append(instance.frozen_clock_policy())
            assert instance.private_population_assignment == assignment
            assert instance.population_guest_plan == plan
        finally:
            instance.cleanup_population_inputs()

    monkeypatch.setattr(pipeline.GenerationPipeline, "run", run_without_vm)
    monkeypatch.setattr(steps, "_load_generation_pipeline", lambda: pipeline)
    assert steps.generate(recipe=str(directory), output_root=str(tmp_path / "execution"))["status"] == "completed"
    assert observed == [policy]


@pytest.mark.parametrize("member", ["private-generation.json", "dependency-lock.json", "source/pipeline.py"])
def test_changed_retained_recipe_member_fails(locked_recipe, member):
    directory = locked_recipe[0]
    path = directory / member
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        recipe.load_recipe(directory, source_root=SOURCE)


def test_changed_external_dependency_fails(locked_recipe):
    directory, lock, *_ = locked_recipe
    Path(lock["tools"]["vagrant"]["path"]).write_text("substituted")
    with pytest.raises(ValueError, match="dependency changed"):
        recipe.load_recipe(directory, source_root=SOURCE)


def test_missing_base_extent_is_not_a_complete_lock(locked_recipe):
    _, lock, *_ = locked_recipe
    bad = copy.deepcopy(lock)
    bad["artifacts"] = [item for item in bad["artifacts"] if not item["path"].endswith("disk-flat.vmdk")]
    with pytest.raises(ValueError, match="extent"):
        recipe.validate_dependency_lock(bad)


def test_recipe_rejects_source_drift(locked_recipe, tmp_path):
    source = tmp_path / "new-source"
    source.mkdir()
    (source / "pipeline.py").write_text("changed source")
    with pytest.raises(ValueError, match="executing generation source"):
        recipe.load_recipe(locked_recipe[0], source_root=source)


def test_private_json_duplicate_keys_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"role": "one", "role": "two"}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        recipe.read_json(path)


def test_activity_and_hardware_are_independent_of_assignment_rng():
    assert recipe.resolved_activity(12) == recipe.resolved_activity(12)
    assert recipe.resolved_activity(12) != recipe.resolved_activity(13)
    assert recipe.resolved_hardware(34) != recipe.resolved_hardware(35)
    assert len(recipe.resolved_activity(12)) == 36


def test_recipe_runtime_receipts_require_actual_completion(locked_recipe, tmp_path):
    directory = locked_recipe[0]
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.recipe_bundle = recipe.load_recipe(directory, source_root=SOURCE)
    instance.output_dir = tmp_path
    environment = instance.recipe_bundle["lock"]["guest"]
    activity = {"schema_version": "generation_activity_receipt.v1", "completed_count": 11,
                "started_utc": "2026-01-01T00:00:00Z", "completed_utc": "2026-01-01T00:00:10Z"}
    output = "\n".join(["GENERATION_ENVIRONMENT_BEGIN", json.dumps(environment),
                         "GENERATION_ENVIRONMENT_END", "GENERATION_ACTIVITY_BEGIN",
                         json.dumps(activity), "GENERATION_ACTIVITY_END"])
    with pytest.raises(ValueError, match="activity completion"):
        instance.capture_recipe_runtime(output)
    assert not (tmp_path / "recipe-runtime-receipt.json").exists()
    instance.capture_clock_receipt = lambda _: {}
    instance.capture_recipe_runtime(output.replace('"completed_count": 11', '"completed_count": 12'))
    assert (tmp_path / "recipe-runtime-receipt.json").is_file()


def test_dependency_failure_precedes_any_vm_preflight_or_launch(locked_recipe, tmp_path, monkeypatch):
    directory, lock, *_ = locked_recipe
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', case='positive', population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None, recipe=directory, output_root=tmp_path / 'run')
    Path(lock["tools"]["vagrant"]["path"]).write_text("changed")
    monkeypatch.setattr(instance, "preflight_checks", lambda: pytest.fail("dependency failure must precede VM preflight"))
    monkeypatch.setattr(instance, "provision_vm", lambda: pytest.fail("VM must not launch"))
    monkeypatch.setattr(instance, "cleanup", lambda: {})
    with pytest.raises(ValueError, match="dependency changed"):
        instance.run()


def test_freezing_never_launches_a_vm(locked_recipe, tmp_path, monkeypatch):
    from fmb.replication import steps

    _, lock, *_ = locked_recipe
    lock_path = tmp_path / "input-lock.json"
    lock_path.write_text(json.dumps(lock))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline.GenerationPipeline, "run", lambda self: pytest.fail("freeze must not execute"))
    monkeypatch.setattr(steps, "_load_generation_pipeline", lambda: pipeline)
    destination = tmp_path / "frozen"
    assert steps.freeze(image="I1", provider="vmware_desktop", lock=str(lock_path),
                        recipe=str(destination))["status"] == "completed"
    loaded = recipe.load_recipe(destination, source_root=SOURCE)
    assert loaded["recipe"]["config"] == recipe.paper_config("I1")
    assert len(loaded["private"]["activity_plan"]) == 12


def test_freezing_an_own_image_starts_its_clock_behind_the_mac_box(locked_recipe, tmp_path, monkeypatch):
    from fmb.replication import host, steps

    _, lock, *_ = locked_recipe
    lock_path = tmp_path / "input-lock.json"
    lock_path.write_text(json.dumps(lock))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline.GenerationPipeline, "run", lambda self: pytest.fail("freeze must not execute"))
    monkeypatch.setattr(steps, "_load_generation_pipeline", lambda: pipeline)
    monkeypatch.setattr(host, "base_guest_facts", lambda: pytest.fail("a Mac image reads the box, not the base"))
    monkeypatch.setattr(host, "box_guest_facts", lambda: None)
    definition = json.loads((SOURCE.parents[2] / "tests/fixtures/images/subset.json").read_text(encoding="utf-8"))
    image = tmp_path / "own.json"
    image.write_text(json.dumps({**definition, "generation": {"clock_bias_minutes": "auto"}}), encoding="utf-8")
    destination = tmp_path / "frozen"
    steps.freeze(image="own", provider="vmware_desktop", lock=str(lock_path), recipe=str(destination),
                 image_file=str(image))
    config = recipe.load_recipe(destination, source_root=SOURCE)["recipe"]["config"]
    assert config["vmware_boot_clock_bias_minutes"] == 482
    monkeypatch.setattr(host, "box_guest_facts", lambda: {"build": "26100", "finished_utc": "2026-07-01T12:00:00+00:00"})
    summer = tmp_path / "summer"
    steps.freeze(image="own", provider="vmware_desktop", lock=str(lock_path), recipe=str(summer), image_file=str(image))
    assert recipe.load_recipe(summer, source_root=SOURCE)["recipe"]["config"]["vmware_boot_clock_bias_minutes"] == 422


def test_each_replay_gets_new_realization_identity(locked_recipe, tmp_path, monkeypatch):
    directory, lock, *_ = locked_recipe
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    refs = []
    for _ in range(2):
        instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', case='positive', population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None, recipe=directory, output_root=tmp_path / 'runs')
        refs.append(json.loads((instance.output_dir / "recipe-reference.json").read_text()))
    assert refs[0]["recipe_id"] == refs[1]["recipe_id"]
    assert refs[0]["realization_id"] != refs[1]["realization_id"]
    assert all(ref["regeneration_status"] == "not_independently_validated" for ref in refs)


@pytest.mark.skipif(os.name == "nt", reason="the VMware dependency-lock schema records POSIX artifact paths (macOS generator)")
def test_actual_frozen_records_validate_against_registered_contracts(locked_recipe, tmp_path, monkeypatch):
    from fmb.core.schemas import validate_payload
    directory, lock, *_ = locked_recipe
    loaded = recipe.load_recipe(directory, source_root=SOURCE)
    for filename, schema in [
        ("recipe.json", "generation_recipe.schema.json"),
        ("private-generation.json", "private_generation.schema.json"),
        ("dependency-lock.json", "generation_dependency_lock.schema.json"),
    ]:
        validate_payload(json.loads((directory / filename).read_text()), schema)
    validate_payload(loaded["private"]["assignment"], "private_assignment.schema.json")
    validate_payload(loaded["private"]["guest_plan"], "generation_inputs.schema.json")
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', case='positive', population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None, recipe=directory, output_root=tmp_path / 'run')
    validate_payload(json.loads((instance.output_dir / "recipe-reference.json").read_text()),
                     "generation_recipe_reference.schema.json")
    activity = {"schema_version": "generation_activity_receipt.v1", "completed_count": 12,
                "started_utc": "2026-01-01T00:00:00Z", "completed_utc": "2026-01-01T00:00:10Z"}
    output = "\n".join(["GENERATION_ENVIRONMENT_BEGIN", json.dumps(lock["guest"]),
                         "GENERATION_ENVIRONMENT_END", "GENERATION_ACTIVITY_BEGIN",
                         json.dumps(activity), "GENERATION_ACTIVITY_END"])
    from test_iteration2_generation import clock_run, clock_receipt
    clock_instance, clock_output = clock_run(
        pipeline, "host_sync_then_service_stopped", receipt=clock_receipt(),
        checkpoints=[("manipulation_start", 61.0, 60.5),
                     ("manipulation_end", 301.0, 300.0), ("pre_export", 901.5, 900.5)])
    block = clock_instance.capture_clock_receipt(clock_output)
    instance.capture_clock_receipt = lambda _: block
    instance.capture_recipe_runtime(output)
    validate_payload(activity, "generation_activity_receipt.schema.json")
    validate_payload(json.loads((instance.output_dir / "recipe-runtime-receipt.json").read_text()),
                     "generation_runtime_receipt.schema.json")
    from copy import deepcopy
    from fmb.core.errors import SchemaValidationError
    from fmb.generation import logfile_retention

    factual = {
        "question_id": "BQ-TIME-01", "operation_class": "same_year",
        "path": r"C:\Public\same-year.txt",
        "before": {"creation_filetime": 134200800000000123, "modified_filetime": 134200800000000456},
        "after": {"creation_filetime": 134200700000000123, "modified_filetime": 134200700000000456},
    }
    (instance.output_dir / "factual-challenge-receipt.json").write_text(json.dumps({"members": [factual]}))
    monkeypatch.setattr(instance, "population_guest_plan", {"native_pilot_profile": "pilot_min.v1"})
    monkeypatch.setattr(instance, "logfile_retention_planned", lambda: {
        "operation_refs": [], "require_logfile_retention": True,
    })
    monkeypatch.setattr(instance, "ground_truth_receipts", lambda: [])

    def retained_export(image, *, targets, output_dir, require, timeline):
        assert require is True and len(targets) == 1
        assert targets[0]["path"] == factual["path"]
        assert set(targets[0]["expected_transition"]) == {"old", "new"}
        return {
            "schema_version": "generation_logfile_retention_receipt.v1",
            "image": str(image), "required": require, "status": "retained",
            "targets": [{**targets[0], "mft_entry": 10, "assigned_timestamp": None,
                         "original_creation_utc": None, "retained": True, "transition_lsn": 500,
                         "committed": True, "candidate_update_count": 1}],
        }

    monkeypatch.setattr(logfile_retention, "check_logfile_retention", retained_export)
    attached = instance.check_logfile_retention(tmp_path / "final-export.vmdk")
    runtime = json.loads((instance.output_dir / "recipe-runtime-receipt.json").read_text())
    assert runtime["logfile_retention"] == attached
    validate_payload(runtime, "generation_runtime_receipt.schema.json")
    legacy = deepcopy(runtime)
    legacy["logfile_retention"]["targets"][0].pop("expected_transition")
    validate_payload(legacy, "generation_runtime_receipt.schema.json")
    for path in [("old",), ("new",), ("old", "created"), ("old", "modified"),
                 ("new", "created"), ("new", "modified")]:
        malformed = deepcopy(runtime)
        transition = malformed["logfile_retention"]["targets"][0]["expected_transition"]
        parent = transition
        for part in path[:-1]:
            parent = parent[part]
        parent.pop(path[-1])
        with pytest.raises(SchemaValidationError, match="validation failed"):
            validate_payload(malformed, "generation_runtime_receipt.schema.json")
    for path, value in [(("unexpected",), True), (("old", "unexpected"), True),
                        (("old", "created"), "invalid"),
                        (("old", "created"), "2026-05-01T00:00:00"),
                        (("old", "created"), 123)]:
        malformed = deepcopy(runtime)
        parent = malformed["logfile_retention"]["targets"][0]["expected_transition"]
        for part in path[:-1]:
            parent = parent[part]
        parent[path[-1]] = value
        with pytest.raises(SchemaValidationError, match="validation failed"):
            validate_payload(malformed, "generation_runtime_receipt.schema.json")
    for value in (None, []):
        malformed = deepcopy(runtime)
        malformed["logfile_retention"]["targets"][0]["expected_transition"] = value
        with pytest.raises(SchemaValidationError, match="validation failed"):
            validate_payload(malformed, "generation_runtime_receipt.schema.json")
    malformed = deepcopy(runtime)
    malformed["logfile_retention"]["targets"][0]["unrelated"] = True
    with pytest.raises(SchemaValidationError, match="validation failed"):
        validate_payload(malformed, "generation_runtime_receipt.schema.json")
    from types import SimpleNamespace
    monkeypatch.setattr(pipeline.shutil, "disk_usage", lambda _: SimpleNamespace(free=100 * 1024**3))
    instance.preflight_generation_storage(Path(lock["base"]["vmx_path"]))
    validate_payload(json.loads((instance.output_dir / "generation_storage_preflight.json").read_text()),
                     "generation_storage_preflight.schema.json")


@pytest.mark.parametrize("field,value", [
    ("regeneration_claim", "byte_identical"), ("source_sha256", "bad-digest"),
    ("recipe_id", "original-image:fake"),
])
def test_recipe_schema_rejects_false_claim_or_broken_identity(locked_recipe, field, value):
    from fmb.core.schemas import schema_validation_errors
    frozen = json.loads((locked_recipe[0] / "recipe.json").read_text())
    frozen[field] = value
    assert schema_validation_errors(frozen, "generation_recipe.schema.json")


def test_private_schema_rejects_truth_field_in_guest_projection(locked_recipe):
    from fmb.core.schemas import schema_validation_errors
    private = json.loads((locked_recipe[0] / "private-generation.json").read_text())
    private["guest_plan"]["scenario_inputs"]["timestomp_01"]["candidate_ids"] = ["secret"]
    assert schema_validation_errors(private, "private_generation.schema.json")


def test_freshly_rehashed_inconsistent_guest_plan_fails_standalone_validation(locked_recipe):
    directory = locked_recipe[0]
    private = json.loads((directory / "private-generation.json").read_text())
    private["guest_plan"]["scenario_inputs"]["timestomp_01"]["operation_refs"] = []
    frozen = json.loads((directory / "recipe.json").read_text())
    frozen["private_sha256"] = recipe.digest(private)
    frozen["recipe_id"] = "recipe:" + recipe.digest({k: v for k, v in frozen.items() if k != "recipe_id"})
    (directory / "private-generation.json").write_text(json.dumps(private))
    (directory / "recipe.json").write_text(json.dumps(frozen))
    with pytest.raises(ValueError, match="guest plan differs"):
        recipe.load_recipe(directory, source_root=SOURCE)


