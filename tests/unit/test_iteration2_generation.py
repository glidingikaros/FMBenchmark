from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "src/fmb/contracts/schemas/generation_recipe.schema.json").read_text(encoding="utf-8"))


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"iteration2_{name}", ROOT / "src/fmb/generation" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if name == "population":
        module.POPULATION_CONTRACT_PATH = ROOT / "tests/fixtures/generation/populations.v1.json"
        module.load_population_contract.__defaults__ = (module.POPULATION_CONTRACT_PATH,)
    return module


@pytest.fixture(scope="module")
def population():
    return load("population")


@pytest.fixture(scope="module")
def pipeline():
    return load("pipeline")


def guest_plan(population, *, seed: int = 20260912, case: str = "positive"):
    manifest = population.build_public_manifest(experiment="full_scale", seed=seed)
    assignment = population.select_private_assignment(manifest, entropy=b"iteration-2-tests" * 2)
    return population.build_guest_plan(manifest, assignment, case=case)


def definition_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]})


def test_stomp_instants_are_utc_whole_seconds_inside_bounds_and_seed_dependent(population) -> None:
    pairs = {seed: population._seeded_stomp_timestamps(seed) for seed in range(1, 41)}
    for pair in pairs.values():
        assert len(pair) == 2 and len(set(pair)) == 2
        for stamp in pair:
            assert stamp.endswith("Z")
            instant = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            assert population.STOMP_YEAR_RANGE[0] <= instant.year <= population.STOMP_YEAR_RANGE[1]
            assert instant.microsecond == 0
    assert len({tuple(pair) for pair in pairs.values()}) == len(pairs)
    assert population._seeded_stomp_timestamps(7) == population._seeded_stomp_timestamps(7)


def test_seeded_lengths_stay_inside_their_declared_bounds(population) -> None:
    low, high = population.LOGICAL_LENGTH_RANGE
    lengths = {population._seeded_logical_length(seed, index) for seed in range(1, 30) for index in range(8)}
    assert all(low <= value <= high for value in lengths)
    assert len(lengths) > 1
    low, high = population.PADDING_BYTES_RANGE
    for seed in range(1, 30):
        padding = population._seeded_padding_bytes(seed)
        assert low <= padding <= high and (padding - low) % 512 == 0


def test_guest_plan_declares_utc_basis_seeded_parameters_and_retention(population) -> None:
    plan = guest_plan(population)
    stomp = plan["scenario_inputs"]["timestomp_01"]
    assert stomp["timestamp_basis"] == "utc"
    assert stomp["require_logfile_retention"] is True
    assert stomp["timestamps"] == population._seeded_stomp_timestamps(20260912)
    other = guest_plan(population, seed=20260913)
    assert other["scenario_inputs"]["timestomp_01"]["timestamps"] != stomp["timestamps"]
    benign = guest_plan(population, case="benign")
    assert benign["scenario_inputs"]["timestomp_01"]["require_logfile_retention"] is False
    assert benign["scenario_inputs"]["timestomp_01"]["timestamps"] == stomp["timestamps"]


def test_assigned_timestamp_must_be_the_requested_instant(population) -> None:
    matches = population._assigned_timestamp_matches
    assert matches("2010-05-04T03:02:01.0000000Z", "2010-05-04T03:02:01Z")
    assert matches("2010-05-04T05:02:01+02:00", "2010-05-04T03:02:01Z")
    assert not matches("2010-05-04T03:02:02Z", "2010-05-04T03:02:01Z")
    assert not matches("2010-05-04T03:02:01", "2010-05-04T03:02:01Z")
    assert matches("2010-05-04T03:02:01+00:00", "2010-05-04T03:02:01")


def test_timestomp_receipt_with_a_different_instant_is_refused(population, verified_receipts) -> None:
    plan = guest_plan(population)
    receipts = verified_receipts(population, plan, case="positive")
    population.validate_guest_receipts(plan, receipts, case="positive")
    drifted = deepcopy(receipts)
    stomp = next(row for row in drifted if row["scenario_id"] == "timestomp_01")
    stomp["instances"][0]["assigned_timestamp"] = "2010-05-04T03:02:01.0000000Z"
    with pytest.raises(population.PopulationError, match="invalid instances"):
        population.validate_guest_receipts(plan, drifted, case="positive")


def test_timestomp_task_parses_the_assigned_instant_as_utc() -> None:
    task = (ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/timestomp_01.yml").read_text(encoding="utf-8")
    assert "AssumeUniversal" in task and "AdjustToUniversal" in task


def test_timestomp_runs_last_in_the_execution_order(pipeline) -> None:
    assert pipeline.execution_order(["timestomp_01", "ads_injection_01", "usn_journal_01"]) == [
        "ads_injection_01", "usn_journal_01", "timestomp_01",
    ]
    assert pipeline.execution_order(["ads_injection_01"]) == ["ads_injection_01"]


def _targets():
    return [{"path": "C:\\Records\\Files\\f_1.txt", "assigned_timestamp": "2010-05-04T03:02:01Z",
             "original_creation_utc": "2026-09-12T10:00:00Z"}]


def test_retention_check_reports_an_unavailable_runtime_and_refuses_when_required(monkeypatch, tmp_path) -> None:
    module = load("logfile_retention")
    import fmb.index.scanners.logfile_runtime as runtime
    monkeypatch.setattr(runtime, "logfile_runtime_availability", lambda *a, **k: {"available": False, "reason": "lock"})
    receipt = module.check_logfile_retention(tmp_path / "image.vmdk", targets=_targets(), output_dir=tmp_path, require=False)
    assert receipt["status"] == "runtime_unavailable" and receipt["reason"] == "lock"
    written = json.loads((tmp_path / module.RECEIPT_NAME).read_text(encoding="utf-8"))
    assert written == receipt
    definition_validator("logfile_retention_receipt").validate(written)
    with pytest.raises(ValueError, match="locked dfir_ntfs"):
        module.check_logfile_retention(tmp_path / "image.vmdk", targets=_targets(), output_dir=tmp_path, require=True)


def test_retention_check_needs_a_readable_image(monkeypatch, tmp_path) -> None:
    module = load("logfile_retention")
    import fmb.index.scanners.logfile_runtime as runtime
    monkeypatch.setattr(runtime, "logfile_runtime_availability", lambda *a, **k: {"available": True})
    receipt = module.check_logfile_retention(tmp_path / "missing.vmdk", targets=_targets(), output_dir=tmp_path, require=False)
    assert receipt["status"] == "image_unreadable"
    with pytest.raises(ValueError, match="could not read the exported image"):
        module.check_logfile_retention(tmp_path / "missing.vmdk", targets=_targets(), output_dir=tmp_path, require=True)


@pytest.mark.parametrize("rolled_back,expected", [(False, "retained"), (True, "not_retained")])
def test_retention_check_binds_the_committed_transition_of_each_target(monkeypatch, tmp_path, rolled_back, expected) -> None:
    module = load("logfile_retention")
    import fmb.collection.tools.host.ntfs_index as ntfs_index
    from fmb.index.adapters import logfile as logfile_adapters
    import fmb.index.scanners.logfile_runtime as runtime

    class FakeIndex:
        def __init__(self, path):
            assert Path(path).name == "image.vmdk"

        def copy_stream(self, entry, name, write):
            write(b"x")

        def resolve_directories(self, components):
            return [5] if components == ["Records", "Files"] else []

        def iter_links(self, directory):
            return [("f_1.txt", 77), ("other.txt", 78)] if directory == 5 else []

    update = {
        "mft_entry": 77, "lsn": 100, "covered_fields": ["created", "modified"],
        "new": {"created": "2010-05-04T03:02:01+00:00", "modified": "2010-05-04T03:02:01+00:00"},
        "old": {"created": "2026-09-12T10:00:00+00:00", "modified": "2026-09-12T10:00:05+00:00"},
        "transaction_forgotten_lsn": 123, "transaction_rolled_back": rolled_back,
    }
    monkeypatch.setattr(runtime, "logfile_runtime_availability", lambda *a, **k: {"available": True})
    monkeypatch.setattr(runtime, "run_logfile_driver", lambda path, output_path: {
        "parse": {"lsn_first": 1, "lsn_last": 200, "record_count": 3, "page_coverage_complete": True,
                  "records_truncated": False, "multi_client": False, "parse_error_count": 0},
        "embedded_usn": {"record_count": 0}, "records": [], "lifecycle_records": [],
    })
    monkeypatch.setattr(ntfs_index, "VolumeIndex", FakeIndex)
    monkeypatch.setattr(logfile_adapters, "_logfile_bound_updates", lambda document, **kwargs: ([update], {"bound": 1}))
    (tmp_path / "image.vmdk").write_bytes(b"image")
    receipt = module.check_logfile_retention(tmp_path / "image.vmdk", targets=_targets(), output_dir=tmp_path, require=False)
    assert receipt["status"] == expected
    row = receipt["targets"][0]
    assert row["mft_entry"] == 77 and row["candidate_update_count"] == 1
    assert row["retained"] is (not rolled_back) and row["transition_lsn"] == 100
    definition_validator("logfile_retention_receipt").validate(receipt)
    if rolled_back:
        with pytest.raises(ValueError, match="not retained"):
            module.check_logfile_retention(tmp_path / "image.vmdk", targets=_targets(), output_dir=tmp_path, require=True)


def test_visit_budgets_are_frozen_validated_recipe_parameters(population) -> None:
    budgets = population.validate_visit_budgets(population.SHELLBAG_VISIT_BUDGETS)
    assert budgets == {"match_seconds": 40, "close_seconds": 40, "child_seconds": 360,
                       "dispatch_seconds": 480, "snapshot_ms": 2000}
    plan = guest_plan(population)
    assert plan["scenario_inputs"]["shellbag_path_residue_01"]["visit_budgets"] == budgets
    for broken, message in [
        ({**budgets, "child_seconds": 41}, "child budget"),
        ({**budgets, "dispatch_seconds": 67}, "dispatch budget"),
        ({**budgets, "snapshot_ms": "2000"}, "outside its bounds"),
        ({**budgets, "match_seconds": 0}, "outside its bounds"),
        ({key: value for key, value in budgets.items() if key != "snapshot_ms"}, "incomplete"),
    ]:
        with pytest.raises(population.PopulationError, match=message):
            population.validate_visit_budgets(broken)


def test_shellbag_receipt_must_echo_the_frozen_budgets_and_carry_timing(population, verified_receipts) -> None:
    plan = guest_plan(population)
    receipts = verified_receipts(population, plan, case="positive")
    population.validate_guest_receipts(plan, receipts, case="positive")

    def shellbag(rows):
        return next(row for row in rows if row["scenario_id"] == "shellbag_path_residue_01")

    instrumented = deepcopy(receipts)
    for item in shellbag(instrumented)["native_receipts"]:
        item["dispatch_elapsed_ms"] = item["explore_elapsed_ms"]
    population.validate_guest_receipts(plan, instrumented, case="positive")

    other = deepcopy(receipts)
    shellbag(other)["visit_budgets"]["dispatch_seconds"] = 120
    with pytest.raises(population.PopulationError, match="differ from the frozen"):
        population.validate_guest_receipts(plan, other, case="positive")
    for mutation in (
        lambda item: item.pop("snapshot_count"),
        lambda item: item.update(snapshot_count=12),
        lambda item: item.update(explore_elapsed_ms=item["visit_elapsed_ms"] + 1),
        lambda item: item.update(visit_elapsed_ms=-1),
        lambda item: item.update(dispatch_elapsed_ms=item["explore_elapsed_ms"] + 1),
        lambda item: item.update(dispatch_elapsed_ms=-1),
    ):
        mutated = deepcopy(receipts)
        mutation(shellbag(mutated)["native_receipts"][3])
        with pytest.raises(population.PopulationError, match="native Explorer postconditions"):
            population.validate_guest_receipts(plan, mutated, case="positive")


def test_native_helper_and_task_take_budgets_from_the_frozen_recipe() -> None:
    files = ROOT / "src/fmb/generation/ansible/roles/manipulation/files"
    helper = (files / "native_shellbag.ps1").read_text(encoding="utf-8")
    task = (ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/shellbag_path_residue_01.yml").read_text(encoding="utf-8")
    assert "Set-LocalNativeShellbagVisitBudgets -Budgets $scenarioInput.visit_budgets" in task
    assert "visit_budgets = Get-LocalNativeShellbagVisitBudgets" in task
    for literal in ("-lt 20)", "-lt 70)", "$maxElapsedMilliseconds = 2000", "ValidateRange(1, 44)"):
        assert literal not in helper
    assert "-TimeoutSeconds $childSeconds" in helper
    assert "$dispatchWatch.Elapsed.TotalSeconds -lt $dispatchSeconds" in helper
    for field in ("visit_elapsed_ms", "explore_elapsed_ms", "snapshot_count"):
        assert field in helper


def ansible_debug(*items: str) -> str:
    body = ",\n".join(f"        {json.dumps(item)}" for item in items)
    return 'ok: [default] => {\n    "msg": [\n' + body + "\n    ]\n}\n"


def clock_run(pipeline, policy, *, receipt=None, checkpoints=(), host=None):
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.recipe_bundle = None if policy is None else {"recipe": {"config": {"clock_policy": policy}, "recipe_id": "r"}}
    instance.marker_receipt_times = []
    host = host or datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
    output = "TASK [noise]\nok: [default]\n"
    if receipt is not None:
        output += ansible_debug("GENERATION_CLOCK_BEGIN", json.dumps(receipt), "GENERATION_CLOCK_END")
        instance.marker_receipt_times.append(('"GENERATION_CLOCK_BEGIN",', host.isoformat()))
    for stage, guest_offset, host_offset in checkpoints:
        guest = (host + timedelta(seconds=guest_offset)).isoformat()
        point = {"stage": stage, "guest_utc": guest,
                 "measurement": clock_measurement(guest, host + timedelta(seconds=host_offset))}
        output += ansible_debug("GENERATION_CLOCKPOINT_BEGIN", json.dumps(point), "GENERATION_CLOCKPOINT_END")
        instance.marker_receipt_times.append(('"GENERATION_CLOCKPOINT_BEGIN",', (host + timedelta(seconds=host_offset)).isoformat()))
    return instance, output


def clock_measurement(guest, host):
    return {"protocol": "winrm_bracketed_relative.v1", "host_send_utc": (host - timedelta(seconds=.01)).isoformat(),
            "host_receive_utc": (host + timedelta(seconds=.01)).isoformat(), "guest_utc": guest,
            "monotonic_elapsed_seconds": .02}


def clock_receipt(policy="host_sync_then_service_stopped", *, applied=True, status="Stopped", guest_after="2026-09-12T12:00:01+00:00"):
    before = "2026-09-12T21:58:00+00:00"
    calibration = clock_measurement(before, datetime(2026, 9, 12, 11, 59, 59, tzinfo=timezone.utc))
    measurement = clock_measurement(guest_after, datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc))
    return {"schema_version": "generation_clock_receipt.v2", "policy": policy, "applied": applied,
            "host_utc_iso": calibration["host_send_utc"], "guest_utc_before": before,
            "guest_utc_after": guest_after, "w32time_status": status,
            "calibration_measurement": calibration, "measurement": measurement}


def test_clock_block_records_offsets_checkpoints_and_meets_the_policy(pipeline) -> None:
    instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=clock_receipt(),
                                 checkpoints=[("manipulation_start", 61.0, 60.5), ("manipulation_end", 301.0, 300.0),
                                              ("pre_export", 901.5, 900.5)])
    block = instance.capture_clock_receipt(output)
    definition_validator("clock_receipt").validate(block)
    assert block["policy_met"] is True and block["applied"] is True
    assert block["offset_seconds_after"] == 1.0
    assert [row["stage"] for row in block["checkpoints"]] == ["manipulation_start", "manipulation_end", "pre_export"]
    assert block["checkpoints"][0]["offset_seconds"] == 0.5
    assert block["max_backward_step_seconds"] == 0.0
    assert block["offset_drift_seconds"] == pytest.approx(0.520002)
    assert block["tolerance_seconds"] == load("clock_protocol").TOLERANCE_SECONDS


@pytest.mark.parametrize("checkpoints,message", [
    ([("manipulation_start", 61.0, 60.0), ("manipulation_end", 50.0, 300.0), ("pre_export", 900.0, 900.0)], "backward step"),
    ([("manipulation_start", 36061.0, 60.0), ("manipulation_end", 36301.0, 300.0), ("pre_export", 36900.0, 900.0)], "offsets"),
    ([("manipulation_start", 61.0, 60.0), ("manipulation_end", 303.5, 300.0), ("pre_export", 900.0, 900.0)], "offsets"),
    ([("manipulation_start", 61.0, 60.0), ("manipulation_end", 301.0, 300.0)], "guest clock policy violated"),
])
def test_clock_policy_violations_make_the_attempt_a_failure_record(pipeline, checkpoints, message) -> None:
    instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=clock_receipt(), checkpoints=checkpoints)
    with pytest.raises(ValueError, match=message):
        instance.capture_clock_receipt(output)
    assert instance.clock_block["policy_met"] is False


def test_clock_receipt_must_match_the_frozen_policy_and_prove_the_stopped_service(pipeline) -> None:
    instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=clock_receipt(status="Running"),
                                 checkpoints=[("manipulation_start", 1.0, 1.0), ("manipulation_end", 2.0, 2.0)])
    with pytest.raises(ValueError, match="not applied"):
        instance.capture_clock_receipt(output)
    instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=clock_receipt(policy="unmanaged"),
                                 checkpoints=[("manipulation_start", 1.0, 1.0), ("manipulation_end", 2.0, 2.0)])
    with pytest.raises(ValueError, match="differs from the frozen policy"):
        instance.capture_clock_receipt(output)
    instance, output = clock_run(pipeline, "host_sync_then_service_stopped", checkpoints=[("manipulation_start", 1.0, 1.0)])
    with pytest.raises(ValueError, match="exactly one guest clock receipt"):
        instance.capture_clock_receipt(output)


def test_unmanaged_policy_records_the_drift_without_refusing(pipeline) -> None:
    instance, output = clock_run(pipeline, "unmanaged", receipt=clock_receipt("unmanaged", applied=False, status="Running",
                                                                             guest_after="2026-09-12T22:00:01+00:00"),
                                 checkpoints=[("manipulation_start", 36001.0, 1.0), ("manipulation_end", 2.0, 200.0)])
    block = instance.capture_clock_receipt(output)
    assert block["policy_met"] is True and block["applied"] is False
    assert block["max_backward_step_seconds"] > 0
    definition_validator("clock_receipt").validate(block)


def test_recipes_without_a_policy_reject_stray_clock_receipts_and_keep_running_unmanaged(pipeline) -> None:
    instance, output = clock_run(pipeline, None)
    assert instance.capture_clock_receipt(output) is None
    instance, output = clock_run(pipeline, None, receipt=clock_receipt())
    with pytest.raises(ValueError, match="without a frozen clock policy"):
        instance.capture_clock_receipt(output)


def test_playbook_applies_the_policy_before_any_role_and_checkpoints_the_population() -> None:
    import yaml
    playbook = yaml.safe_load((ROOT / "src/fmb/generation/ansible/playbook.yml").read_text(encoding="utf-8"))
    first = playbook[0]
    assert first["gather_facts"] is False
    wait, emit, policy = first["tasks"]
    script = wait["ansible.windows.win_shell"]
    assert "Microsoft-Windows-Time-Service" in script and "Id=37" in script and "-lt {{ fmb_boot_sync_seconds | default(120) | int }}" in script
    assert not any(verb in script for verb in ("Set-Service", "Stop-Service", "Start-Service", "Set-Date",
                                               "Set-Item", "New-Item", "Remove-Item", "w32tm", "sc.exe"))
    assert emit["ansible.builtin.debug"]["msg"].startswith("FMB_BOOT_SYNC ")
    assert policy["ansible.builtin.include_tasks"] == "recipe_clock.yml"
    assert wait["when"] == emit["when"] == policy["when"] == "fmb_clock_policy is defined"
    last = playbook[-1]
    assert last["tasks"][0]["ansible.builtin.include_tasks"] == "clock_checkpoint.yml"
    assert last["tasks"][0]["vars"]["fmb_clock_stage"] == "pre_export"
    main = yaml.safe_load((ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/main.yml").read_text(encoding="utf-8"))
    stages = [task["vars"]["fmb_clock_stage"] for task in main if "vars" in task and "fmb_clock_stage" in task["vars"]]
    assert stages == ["manipulation_start", "manipulation_end"]
    clock = (ROOT / "src/fmb/generation/ansible/recipe_clock.yml").read_text(encoding="utf-8")
    assert "fmb_clock:" in clock and "fmb_host_utc_iso" not in clock
    protocol = (ROOT / "src/fmb/generation/clock_protocol.py").read_text(encoding="utf-8")
    assert "Stop-Service -Name w32time" in protocol and "UtcNow.AddTicks" in protocol
    assert (ROOT / "src/fmb/generation/ansible/action_plugins/fmb_clock.py").is_file()


