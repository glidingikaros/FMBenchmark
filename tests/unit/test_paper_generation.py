from __future__ import annotations
from copy import deepcopy


import json


import re


from pathlib import Path


import struct


import subprocess


import pytest


import yaml


from fmb.generation.factual_challenge import build_plan


from fmb.generation.logfile_retention import _matches_complete_transition


from fmb.generation.pilot_media import check_slots, match_backings


from fmb.generation.population import SHELLBAG_VISIT_BUDGETS, build_guest_plan, build_public_manifest, load_population_contract, select_private_assignment, validate_guest_receipts, operation_refs_sha256


from fmb.generation.recipe import validate_resolved_inputs


from fmb.evaluation.factual_reference import supplemental_status


from fmb.analysis.population_binding import verify_population_manifest


from fmb.collection.usb_volume import usb_volume_source_manifests


from fmb.core.hashing import sha256_file


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "occupied",
    [
        'usb_xhci:9.present = "FALSE"',
        'usb_xhci:3.port = "2"',
        'usb_xhci:10.fileName = "other.vmdk"',
    ],
)
def test_pilot_refuses_every_occupied_slot_or_port(occupied):
    _, _, plan = resolved()
    layout = plan["scenario_inputs"]["usbstor_setupapi_discrepancy_01"]["media"]
    check_slots('usb_xhci:0.port = "0"', layout)
    with pytest.raises(RuntimeError, match="occupies"):
        check_slots(occupied, layout)


def _usb_set(tmp_path):
    rows = []
    for number in range(3):
        name = f"media_{number:012x}.json"
        child = tmp_path / Path(name).stem / "native-usb-volume.json"
        child.parent.mkdir()
        child.write_text(
            json.dumps(
                {
                    "schema_version": "native_usb_volume_sources.v1",
                    "evidence_sha256": "a" * 64,
                    "companion_sha256": str(number) * 64,
                    "sources": {"binding": {"file": name}},
                }
            )
        )
        rows.append(
            {
                "binding_file": name,
                "file": str(child.relative_to(tmp_path)),
                "sha256": sha256_file(child),
            }
        )
    path = tmp_path / "native-usb-volumes.json"
    value = {
        "schema_version": "native_usb_volume_set.v1",
        "evidence_sha256": "a" * 64,
        "volumes": rows,
    }
    path.write_text(json.dumps(value))
    return path, value


@pytest.mark.parametrize(
    "change",
    ["empty", "repeated", "swapped", "tampered", "other_evidence", "same_companion"],
)
def test_three_usb_source_receipts_are_complete_and_separately_bound(tmp_path, change):
    path, value = _usb_set(tmp_path)
    assert len(usb_volume_source_manifests(path)) == 3
    if change == "empty":
        value["volumes"].clear()
    elif change == "repeated":
        value["volumes"][1] = deepcopy(value["volumes"][0])
    elif change == "swapped":
        value["volumes"][1]["file"] = value["volumes"][0]["file"]
    else:
        row = value["volumes"][1]
        child = tmp_path / row["file"]
        data = json.loads(child.read_text())
        if change == "other_evidence":
            data["evidence_sha256"] = "b" * 64
        elif change == "same_companion":
            data["companion_sha256"] = "0" * 64
        else:
            data["tampered"] = True
        child.write_text(json.dumps(data))
        if change != "tampered":
            row["sha256"] = sha256_file(child)
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        usb_volume_source_manifests(path)


def resolved():
    contract = load_population_contract(
        ROOT / "src/fmb/generation/populations.pilot-i1-20260918.json"
    )
    public = build_public_manifest(
        experiment="full_scale", seed=2026091811, contract=contract
    )
    assignment = select_private_assignment(
        public, entropy=b"pilot-offline-check-20260916"
    )
    return public, assignment, build_guest_plan(public, assignment)


def test_same_year_construction_changes_the_creation_low_byte():
    plan = build_plan(
        2026091707,
        shellbag_input={"visit_budgets": SHELLBAG_VISIT_BUDGETS},
        profile="pilot_min.v1",
    )
    row = next(
        member for member in plan["members"] if member["operation_class"] == "same_year"
    )
    observed_before = 134340692126102719
    for field in ("creation_filetime", "modified_filetime"):
        after = observed_before + row["timestamp_deltas"][field]
        assert after < observed_before
        assert (
            after.to_bytes(8, "little")[0] != observed_before.to_bytes(8, "little")[0]
        )
        assert all(
            (byte + row["timestamp_deltas"][field]) % 256 != byte for byte in range(256)
        )


def test_registered_complete_scope_and_disjoint_native_device_components():
    public, _, plan = resolved()
    assert verify_population_manifest(public) == public
    assert public["declared_count"] == 56
    inputs = plan["scenario_inputs"]
    identity = inputs["usbstor_setupapi_discrepancy_01"]
    history = inputs["usb_volume_activity_gap_01"]
    assert identity["operation_refs"] != history["operation_refs"]
    assert identity["media"] == history["media"]
    assert sorted(
        (row["installation_discrepancy"], row["history_discrepancy"])
        for row in identity["media"]
    ) == [(False, False), (False, True), (True, False)]
    assert len({r["binding_file"] for r in identity["media"]}) == 3
    assert len({r["companion_file"] for r in identity["media"]}) == 3
    assert inputs["security_log_clear_event_01"]["operation_refs"] == []
    assert len(inputs["event_record_sequence_gap_01"]["operation_refs"]) == 1
    assert not set(inputs["timestomp_01"]["archive_restore_paths"]) & set(
        inputs["timestomp_01"]["operation_refs"]
    )
    assert len(inputs["timestomp_01"]["archive_restore_paths"]) == 1


def test_pilot_cannot_be_frozen_without_matching_profile_and_managed_clock():
    from fmb.generation.recipe import paper_config
    public = build_public_manifest(experiment="full_scale", seed=2026091811)
    assignment = select_private_assignment(public, entropy=b"paper-validation"*2)
    plan = build_guest_plan(public, assignment)
    config = paper_config("I1")
    validate_resolved_inputs(config, public, assignment, plan)
    for changes in ({"factual_challenge": None}, {"clock_policy": "unmanaged"}, {"activity_count": 36}):
        with pytest.raises(ValueError, match="fixed paper"):
            validate_resolved_inputs({**config, **changes}, public, assignment, plan)


def test_mixed_log_case_requires_a_verified_no_clear_receipt():
    _, _, plan = resolved()
    sid = "security_log_clear_event_01"
    scoped = {**plan, "scenario_inputs": {sid: plan["scenario_inputs"][sid]}}
    row = dict(
        scenario_id=sid,
        case="benign",
        operation_count=0,
        operation_refs_sha256=operation_refs_sha256([]),
        postcondition_verified=True,
        event_id=None,
        record_id=None,
    )
    assert validate_guest_receipts(scoped, [row], case="positive") == [row]
    row["event_id"] = 1102
    with pytest.raises(ValueError, match="Event 1102"):
        validate_guest_receipts(scoped, [row], case="positive")


@pytest.mark.parametrize("event_id", [1101, 1102, 4624])
def test_log_a_preserves_audit_loss_but_refuses_clearing(monkeypatch, event_id):
    from fmb.generation import event_sequence_injection, pilot_profile
    from fmb.index.scanners import evtx_sequence

    class Record:
        def record_num(self):
            return 7

        def xml(self):
            return (
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                f"<System><EventID>{event_id}</EventID></System></Event>"
            )

    class Chunk:
        def records(self):
            return [Record()]

    monkeypatch.setattr(event_sequence_injection, "_active_chunks", lambda _: [Chunk()])
    monkeypatch.setattr(evtx_sequence, "retained_record_ids", lambda _: (7,))
    if event_id == 1102:
        with pytest.raises(ValueError, match="inherited clearing"):
            pilot_profile.validate_log_a_source(b"unchanged source")
    else:
        pilot_profile.validate_log_a_source(b"unchanged source")


@pytest.mark.parametrize(
    ("qid", "operation", "status"),
    [
        ("BQ-SHELLBAG-01", "recreated", "not_supported"),
        ("BQ-SHELLBAG-01", "present_case", "not_supported"),
        ("BQ-SHELLBAG-01", "renamed", "supported"),
        ("BQ-DIRECTORY-01", "recreated_children", "supported"),
        ("BQ-DIRECTORY-01", "moved_children", "not_supported"),
        ("BQ-DELETE-01", "entry_reused", "supported"),
        ("BQ-STREAM-01", "empty_zip", "not_supported"),
        ("BQ-STREAM-01", "second_pe", "supported"),
    ],
)
def test_reference_consequences_follow_the_approved_subject_semantics(
    qid, operation, status
):
    assert supplemental_status(qid, operation) == status


@pytest.mark.parametrize("defect", [None, "partial", "tick", "uncommitted", "rollback"])
def test_complete_pilot_transition_requires_every_declared_native_tick(defect):
    expected = {
        "old": {
            "created": "2026-09-16T10:00:00.0000001Z",
            "modified": "2026-09-16T11:00:00.0000002Z",
        },
        "new": {
            "created": "2026-09-02T10:00:00.0000001Z",
            "modified": "2026-09-02T11:00:00.0000002Z",
        },
    }
    update = {
        **deepcopy(expected),
        "covered_fields": ["created", "modified"],
        "transaction_forgotten_lsn": 777,
        "transaction_rolled_back": False,
    }
    if defect == "partial":
        update["covered_fields"] = ["modified"]
    if defect == "tick":
        update["new"]["modified"] = "2026-09-02T11:00:00.0000001Z"
    if defect == "uncommitted":
        update["transaction_forgotten_lsn"] = None
    if defect == "rollback":
        update["transaction_rolled_back"] = True
    assert _matches_complete_transition(update, expected) is (defect is None)


def boot(serial):
    data = bytearray(512)
    data[3:11] = b"NTFS    "
    struct.pack_into("<H", data, 11, 512)
    data[13] = 8
    struct.pack_into("<QQQ", data, 40, 131072, 4, 8)
    struct.pack_into("<bb", data, 64, -10, 0)
    struct.pack_into("<b", data, 68, -12)
    struct.pack_into("<Q", data, 72, serial)
    data[510:] = b"\x55\xaa"
    return bytes(data)


@pytest.mark.parametrize(
    "defect", [None, "duplicate_serial", "wrong_serial", "wrong_partition"]
)
def test_backing_reconciliation_uses_native_serials_and_refuses_ambiguity(defect):
    disks = {Path("one.vmdk"): 11, Path("two.vmdk"): 22, Path("three.vmdk"): 33}

    class Reader:
        size = 67_108_864

        def __init__(self, path, **kwargs):
            self.path = path

        def read_at(self, offset, size):
            assert offset == 0 and size == 512
            return boot(disks[self.path])

    bindings = [
        {
            "subject_ref": str(serial),
            "native_binding": {
                "volume_serial_number": f"{serial:08x}",
                "partition_offset_bytes": 0,
            },
        }
        for serial in (33, 11, 22)
    ]
    if defect == "duplicate_serial":
        disks[Path("two.vmdk")] = 11
    if defect == "wrong_serial":
        bindings[0]["native_binding"]["volume_serial_number"] = "00000001"
    if defect == "wrong_partition":
        bindings[0]["native_binding"]["partition_offset_bytes"] = 512
    sources = [{"path": p} for p in disks]
    if defect is None:
        assert match_backings(sources, bindings, reader_factory=Reader) == {
            "33": Path("three.vmdk"),
            "11": Path("one.vmdk"),
            "22": Path("two.vmdk"),
        }
    else:
        with pytest.raises(ValueError, match="serial|identity"):
            match_backings(sources, bindings, reader_factory=Reader)


@pytest.mark.pwsh
def test_all_pilot_powershell_parses_without_running_guest_operations(tmp_path):
    source = ROOT / "src/fmb/generation/ansible/roles/manipulation"
    files = list((source / "files").glob("pilot_*.ps1"))
    for task in (source / "tasks").glob("pilot_*.yml"):
        for item in yaml.safe_load(task.read_text()):
            command = item.get("ansible.windows.win_shell")
            if command is None:
                continue
            rendered = re.sub(
                r"\{\{ lookup\('file', role_path \+ '/files/([^']+)'\) \| indent\(4\) \}\}",
                lambda match: (source / "files" / match[1])
                .read_text()
                .replace("\n", "\n    "),
                command,
            )
            assert "{{" not in rendered
            import base64

            assert len(base64.b64encode(rendered.encode("utf-16le"))) + 1024 < 32767
            path = tmp_path / (task.stem + ".ps1")
            path.write_text(rendered)
            files.append(path)
    checker = tmp_path / "parse.ps1"
    checker.write_text(
        "$ErrorActionPreference='Stop'; foreach($p in $args){$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors);if($errors.Count){$errors|ForEach-Object{Write-Error ($p+': '+$_.Message)};exit 1}}"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(checker), *map(str, files)],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("profile", ["pilot_min.v1"])
def test_ansible_loads_and_routes_actual_dynamic_scenario_tasks_locally(
    tmp_path, profile
):
    import os
    import shutil

    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible runtime is unavailable")
    dispatcher = (
        ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/execute_scenario.yml"
    )
    shutil.copyfile(dispatcher, tmp_path / dispatcher.name)
    scenarios = [
        "security_log_clear_event_01",
        "ads_injection_01",
        "bitmap_trailing_data_01",
        "typed_path_residue_01",
        "usbstor_setupapi_discrepancy_01",
        "usb_volume_activity_gap_01",
        "ntfs_allocation_01",
        "timestomp_01",
    ]
    pilot_routes = set(scenarios[2:7])
    names = (
        scenarios
        + ["pilot_" + name for name in sorted(pilot_routes)]
        + [
            "factual_security_checkpoint",
            "pilot_challenge",
            "factual_challenge",
            "archive_restore_controls",
        ]
    )
    for name in names:
        (tmp_path / (name + ".yml")).write_text(
            yaml.safe_dump(
                [
                    {
                        "ansible.builtin.set_fact": {
                            "fmb_test_dispatch": "{{ fmb_test_dispatch + ['"
                            + name
                            + "'] }}"
                        }
                    }
                ]
            )
        )
    expected = []
    for name in scenarios:
        if name == "security_log_clear_event_01" and profile is not None:
            expected.append("factual_security_checkpoint")
        if name == "timestomp_01":
            if profile is not None:
                expected.append(
                    "pilot_challenge"
                    if profile == "pilot_min.v1"
                    else "factual_challenge"
                )
            expected.append("archive_restore_controls")
        expected.append(
            ("pilot_" if profile == "pilot_min.v1" and name in pilot_routes else "")
            + name
        )
    variables = {
        "fmb_test_dispatch": [],
        "expected_dispatch": expected,
        "generation_inputs": {
            "native_pilot_profile": profile or "",
            "scenario_inputs": {"timestomp_01": {"require_archive_retention": True}},
        },
    }
    if profile is not None:
        variables["fmb_factual_challenge_plan"] = {"profile": profile}
    play = tmp_path / "dispatch.yml"
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": [
                        {
                            "ansible.builtin.include_tasks": dispatcher.name,
                            "loop": scenarios,
                            "loop_control": {"loop_var": "fmb_scenario_item"},
                        },
                        {
                            "ansible.builtin.assert": {
                                "that": ["fmb_test_dispatch == expected_dispatch"]
                            }
                        },
                    ],
                }
            ]
        )
    )
    result = subprocess.run(
        [executable, "-i", "localhost,", "-c", "local", str(play)],
        cwd=tmp_path,
        env={
            **os.environ,
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_NOCOWS": "1",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
        },
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("defect", [None, "extra_operation", "missing_control"])
def test_pilot_allocation_executes_exact_frozen_shape_with_native_api_doubles(
    tmp_path, defect
):
    from test_native_allocation_diagnostics import public_input, mock_prefix, run_body

    ordinary = public_input(tmp_path, "positive")
    payload = deepcopy(ordinary)
    selected = [0, 1, 2, 3]
    for key in ("population_paths", "storage_cases"):
        payload[key] = [ordinary[key][index] for index in selected]
    payload.update(
        operation_refs=payload["population_paths"][:1],
        expected_population_count=4,
        expected_operation_count=1,
    )
    if defect == "extra_operation":
        payload["operation_refs"] = payload["population_paths"][:2]
        payload["expected_operation_count"] = 2
    elif defect == "missing_control":
        payload["population_paths"].pop()
    tasks = ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks"
    body = yaml.safe_load((tasks / "pilot_ntfs_allocation_01.yml").read_text())[0][
        "ansible.windows.win_shell"
    ]
    legacy = yaml.safe_load((ROOT / "tests/fixtures/generation/ntfs_allocation_01.yml").read_text())[0][
        "ansible.windows.win_shell"
    ]
    assert body == legacy.replace(
        "$expectedPopulationCount -lt 1", "$expectedPopulationCount -ne 4"
    ).replace(
        "$expectedOperationCount -ne $(if ($case -eq 'positive') { 2 } else { 0 })",
        "$expectedOperationCount -ne $(if ($case -eq 'positive') { 1 } else { 0 })",
    )
    result = run_body(
        tmp_path, json.dumps(payload), body=mock_prefix(ordinary) + "\n" + body
    )
    if defect:
        assert result["native_failure_code"] == "population_cardinality_invalid"
        assert result["native_diagnostic"]["last_api_stage"] == "not_called"
    else:
        assert result["postcondition_verified"] is True
        assert result["operation_count"] == 1 and result["population_count"] == 4
        assert result["prepared_modes"] == [
            "ordinary",
            "ordinary",
            "resident",
            "preallocation_request_then_close",
        ]
        assert len(result["preallocation_close_controls"]) == 1


