from __future__ import annotations

from pathlib import Path

import pytest

from fmb.collection.tools import envelope as execution_envelope
from fmb.index.contract import evidence_index
from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.core.schemas import validate_payload

pytestmark = pytest.mark.integration


def test_validated_external_bundle_feeds_collector_import(tmp_path: Path) -> None:
    output_root = tmp_path / "collector-output"
    artifact = (
        output_root
        / "Targets"
        / "C"
        / "Windows"
        / "System32"
        / "winevt"
        / "Logs"
        / "Security.evtx"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"portable external bundle evidence bytes\n")
    console_log = output_root / "kape.console.log"
    console_log.write_text(
        "Command line: KAPE.exe --target EventLogs\n", encoding="utf-8"
    )

    request_path = tmp_path / "tool_run_request.json"
    result_path = tmp_path / "tool_run_result.json"
    manifest_path = tmp_path / "tool_bundle_manifest.json"

    request = execution_envelope.build_tool_run_request(
        question_id="Q-LOG-01",
        question_text="Was the Windows Security log cleared?",
        collector="kape",
        run_id="run-portable-bundle",
        collector_config={
            "source": "E:",
            "targets": "EventLogs",
            "modules": None,
            "output": output_root,
        },
        expected_artifact_families=["windows.event_log.security"],
        source_evidence_id="case-image-001",
        source_evidence_sha256="a" * 64,
    )
    write_json(request_path, request)

    result = {
        "schema_version": "tool_run_result.v1",
        "request_id": request["request_id"],
        "request_sha256": sha256_file(request_path),
        "run_id": request["run_id"],
        "question_id": request["question"]["question_id"],
        "collector": "kape",
        "execution_environment": {
            "platform": "windows",
            "os": "Windows Server",
            "architecture": "x64",
        },
        "tool_identity": {
            "name": "kape",
            "executable_path": "KAPE.exe",
            "version": "1.0",
            "executable_sha256": None,
        },
        "source_evidence": {
            "evidence_id": "case-image-001",
            "path_seen_by_worker": "E:",
            "sha256": "a" * 64,
            "sha256_expected": "a" * 64,
            "sha256_observed": "a" * 64,
            "hash_verified": True,
            "mount_mode": "read_only",
            "read_only_asserted": True,
            "source_drive": "E:",
            "source_drive_not_boot_drive": True,
        },
        "executed_collection": {
            "collector": "kape",
            "targets": "EventLogs",
            "modules": None,
            "extra_args": [],
        },
        "command": {"command_line": "KAPE.exe --target EventLogs"},
        "output": {"collector_output_root": str(output_root)},
        "artifact_manifest": {"path": str(manifest_path)},
        "status": {"exit_code": 0, "result": "success"},
    }
    write_json(result_path, result)
    manifest = execution_envelope.build_tool_bundle_manifest(
        request=request,
        result=result,
        request_path=request_path,
        result_path=result_path,
        collector_output_root=output_root,
    )
    write_json(manifest_path, manifest)

    validated = execution_envelope.validate_external_tool_bundle(
        request_path=request_path,
        result_path=result_path,
        manifest_path=manifest_path,
    )
    envelope = validated["execution_envelope"]
    assert envelope["bundle_validation"]["status"] == "passed"

    collector_run = evidence_index.inventory_collector_output(
        collector="kape",
        output_root=validated["collector_output_root"],
        target_or_profile=envelope["target_or_profile"],
        command_line=envelope["command_line"],
        adapter_scope="run_then_inventory_tool_output",
        execution_envelope=envelope,
    )
    imported_index = evidence_index.assemble_evidence_index(
        run_id=request["run_id"],
        question_id=request["question"]["question_id"],
        question_text=request["question"]["question_text"],
        collector_runs=[collector_run],
        rule_runs=[],
    )
    validate_payload(imported_index, "evidence_index.schema.json")

    assert collector_run["provenance"]["bundle_validation"]["status"] == "passed"
    assert collector_run["provenance"]["expected_artifact_families"] == [
        "windows.event_log.security"
    ]
    assert collector_run["provenance"]["exact_replay_command_available"] is True
    assert {item["relative_path"] for item in collector_run["artifacts"]} == {
        "Targets/C/Windows/System32/winevt/Logs/Security.evtx",
        "kape.console.log",
    }
    assert collector_run["provenance"]["collector_plan_declarations"] == [
        {
            "artifact_family": "windows.event_log.security",
            "source_surface": "collector_plan",
            "coverage_role": "direct",
            "method": "collector_plan_declaration",
            "source_field": "requested_collection.expected_artifact_families",
            "basis": "collector=kape targets=EventLogs",
            "request_expected": True,
        }
    ]
    assert {
        item["relative_path"]: item["artifact_family"]
        for item in collector_run["artifacts"]
    } == {
        "Targets/C/Windows/System32/winevt/Logs/Security.evtx": "collection.artifact",
        "kape.console.log": "collection.artifact",
    }
    assert all(
        item["artifact_id"].startswith("source-artifact:")
        for item in collector_run["artifacts"]
    )
