from __future__ import annotations

import getpass
import platform
import sys
from pathlib import Path
from typing import Any

from fmb.collection.tools.envelope import (
    build_tool_bundle_manifest,
    validate_tool_execution_payload,
)
from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json

HOST_COLLECTOR_TOOL = "fmb-host-collector"
HOST_COLLECTOR_VERSION = "1"
HOST_COLLECTOR_CAPABILITY = "fmb_host_collector"
KAPEFILES_LABEL = "KapeFiles definitions c47575d8 (vendored)"
HOST_MOUNT_MODE = "host_sleuthkit_read_only"
COLLECTOR_OUTPUT_HINT = "kape-output"
RESULT_FILE = "tool_run_result.json"
MANIFEST_FILE = "tool_bundle_manifest.json"
METADATA_FILE = "host_collector_metadata.json"
METADATA_SCHEMA_VERSION = "fmb_host_collector_metadata.v1"
METADATA_BINDING_KEY = "host_collector_metadata"
TOOL_LOGS_DIR = "tool-logs"
PARSER_APPLIANCE_ARG = "--parser-appliance"
PARSER_APPLIANCE_MODULES_ARG = "--parser-appliance-modules"


def parser_appliance_request_args(mode: str, modules: list[str]) -> list[str]:
    names = [str(item).strip() for item in modules if str(item).strip()]
    return [
        f"{PARSER_APPLIANCE_ARG}={mode}",
        f"{PARSER_APPLIANCE_MODULES_ARG}={','.join(names)}",
    ]


def parser_appliance_authorization(request: dict[str, Any]) -> dict[str, Any]:
    collection = request.get("requested_collection")
    args = collection.get("extra_args") if isinstance(collection, dict) else None
    mode: str | None = None
    modules: list[str] = []
    for item in args if isinstance(args, list) else []:
        text = str(item)
        if text.startswith(PARSER_APPLIANCE_ARG + "="):
            mode = text[len(PARSER_APPLIANCE_ARG) + 1 :].strip() or None
        elif text.startswith(PARSER_APPLIANCE_MODULES_ARG + "="):
            modules = [
                part.strip()
                for part in text[len(PARSER_APPLIANCE_MODULES_ARG) + 1 :].split(",")
                if part.strip()
            ]
    return {"mode": mode, "modules": modules}


def metadata_binding(result: dict[str, Any]) -> dict[str, Any] | None:
    environment = result.get("execution_environment")
    binding = environment.get(METADATA_BINDING_KEY) if isinstance(environment, dict) else None
    if not isinstance(binding, dict):
        return None
    path = binding.get("path")
    digest = binding.get("sha256")
    if not isinstance(path, str) or not path or not isinstance(digest, str) or not digest:
        return None
    return {"path": path, "sha256": digest.lower()}


def host_execution_environment(
    *,
    definitions_sha256: str,
    toolchain: dict[str, Any] | None,
    source_hash_basis: str,
) -> dict[str, Any]:
    return {
        "platform": sys.platform,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "hostname": platform.node() or None,
        "operator": getpass.getuser(),
        "collection_agent": HOST_COLLECTOR_TOOL,
        "collection_agent_version": HOST_COLLECTOR_VERSION,
        "python": sys.version.split()[0],
        "kape_definitions": {"source": KAPEFILES_LABEL, "sha256": definitions_sha256},
        "parser_toolchain": toolchain,
        "source_hash_basis": source_hash_basis,
    }


def build_host_result(
    *,
    request: dict[str, Any],
    request_path: Path,
    evidence_path: Path,
    evidence_sha256: str,
    evidence_id: str | None,
    drive_letter: str,
    targets: str,
    modules: str,
    command_line: str,
    argv: list[str],
    started_at: str,
    ended_at: str,
    duration_seconds: float,
    stdout_relative: str,
    stdout_sha256: str,
    stderr_relative: str,
    stderr_sha256: str,
    execution_environment: dict[str, Any],
    definitions_sha256: str,
    exit_code: int,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    result = {
        "schema_version": "tool_run_result.v1",
        "request_id": str(request["request_id"]),
        "request_sha256": sha256_file(request_path),
        "run_id": str(request["run_id"]),
        "question_id": str(request["question"]["question_id"]),
        "collector": "kape",
        "execution_environment": execution_environment,
        "tool_identity": {
            "name": HOST_COLLECTOR_TOOL,
            "executable_path": f"{HOST_COLLECTOR_TOOL} executing {KAPEFILES_LABEL}",
            "version": f"{HOST_COLLECTOR_TOOL}/{HOST_COLLECTOR_VERSION}",
            "executable_sha256": definitions_sha256,
        },
        "source_evidence": {
            "evidence_id": evidence_id,
            "path_seen_by_worker": str(evidence_path),
            "sha256": evidence_sha256,
            "sha256_expected": evidence_sha256,
            "sha256_observed": evidence_sha256,
            "hash_verified": True,
            "mount_mode": HOST_MOUNT_MODE,
            "read_only_asserted": True,
            "source_drive": f"{drive_letter}:",
            "source_drive_not_boot_drive": True,
        },
        "executed_collection": {
            "collector": "kape",
            "targets": targets,
            "modules": modules,
            "profile": None,
            "extra_args": [str(item) for item in (extra_args or [])],
        },
        "command": {
            "command_line": command_line,
            "argv": list(argv),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_seconds,
            "timestamp_basis": "host_utc_clock",
        },
        "output": {
            "collector_output_root": COLLECTOR_OUTPUT_HINT,
            "stdout_path": stdout_relative,
            "stdout_sha256": stdout_sha256,
            "stderr_path": stderr_relative,
            "stderr_sha256": stderr_sha256,
        },
        "artifact_manifest": {"path": MANIFEST_FILE, "sha256": None},
        "status": {
            "exit_code": exit_code,
            "result": "success" if exit_code == 0 else "failure",
        },
    }
    validate_tool_execution_payload(result, "tool_run_result")
    return result


def write_host_bundle_documents(
    *,
    bundle_dir: Path,
    request: dict[str, Any],
    request_path: Path,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Path]:
    metadata_path = bundle_dir / METADATA_FILE
    write_json(metadata_path, {"schema_version": METADATA_SCHEMA_VERSION, **metadata})
    environment = result.setdefault("execution_environment", {})
    environment[METADATA_BINDING_KEY] = {
        "path": METADATA_FILE,
        "sha256": sha256_file(metadata_path),
    }
    validate_tool_execution_payload(result, "tool_run_result")
    result_path = bundle_dir / RESULT_FILE
    write_json(result_path, result)
    manifest = build_tool_bundle_manifest(
        request=request,
        result=result,
        request_path=request_path,
        result_path=result_path,
        collector_output_root=bundle_dir / COLLECTOR_OUTPUT_HINT,
    )
    manifest["collector_output_root"] = COLLECTOR_OUTPUT_HINT
    manifest_path = bundle_dir / MANIFEST_FILE
    write_json(manifest_path, manifest)
    return {"result": result_path, "manifest": manifest_path, "metadata": metadata_path}


__all__ = [
    "COLLECTOR_OUTPUT_HINT",
    "HOST_COLLECTOR_CAPABILITY",
    "HOST_COLLECTOR_TOOL",
    "HOST_COLLECTOR_VERSION",
    "HOST_MOUNT_MODE",
    "MANIFEST_FILE",
    "METADATA_BINDING_KEY",
    "METADATA_FILE",
    "METADATA_SCHEMA_VERSION",
    "PARSER_APPLIANCE_ARG",
    "PARSER_APPLIANCE_MODULES_ARG",
    "RESULT_FILE",
    "TOOL_LOGS_DIR",
    "build_host_result",
    "host_execution_environment",
    "metadata_binding",
    "parser_appliance_authorization",
    "parser_appliance_request_args",
    "write_host_bundle_documents",
]
