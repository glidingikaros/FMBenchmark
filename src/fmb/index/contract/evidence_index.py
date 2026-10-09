from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_file, sha256_json
from fmb.index.contract.artifact_declarations import (
    SOURCE_SURFACE_PARSER_NORMALIZED_OUTPUT,
    SOURCE_SURFACE_PARSER_RAW_OUTPUT,
    collected_artifact_family_evidence,
    expected_collection_family_evidence,
    parser_output_family_evidence,
    stamp_artifact_family_evidence,
)
from fmb.index.contract.constants import (
    COLLECTION_TOOLS,
    EVIDENCE_INDEX_SCHEMA_VERSION,
    PARSER_TOOLS,
    RULE_ENGINES,
    artifact_families_for_parser_kind,
    canonical_parser_tool_name,
    collection_tool_for_contract,
    observation_type_for_contract,
    parser_tool_for_contract,
)

COMMAND_LINE_RE = re.compile(r"\bcommand line:\s*(?P<command_line>.*)$", re.IGNORECASE)
COLLECTOR_ADAPTER_SCOPES = frozenset(
    {
        "inventory_existing_tool_output_no_collection_execution",
        "run_then_inventory_tool_output",
    }
)
PARSER_ADAPTER_SCOPE = "consume_external_parser_output"
RUN_STATUS_CONSUMED = "consumed"
PARSER_RUN_STATUS_CONSUMED_EMPTY = "consumed_empty"
CONSUMED_RUN_STATUSES = frozenset({RUN_STATUS_CONSUMED, PARSER_RUN_STATUS_CONSUMED_EMPTY})
COVERAGE_STATUS_UNAVAILABLE = "unavailable"


def non_negative_int_field(payload: dict[str, Any], key: str, *, label: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} {key} must be a non-negative integer")
    return value


def list_field(payload: dict[str, Any], key: str, *, label: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{label} {key} must be a list")
    return value


def require_count_matches(
    payload: dict[str, Any],
    *,
    count_key: str,
    list_key: str,
    label: str,
) -> list[Any]:
    items = list_field(payload, list_key, label=label)
    expected_count = non_negative_int_field(payload, count_key, label=label)
    if expected_count != len(items):
        raise ValueError(
            f"{label} {count_key} {expected_count} does not match {list_key} length {len(items)}"
        )
    return items


def assert_run_counts_match(
    runs: list[dict[str, Any]],
    *,
    count_key: str,
    list_key: str,
    label: str,
) -> None:
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"{label} {index} is not an object")
        require_count_matches(
            run,
            count_key=count_key,
            list_key=list_key,
            label=f"{label} {index}",
        )


def require_supported_tool_values(
    runs: list[dict[str, Any]],
    *,
    field: str,
    supported_values: set[str],
    label: str,
) -> None:
    unsupported = sorted(
        {
            str(item.get(field))
            for item in runs
            if item.get(field) not in supported_values
        }
    )
    if unsupported:
        raise ValueError(
            f"evidence index contains unsupported {label}: " + ", ".join(unsupported)
        )


def unconsumed_run_labels(*run_groups: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item.get('collector') or item.get('engine') or item.get('parser')}:{item.get('status')}"
        for run_group in run_groups
        for item in run_group
        if item.get("status") not in CONSUMED_RUN_STATUSES
    ]


def summarize_tool_alignment(
    *,
    collector_runs: list[dict[str, Any]],
    rule_runs: list[dict[str, Any]],
    parser_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    collection_tools_used = sorted(
        {str(run["collector"]) for run in collector_runs if run.get("collector")}
    )
    rule_engines_used = sorted(
        {str(run["engine"]) for run in rule_runs if run.get("engine")}
    )
    parser_tools_used = sorted(
        {
            canonical_parser_tool_name(str(run["parser"]))
            for run in parser_runs
            if run.get("parser")
        }
    )
    return {
        "collection_tools_supported": list(COLLECTION_TOOLS),
        "collection_tools_used": collection_tools_used,
        "rule_engines_supported": list(RULE_ENGINES),
        "rule_engines_used": rule_engines_used,
        "parser_tools_supported": list(PARSER_TOOLS),
        "parser_tools_used": parser_tools_used,
        "custom_forensic_heuristics_allowed": False,
        "normalization_role": "map_tool_outputs_to_project_contracts_only",
        "synthetic_fixture_role": "ground_truth_for_final_evaluation_only_not_analysis_input",
    }


def declared_observation_family_list(
    observation_families: Any,
    *,
    expected_artifact_families: set[str],
    parser_kind: str,
    label: str,
) -> list[str]:
    if observation_families is not None and (
        not isinstance(observation_families, list)
        or any(not isinstance(item, str) or not item for item in observation_families)
    ):
        raise ValueError(f"{label} observation_families must be non-empty strings")
    declared_observation_families = sorted(set(observation_families or []))
    unsupported_observation_families = sorted(
        set(declared_observation_families) - expected_artifact_families
    )
    if unsupported_observation_families:
        raise ValueError(
            f"{label} parser_kind {parser_kind} does not support observation_families: "
            + ", ".join(unsupported_observation_families)
        )
    return declared_observation_families


def parser_observation_record(
    observation: Any,
    *,
    expected_artifact_families: set[str],
    parser_kind: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ValueError(f"{label} is not an object")
    observation_id = observation.get("observation_id")
    if not isinstance(observation_id, str) or not observation_id:
        raise ValueError(f"{label} has no observation_id")
    artifact_family = observation.get("artifact_family")
    if not isinstance(artifact_family, str) or not artifact_family:
        raise ValueError(f"{label} has no artifact_family")
    if artifact_family not in expected_artifact_families:
        raise ValueError(
            f"{label} artifact_family {artifact_family} "
            f"is not supported by parser_kind {parser_kind}"
        )
    observation_type = observation_type_for_contract(
        observation.get("observation_type"), label=label
    )
    subject_ref = observation.get("subject_ref")
    if not isinstance(subject_ref, str) or not subject_ref:
        raise ValueError(f"{label} has no subject_ref")
    fields = observation.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise ValueError(f"{label} fields must be a non-empty object")
    source_record_ref = observation.get("source_record_ref")
    if not isinstance(source_record_ref, str) or not source_record_ref:
        raise ValueError(f"{label} has no source_record_ref")
    return {
        "observation_id": str(observation_id),
        "artifact_family": artifact_family,
        "observation_type": observation_type,
        "subject_ref": subject_ref,
        "fields": fields,
        "source_record_ref": source_record_ref,
    }


def parser_observation_records(
    observations: list[Any],
    *,
    expected_artifact_families: set[str],
    parser_kind: str,
    label_prefix: str,
    start_index: int,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for observation_index, observation in enumerate(observations, start=start_index):
        records.append(
            parser_observation_record(
                observation,
                expected_artifact_families=expected_artifact_families,
                parser_kind=parser_kind,
                label=f"{label_prefix} {observation_index}",
            )
        )
    return records


def observation_family_list(observations: list[dict[str, Any]]) -> list[str]:
    return sorted({str(observation["artifact_family"]) for observation in observations})


def require_observation_families_match(
    *,
    declared_observation_families: list[str],
    actual_observation_families: list[str],
    observation_families_was_declared: bool,
    label: str,
) -> None:
    if (
        observation_families_was_declared
        and declared_observation_families != actual_observation_families
    ):
        raise ValueError(
            f"{label} observation_families must match observed artifact families: "
            + ", ".join(actual_observation_families)
        )


def validate_parser_run(
    parser_run: dict[str, Any], *, run_index: int
) -> dict[str, Any]:
    if not isinstance(parser_run, dict):
        raise ValueError(f"parser run {run_index} is not an object")
    run_label = f"parser run {run_index}"
    canonical_parser = parser_tool_for_contract(
        parser_run.get("parser"), label=run_label
    )
    parser_kind = parser_run.get("parser_kind")
    expected_artifact_families = artifact_families_for_parser_kind(
        parser_kind, label=run_label
    )
    observation_families = parser_run.get("observation_families")
    declared_observation_families = declared_observation_family_list(
        observation_families,
        expected_artifact_families=expected_artifact_families,
        parser_kind=parser_kind,
        label=run_label,
    )

    raw_outputs = list_field(parser_run, "raw_outputs", label=f"parser run {run_index}")
    if not raw_outputs:
        raise ValueError(f"parser run {run_index} raw_outputs must not be empty")

    normalized_output = parser_run.get("normalized_output")
    if not isinstance(normalized_output, dict):
        raise ValueError(f"parser run {run_index} normalized_output must be an object")

    observations = require_count_matches(
        parser_run,
        count_key="observation_count",
        list_key="observations",
        label=f"parser run {run_index}",
    )
    normalized_record_count = non_negative_int_field(
        normalized_output,
        "record_count",
        label=f"parser run {run_index} normalized_output",
    )
    if normalized_record_count != len(observations):
        raise ValueError(
            f"parser run {run_index} normalized_output record_count {normalized_record_count} "
            f"does not match observations length {len(observations)}"
        )
    validated_observations = parser_observation_records(
        observations,
        expected_artifact_families=expected_artifact_families,
        parser_kind=parser_kind,
        label_prefix=f"{run_label} observation",
        start_index=0,
    )
    validate_source_record_references(
        validated_observations,
        raw_outputs=raw_outputs,
        label=run_label,
    )
    actual_observation_family_list = observation_family_list(validated_observations)
    require_observation_families_match(
        declared_observation_families=declared_observation_families,
        actual_observation_families=actual_observation_family_list,
        observation_families_was_declared=observation_families is not None,
        label=run_label,
    )

    return {
        **parser_run,
        "parser": canonical_parser,
        "observation_families": actual_observation_family_list,
    }


def inventory_artifact(
    *,
    path: Path,
    relative_path: str,
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    return stamp_artifact_family_evidence(
        {
            "relative_path": relative_path,
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        },
        declarations,
    )


def explicit_artifact_declarations_from_record(
    record: dict[str, Any] | None,
) -> list[dict[str, Any]] | None:
    if not isinstance(record, dict):
        return None
    if "artifact_family_declarations" not in record:
        return None
    declarations = record.get("artifact_family_declarations")
    if not isinstance(declarations, list) or not declarations:
        raise ValueError(
            "manifest artifact_family_declarations must be a non-empty list"
        )
    normalized: list[dict[str, Any]] = []
    for index, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            raise ValueError(
                f"manifest artifact_family_declarations[{index}] is not an object"
            )
        normalized.append(dict(declaration))
    return normalized


def manifest_artifact_records_by_relative_path(
    execution_envelope: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if not isinstance(execution_envelope, dict):
        return {}
    manifest = execution_envelope.get("bundle_manifest")
    if not isinstance(manifest, dict):
        return {}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        relative_path = artifact.get("relative_path")
        if isinstance(relative_path, str) and relative_path:
            records[relative_path] = artifact
    return records


def requested_collection_from_execution_envelope(
    execution_envelope: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(execution_envelope, dict):
        return None
    requested_collection = execution_envelope.get("requested_collection")
    if isinstance(requested_collection, dict):
        return requested_collection
    tool_run_request = execution_envelope.get("tool_run_request")
    if not isinstance(tool_run_request, dict):
        return None
    requested_collection = tool_run_request.get("requested_collection")
    if isinstance(requested_collection, dict):
        return requested_collection
    return None


def iter_collector_artifact_paths(output_path: Path) -> Iterator[tuple[Path, str]]:
    if output_path.is_file():
        yield output_path, output_path.name
        return

    for path in sorted(output_path.rglob("*")):
        if path.is_file():
            yield path, path.relative_to(output_path).as_posix()


def inventory_collector_artifacts(
    output_path: Path,
    *,
    declared_artifacts_by_relative_path: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    manifest_records = declared_artifacts_by_relative_path or {}
    for path, relative_path in iter_collector_artifact_paths(output_path):
        manifest_record = manifest_records.get(relative_path)
        artifacts.append(
            inventory_artifact(
                path=path,
                relative_path=relative_path,
                declarations=(
                    explicit_artifact_declarations_from_record(manifest_record)
                    or collected_artifact_family_evidence()
                ),
            )
        )
    return artifacts


def expected_artifact_families_from_execution_envelope(
    execution_envelope: dict[str, Any] | None,
) -> list[str]:
    requested_collection = requested_collection_from_execution_envelope(
        execution_envelope
    )
    if requested_collection is None:
        return []
    families = requested_collection.get("expected_artifact_families")
    if not isinstance(families, list):
        return []
    return sorted(
        {str(family) for family in families if isinstance(family, str) and family}
    )


def decode_console_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    encodings = (
        ("utf-16", "utf-8-sig", "utf-8")
        if data.count(b"\x00") > len(data) // 10
        else ("utf-8-sig", "utf-8", "utf-16")
    )
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeError:
            continue
    return data.decode("utf-8", errors="replace")


def is_command_log_name(name: str) -> bool:
    return "console" in name or name.endswith((".console.log", ".all-streams.log"))


def console_command_lines(
    output_root: Path,
    *,
    read_errors: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    if not output_root.is_dir():
        return []
    commands = []
    for path in sorted(output_root.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if not is_command_log_name(name):
            continue
        try:
            text = decode_console_text(path)
        except OSError as error:
            if read_errors is not None:
                read_errors.append(
                    {
                        "relative_path": path.relative_to(output_root).as_posix(),
                        "error_type": type(error).__name__,
                        "error": str(error),
                    }
                )
            continue
        for line in text.splitlines():
            stripped = line.strip()
            match = COMMAND_LINE_RE.search(stripped)
            if not match:
                continue
            command_line = match.group("command_line").strip()
            commands.append(
                {
                    "relative_path": path.relative_to(output_root).as_posix(),
                    "command_line": command_line,
                }
            )
    return commands


def command_line_discrepancies(
    intended_command_line: str | None,
    executed_commands: list[dict[str, str]],
) -> list[dict[str, str]]:
    if not intended_command_line or not executed_commands:
        return []
    discrepancies = []
    intended_folded = intended_command_line.casefold()
    for executed in top_level_replay_command_lines(executed_commands):
        command = executed["command_line"]
        if command and command.casefold() not in intended_folded:
            discrepancies.append(
                {
                    "relative_path": executed["relative_path"],
                    "executed_command_line": command,
                    "detail": "executed console command is not a literal substring of recorded intended command line",
                }
            )
    return discrepancies


def is_nested_tool_command(command: dict[str, str]) -> bool:
    relative_path = command.get("relative_path", "").replace("\\", "/")
    if not relative_path or "/" not in relative_path:
        return False
    if relative_path.startswith("tool_run_result."):
        return False
    if "exact_kape_rerun_metadata.json" in relative_path:
        return False
    parts = [part for part in relative_path.split("/") if part and part != "."]
    if (
        len(parts) == 2
        and parts[0].casefold() in {"targets", "modules"}
        and is_command_log_name(parts[1].casefold())
    ):
        return False
    return not relative_path.endswith(".all-streams.log")


def top_level_replay_command_lines(
    commands: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [command for command in commands if not is_nested_tool_command(command)]


def nested_tool_command_lines(commands: list[dict[str, str]]) -> list[dict[str, str]]:
    return [command for command in commands if is_nested_tool_command(command)]


def exact_replay_metadata_command_lines(
    output_root: Path,
    execution_envelope: dict[str, Any] | None,
    *,
    read_errors: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    if execution_envelope:
        command_line = execution_envelope.get("command_line")
        if isinstance(command_line, str) and command_line:
            commands.append(
                {
                    "relative_path": "tool_run_result.command.command_line",
                    "command_line": command_line,
                }
            )

    metadata_path = output_root.parent / "exact_kape_rerun_metadata.json"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            if read_errors is not None:
                read_errors.append(
                    {
                        "relative_path": str(
                            metadata_path.relative_to(output_root.parent)
                        ),
                        "error_type": type(error).__name__,
                        "error": str(error),
                    }
                )
            metadata = {}
        phase_runs = (
            metadata.get("phase_runs", []) if isinstance(metadata, dict) else []
        )
        if isinstance(phase_runs, list):
            for index, phase_run in enumerate(phase_runs):
                if not isinstance(phase_run, dict):
                    continue
                command_line = phase_run.get("command_line")
                if not isinstance(command_line, str) or not command_line:
                    continue
                commands.append(
                    {
                        "relative_path": f"../exact_kape_rerun_metadata.json#phase_runs[{index}].command_line",
                        "command_line": command_line,
                    }
                )
    return commands


def inventory_collector_output(
    *,
    collector: str,
    output_root: Path,
    target_or_profile: str | None = None,
    command_line: str | None = None,
    adapter_scope: str = "inventory_existing_tool_output_no_collection_execution",
    execution_envelope: dict[str, Any] | None = None,
    expected_artifact_families: list[str] | None = None,
) -> dict[str, Any]:
    collector = collection_tool_for_contract(collector, label="collector")
    if adapter_scope not in COLLECTOR_ADAPTER_SCOPES:
        raise ValueError(f"unsupported collector adapter_scope: {adapter_scope}")
    if not output_root.exists():
        raise FileNotFoundError(
            f"{collector} output path does not exist: {output_root}"
        )
    if not output_root.is_dir() and not output_root.is_file():
        raise ValueError(
            f"{collector} output path is not a regular file or directory: {output_root}"
        )
    declared_expected_families = (
        expected_artifact_families
        if expected_artifact_families is not None
        else expected_artifact_families_from_execution_envelope(execution_envelope)
    )
    artifacts = inventory_collector_artifacts(
        output_root,
        declared_artifacts_by_relative_path=manifest_artifact_records_by_relative_path(
            execution_envelope
        ),
    )
    diagnostic_read_errors: list[dict[str, str]] = []
    executed_commands = console_command_lines(
        output_root, read_errors=diagnostic_read_errors
    )
    replay_metadata_commands = exact_replay_metadata_command_lines(
        output_root,
        execution_envelope,
        read_errors=diagnostic_read_errors,
    )
    replay_command_sources = [*executed_commands, *replay_metadata_commands]
    top_level_commands = top_level_replay_command_lines(replay_command_sources)
    nested_commands = nested_tool_command_lines(executed_commands)
    discrepancies = command_line_discrepancies(command_line, replay_command_sources)
    requested_collection = requested_collection_from_execution_envelope(
        execution_envelope
    )
    collector_plan_declarations = expected_collection_family_evidence(
        collector=collector,
        expected_artifact_families=declared_expected_families,
        requested_collection=requested_collection,
    )
    provenance = {
        "adapter": "fmb.tool_output_adapter",
        "adapter_scope": adapter_scope,
        "expected_artifact_families": declared_expected_families,
        "collector_plan_declarations": collector_plan_declarations,
        "console_command_lines": executed_commands,
        "top_level_replay_command_lines": top_level_commands,
        "nested_tool_command_lines": nested_commands,
        "command_line_discrepancies": discrepancies,
        "exact_replay_command_available": bool(command_line)
        and bool(top_level_commands)
        and not discrepancies,
    }
    if diagnostic_read_errors:
        provenance["diagnostic_read_errors"] = diagnostic_read_errors
    if execution_envelope:
        for key in (
            "execution_environment",
            "tool_identity",
            "source_evidence",
            "tool_run_request",
            "requested_collection",
            "tool_run_result",
            "bundle_manifest",
            "bundle_validation",
        ):
            if key in execution_envelope:
                provenance[key] = execution_envelope[key]

    return {
        "collector": collector,
        "input_kind": "external_tool_output",
        "output_root": str(output_root),
        "status": "consumed",
        "target_or_profile": target_or_profile,
        "command_line": command_line,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "provenance": provenance,
    }


def parser_output_artifact(
    path: Path,
    *,
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"parser output does not exist: {path}")
    digest = sha256_file(path)
    record = {
        "artifact_record_id": f"source:{digest[:16]}",
        "relative_path": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": digest,
    }
    stamp_artifact_family_evidence(record, declarations)
    return record


def validate_source_record_references(
    observations: list[dict[str, Any]],
    *,
    raw_outputs: list[Any],
    label: str,
) -> None:
    raw_source_ids = {
        str(item["artifact_record_id"])
        for item in raw_outputs
        if isinstance(item, dict) and isinstance(item.get("artifact_record_id"), str)
    }
    for index, observation in enumerate(observations):
        source_record_ref = str(observation.get("source_record_ref") or "")
        if not source_record_ref.startswith("source:"):
            continue
        parts = source_record_ref.split(":", 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            raise ValueError(
                f"{label} observation {index} has malformed source_record_ref"
            )
        source_id = f"source:{parts[1]}"
        if source_id not in raw_source_ids:
            raise ValueError(
                f"{label} observation {index} source_record_ref does not resolve "
                "to a raw parser output"
            )


def normalize_parser_output(
    *,
    parser: str,
    parser_kind: str,
    source_collector: str,
    raw_outputs: list[Path],
    normalized_output: Path,
    observations: list[dict[str, Any]],
    source_module: str | None = None,
    command_line: str | None = None,
    tool_identity: dict[str, Any] | None = None,
    observation_families: list[str] | None = None,
    coverage_status: str = "partial",
    coverage_families: list[str] | None = None,
    coverage_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(parser, str) or not parser.strip():
        raise ValueError("parser name is required")
    if coverage_scope is not None and (
        not isinstance(coverage_scope, dict) or not isinstance(coverage_scope.get("kind"), str)
    ):
        raise ValueError("parser coverage_scope must be an object with a kind")
    if not isinstance(parser_kind, str) or not parser_kind.strip():
        raise ValueError("parser_kind is required")
    if coverage_status not in {"complete", "partial"}:
        raise ValueError("parser coverage_status must be complete or partial")
    try:
        canonical_parser = parser_tool_for_contract(parser, label="parser")
    except ValueError as error:
        raise ValueError(f"unsupported parser tool: {parser}") from error
    try:
        expected_artifact_families = artifact_families_for_parser_kind(
            parser_kind, label="parser"
        )
    except ValueError as error:
        raise ValueError(f"unsupported parser_kind: {parser_kind}") from error
    try:
        collection_tool_for_contract(source_collector, label="parser source collector")
    except ValueError as error:
        raise ValueError(
            f"unsupported parser source collector: {source_collector}"
        ) from error
    if not raw_outputs:
        raise ValueError("at least one raw parser output is required")
    declared_observation_families = declared_observation_family_list(
        observation_families,
        expected_artifact_families=expected_artifact_families,
        parser_kind=parser_kind,
        label="parser",
    )
    normalized_observations = parser_observation_records(
        observations,
        expected_artifact_families=expected_artifact_families,
        parser_kind=parser_kind,
        label_prefix="parser observation",
        start_index=1,
    )
    actual_observation_families = observation_family_list(normalized_observations)
    normalized_coverage_families = sorted(
        set(coverage_families or expected_artifact_families)
    )
    unsupported_coverage_families = sorted(
        set(normalized_coverage_families) - expected_artifact_families
    )
    if unsupported_coverage_families:
        raise ValueError(
            f"parser_kind {parser_kind} does not support coverage families: "
            + ", ".join(unsupported_coverage_families)
        )
    if not set(actual_observation_families).issubset(normalized_coverage_families):
        raise ValueError("parser observations fall outside declared coverage families")
    declared_families = actual_observation_families or sorted(
        expected_artifact_families
    )
    raw_records = [
        parser_output_artifact(
            path,
            declarations=parser_output_family_evidence(
                artifact_families=declared_families,
                source_surface=SOURCE_SURFACE_PARSER_RAW_OUTPUT,
                basis=parser_kind,
            ),
        )
        for path in raw_outputs
    ]
    validate_source_record_references(
        normalized_observations,
        raw_outputs=raw_records,
        label="parser",
    )
    normalized_record = parser_output_artifact(
        normalized_output,
        declarations=parser_output_family_evidence(
            artifact_families=declared_families,
            source_surface=SOURCE_SURFACE_PARSER_NORMALIZED_OUTPUT,
            basis=parser_kind,
        ),
    )
    normalized_record["record_count"] = len(observations)
    require_observation_families_match(
        declared_observation_families=declared_observation_families,
        actual_observation_families=actual_observation_families,
        observation_families_was_declared=observation_families is not None,
        label="parser",
    )

    return {
        "parser": canonical_parser,
        "parser_kind": parser_kind,
        "input_kind": "external_tool_parser_output",
        "source_collector": source_collector,
        "source_module": source_module,
        "status": "consumed",
        "tool_identity": tool_identity or {"name": parser, "version": None},
        "command_line": command_line,
        "input_artifacts": [],
        "raw_outputs": raw_records,
        "normalized_output": normalized_record,
        "observation_families": actual_observation_families,
        "observation_count": len(normalized_observations),
        "observations": normalized_observations,
        "coverage_status": coverage_status,
        "coverage_families": normalized_coverage_families,
        **({"coverage_scope": coverage_scope} if coverage_scope is not None else {}),
        "provenance": {
            "adapter": "fmb.parser_output_adapter",
            "adapter_scope": PARSER_ADAPTER_SCOPE,
            "truth_sources_used": [],
        },
    }


def validate_candidate_populations(
    candidate_populations: list[dict[str, Any]],
    *,
    parser_runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observation_ids = {
        str(observation["observation_id"])
        for parser_run in parser_runs
        for observation in parser_run.get("observations", [])
        if isinstance(observation, dict) and observation.get("observation_id")
    }
    population_ids: set[str] = set()
    population_scopes: set[tuple[str, str]] = set()
    validated: list[dict[str, Any]] = []
    for index, population in enumerate(candidate_populations):
        label = f"candidate population {index}"
        if not isinstance(population, dict):
            raise ValueError(f"{label} is not an object")
        for field in (
            "population_id",
            "question_id",
            "technique_id",
            "subject_type",
        ):
            if (
                not isinstance(population.get(field), str)
                or not population[field].strip()
            ):
                raise ValueError(f"{label} {field} is required")
        population_id = str(population["population_id"])
        if population_id in population_ids:
            raise ValueError(f"duplicate candidate population_id: {population_id}")
        population_ids.add(population_id)
        scope = (str(population["question_id"]), str(population["technique_id"]))
        if scope in population_scopes:
            raise ValueError(
                "duplicate candidate population for question/technique: "
                f"{scope[0]}/{scope[1]}"
            )
        population_scopes.add(scope)
        if population.get("coverage_status") not in {"complete", "partial"}:
            raise ValueError(f"{label} coverage_status must be complete or partial")
        subjects = population.get("subjects")
        if not isinstance(subjects, list):
            raise ValueError(f"{label} subjects must be a list")
        identities: set[str] = set()
        for subject_index, subject in enumerate(subjects):
            subject_label = f"{label} subject {subject_index}"
            if not isinstance(subject, dict):
                raise ValueError(f"{subject_label} is not an object")
            if (
                not isinstance(subject.get("subject_ref"), str)
                or not subject["subject_ref"].strip()
            ):
                raise ValueError(f"{subject_label} subject_ref is required")
            identity = subject.get("identity")
            if (
                not isinstance(identity, dict)
                or not identity
                or any(
                    not isinstance(key, str)
                    or not key.strip()
                    or not isinstance(value, str)
                    or not value.strip()
                    for key, value in identity.items()
                )
            ):
                raise ValueError(
                    f"{subject_label} identity must contain non-empty string pairs"
                )
            identity_key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            if identity_key in identities:
                raise ValueError(f"{label} has a duplicate subject identity")
            identities.add(identity_key)
            refs = subject.get("observation_ids")
            if (
                not isinstance(refs, list)
                or any(not isinstance(ref, str) or not ref.strip() for ref in refs)
                or len(refs) != len(set(refs))
            ):
                raise ValueError(
                    f"{subject_label} observation_ids must be unique strings"
                )
            unknown = sorted(set(refs) - observation_ids)
            if unknown:
                raise ValueError(
                    f"{subject_label} references unknown observation_id: {unknown[0]}"
                )
        validated.append(dict(population))
    return validated


def merge_embedded_candidate_populations(
    populations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for population in populations:
        if not isinstance(population, dict):
            return populations
        scope = (
            str(population.get("question_id") or ""),
            str(population.get("technique_id") or ""),
        )
        grouped.setdefault(scope, []).append(population)
    merged: list[dict[str, Any]] = []
    for scope, scoped in grouped.items():
        if len(scoped) == 1:
            merged.append(scoped[0])
            continue
        merged_subjects: dict[str, dict[str, Any]] = {}
        invalid_subjects: list[Any] = []
        for population in scoped:
            for subject in population.get("subjects", []):
                if not isinstance(subject, dict) or not isinstance(
                    subject.get("identity"), dict
                ):
                    invalid_subjects.append(subject)
                    continue
                identity_key = json.dumps(
                    subject["identity"], sort_keys=True, separators=(",", ":")
                )
                existing = merged_subjects.setdefault(identity_key, dict(subject))
                existing["observation_ids"] = sorted(
                    {
                        *existing.get("observation_ids", []),
                        *subject.get("observation_ids", []),
                    }
                )
        subjects = [*merged_subjects.values(), *invalid_subjects]
        population_ids = sorted(
            str(population.get("population_id") or "") for population in scoped
        )
        merged.append(
            {
                "population_id": (
                    "population:merged:"
                    f"{sha256_json({'population_ids': population_ids})[:24]}"
                ),
                "question_id": scope[0],
                "technique_id": scope[1],
                "subject_type": scoped[0].get("subject_type"),
                "coverage_status": (
                    "complete"
                    if all(item.get("coverage_status") == "complete" for item in scoped)
                    else "partial"
                ),
                "subjects": subjects,
            }
        )
    return merged


def assemble_evidence_index(
    *,
    run_id: str,
    question_id: str,
    question_text: str,
    collector_runs: list[dict[str, Any]],
    rule_runs: list[dict[str, Any]],
    parser_runs: list[dict[str, Any]] | None = None,
    detector_runs: list[dict[str, Any]] | None = None,
    candidate_populations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    raw_parser_runs = parser_runs or []
    embedded_populations: list[dict[str, Any]] = []
    parser_runs = []
    for parser_run in raw_parser_runs:
        if isinstance(parser_run, dict) and "candidate_populations" in parser_run:
            raw_embedded = parser_run.get("candidate_populations")
            if not isinstance(raw_embedded, list):
                raise ValueError("parser run candidate_populations must be a list")
            embedded_populations.extend(raw_embedded)
            parser_run = {
                key: value
                for key, value in parser_run.items()
                if key != "candidate_populations"
            }
        parser_runs.append(parser_run)
    detector_runs = detector_runs or []
    if not collector_runs:
        raise ValueError("at least one supported collector output is required")
    assert_run_counts_match(
        collector_runs,
        count_key="artifact_count",
        list_key="artifacts",
        label="collector run",
    )
    assert_run_counts_match(
        rule_runs,
        count_key="match_count",
        list_key="matches",
        label="rule run",
    )
    assert_run_counts_match(
        detector_runs,
        count_key="match_count",
        list_key="matches",
        label="detector run",
    )
    require_supported_tool_values(
        collector_runs,
        field="collector",
        supported_values=set(COLLECTION_TOOLS),
        label="collectors",
    )
    require_supported_tool_values(
        rule_runs,
        field="engine",
        supported_values=set(RULE_ENGINES),
        label="rule engines",
    )
    parser_runs = [
        validate_parser_run(parser_run, run_index=index)
        for index, parser_run in enumerate(parser_runs)
    ]
    explicit_populations = candidate_populations or []
    explicit_scopes = {
        (str(item.get("question_id")), str(item.get("technique_id")))
        for item in explicit_populations
        if isinstance(item, dict)
    }
    remaining_embedded = [
        item
        for item in embedded_populations
        if not isinstance(item, dict)
        or (str(item.get("question_id")), str(item.get("technique_id")))
        not in explicit_scopes
    ]
    normalized_populations = validate_candidate_populations(
        [
            *explicit_populations,
            *merge_embedded_candidate_populations(remaining_embedded),
        ],
        parser_runs=parser_runs,
    )
    incomplete = unconsumed_run_labels(
        collector_runs, rule_runs, parser_runs, detector_runs
    )
    if incomplete:
        raise ValueError(
            "evidence index contains non-consumed inputs: " + ", ".join(incomplete)
        )

    evidence_index = {
        "schema_version": EVIDENCE_INDEX_SCHEMA_VERSION,
        "run_id": run_id,
        "question": {
            "question_id": question_id,
            "question_text": question_text,
        },
        "external_inputs_allowed": False,
        "collector_runs": collector_runs,
        "rule_runs": rule_runs,
        "parser_runs": parser_runs,
        "tool_alignment": summarize_tool_alignment(
            collector_runs=collector_runs,
            rule_runs=rule_runs,
            parser_runs=parser_runs,
        ),
    }
    if detector_runs:
        evidence_index["detector_runs"] = detector_runs
    if normalized_populations:
        evidence_index["candidate_populations"] = normalized_populations
    return evidence_index
