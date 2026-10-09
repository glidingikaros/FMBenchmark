from __future__ import annotations

import heapq
import json
from pathlib import Path
from typing import Any

from fmb.core.hashing import (
    sha256_file,
    sha256_text,
)
from fmb.core.json_io import write_json
from fmb.index.contract.evidence_index import (
    COVERAGE_STATUS_UNAVAILABLE,
    PARSER_RUN_STATUS_CONSUMED_EMPTY,
    normalize_parser_output,
)
from fmb.index.support.windows_artifacts import safe_path_component

HOST_COLLECTOR_METADATA_FILE = "host_collector_metadata.json"

HOST_PROCESSOR_STATUS_COMPLETED_EMPTY_OUTPUT = "completed_empty_output"

ParserRunAdapterResult = dict[str, Any] | list[dict[str, Any]]

RankedObservation = tuple[int, int, dict[str, Any]]


def observed_artifact_families(observations: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(observation["artifact_family"])
            for observation in observations
            if isinstance(observation.get("artifact_family"), str)
            and observation["artifact_family"]
        }
    )


def keep_ranked_observation(
    candidates: list[RankedObservation],
    *,
    score: int,
    row_index: int,
    observation: dict[str, Any],
    limit: int,
) -> None:
    ranked = (score, row_index, observation)
    if len(candidates) < limit:
        heapq.heappush(candidates, ranked)
    elif ranked[:2] > candidates[0][:2]:
        heapq.heapreplace(candidates, ranked)


def ranked_observations(candidates: list[RankedObservation]) -> list[dict[str, Any]]:
    return [
        observation
        for _score, _row_index, observation in sorted(
            candidates,
            key=lambda item: (item[0], item[1]),
            reverse=True,
        )
    ]


def source_scope_id(source_path: Path) -> str:
    return sha256_file(source_path.expanduser())[:16]


def source_bound_observations(
    observations: list[dict[str, Any]],
    source_path: Path,
    *,
    source_id: str | None = None,
) -> list[dict[str, Any]]:

    source_id = source_id or source_scope_id(source_path)
    scoped: list[dict[str, Any]] = []
    for observation in observations:
        observation_id = str(observation["observation_id"])
        source_record_ref = str(observation["source_record_ref"])
        if ":source:" not in observation_id:
            observation_id = f"{observation_id}:source:{source_id}"
        if not source_record_ref.startswith("source:"):
            source_record_ref = f"source:{source_id}:{source_record_ref}"
        scoped.append(
            {
                **observation,
                "observation_id": observation_id,
                "source_record_ref": source_record_ref,
            }
        )
    return scoped


def normalized_output_path(
    normalized_output_dir: Path,
    source_path: Path,
    suffix: str,
) -> Path:
    path_hash = (
        sha256_text(str(source_path.resolve()))[:12]
        if source_path.exists()
        else sha256_text(str(source_path))[:12]
    )
    return normalized_output_dir / (
        f"{safe_path_component(source_path.parent.name)}."
        f"{safe_path_component(source_path.stem)}."
        f"{path_hash}."
        f"{suffix}"
    )


def collector_artifact_identity_index(
    collector_run: dict[str, Any],
) -> dict[str, tuple[int | None, str | None]]:
    index: dict[str, tuple[int | None, str | None]] = {}
    for artifact in collector_run.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            continue
        try:
            key = str(Path(path).expanduser().resolve())
        except OSError:
            key = str(Path(path).expanduser())
        size_value = artifact.get("size_bytes")
        size = int(size_value) if isinstance(size_value, int) else None
        sha256 = artifact.get("sha256")
        index[key] = (size, sha256 if isinstance(sha256, str) and sha256 else None)
    return index


def dedupe_exact_parser_outputs(
    paths: list[Path],
    artifact_index: dict[str, tuple[int | None, str | None]],
) -> list[Path]:
    seen: set[tuple[str, int | None, str | None]] = set()
    unique_paths: list[Path] = []
    for path in paths:
        try:
            path_key = str(path.expanduser().resolve())
        except OSError:
            path_key = str(path.expanduser())
        size, sha256 = artifact_index.get(path_key, (None, None))
        key = ("sha256", size, sha256) if sha256 else ("path", None, path_key)
        if key in seen:
            continue
        seen.add(key)
        unique_paths.append(path)
    return unique_paths


def module_command_line(collector_run: dict[str, Any], *needles: str) -> str | None:
    folded_needles = tuple(needle.casefold() for needle in needles)
    provenance = collector_run.get("provenance", {})
    if not isinstance(provenance, dict):
        return None
    commands: list[dict[str, Any]] = []
    for key in (
        "nested_tool_command_lines",
        "console_command_lines",
        "top_level_replay_command_lines",
    ):
        value = provenance.get(key, [])
        if isinstance(value, list):
            commands.extend(item for item in value if isinstance(item, dict))
    for command in commands:
        command_line = str(command.get("command_line", ""))
        folded = command_line.casefold()
        if all(needle in folded for needle in folded_needles):
            return command_line
    return None


def host_processor_runs(collector_run: dict[str, Any]) -> list[dict[str, Any]]:
    root = collector_output_root(collector_run)
    if root is None:
        return []
    metadata_path = root.parent / HOST_COLLECTOR_METADATA_FILE
    if not metadata_path.is_file():
        return []
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    runs = payload.get("module_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        return []
    return [run for run in runs if isinstance(run, dict)]


def host_processor_run_for_output(
    collector_run: dict[str, Any], raw_output: Path
) -> dict[str, Any] | None:
    root = collector_output_root(collector_run)
    if root is None:
        return None
    try:
        relative = raw_output.expanduser().resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None
    for run in host_processor_runs(collector_run):
        outputs = run.get("outputs")
        if isinstance(outputs, list) and relative in {str(item) for item in outputs}:
            return run
    return None


def apply_host_processor_status(
    parser_run: dict[str, Any], collector_run: dict[str, Any]
) -> dict[str, Any]:
    for record in parser_run.get("raw_outputs") or []:
        path = record.get("path") if isinstance(record, dict) else None
        if not isinstance(path, str) or not path:
            continue
        processor = host_processor_run_for_output(collector_run, Path(path))
        if processor is None:
            continue
        if processor.get("status") != HOST_PROCESSOR_STATUS_COMPLETED_EMPTY_OUTPUT:
            return parser_run
        parser_run["status"] = PARSER_RUN_STATUS_CONSUMED_EMPTY
        parser_run["coverage_status"] = COVERAGE_STATUS_UNAVAILABLE
        parser_run.pop("coverage_scope", None)
        for population in parser_run.get("candidate_populations") or []:
            if isinstance(population, dict):
                population["coverage_status"] = "partial"
        provenance = parser_run.setdefault("provenance", {})
        provenance["host_processor_run"] = {
            "module": str(processor.get("module")),
            "tool": processor.get("tool"),
            "status": HOST_PROCESSOR_STATUS_COMPLETED_EMPTY_OUTPUT,
            "exit_code": processor.get("exit_code"),
            "input_file_count": processor.get("input_file_count"),
            "input_byte_count": processor.get("input_byte_count"),
            "data_row_count": processor.get("data_row_count"),
            "outputs": [str(item) for item in (processor.get("outputs") or [])],
            "detail": processor.get("detail"),
        }
        return parser_run
    return parser_run


def write_observation_index(
    *,
    normalized_output_dir: Path,
    raw_output: Path,
    file_suffix: str,
    parser: str,
    parser_kind: str,
    observations: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> Path:
    normalized_output = normalized_output_path(
        normalized_output_dir,
        raw_output,
        file_suffix,
    )
    write_json(
        normalized_output,
        {
            "schema_version": "parser_observation_index.v1",
            "parser": parser,
            "parser_kind": parser_kind,
            "source": str(raw_output),
            **(extra or {}),
            "record_count": len(observations),
            "observations": observations,
            "truth_sources_used": [],
        },
    )
    return normalized_output


def parser_run_from_observations(
    *,
    parser: str,
    parser_kind: str,
    source_module: str,
    command_needles: tuple[str, ...],
    normalized_suffix: str,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    raw_output: Path,
    observations: list[dict[str, Any]],
    index_extra: dict[str, Any] | None = None,
    coverage_status: str = "complete",
    coverage_families: list[str] | None = None,
    additional_raw_outputs: list[Path] | None = None,
    coverage_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observations = source_bound_observations(observations, raw_output)
    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=raw_output,
        file_suffix=f"{normalized_suffix}.observations.json",
        parser=parser,
        parser_kind=parser_kind,
        observations=observations,
        extra=index_extra,
    )
    return normalize_parser_output(
        parser=parser,
        parser_kind=parser_kind,
        source_collector=str(collector_run["collector"]),
        source_module=source_module,
        raw_outputs=list(dict.fromkeys([raw_output, *(additional_raw_outputs or [])])),
        normalized_output=normalized_output,
        observations=observations,
        command_line=module_command_line(collector_run, *command_needles),
        tool_identity={"name": parser, "version": None, "source": "KAPE module output"},
        observation_families=observed_artifact_families(observations),
        coverage_status=coverage_status,
        coverage_families=coverage_families,
        coverage_scope=coverage_scope,
    )


def collector_output_root(collector_run: dict[str, Any]) -> Path | None:
    root = collector_run.get("output_root")
    if not isinstance(root, str) or not root:
        return None
    path = Path(root).expanduser()
    return path if path.is_dir() else None
