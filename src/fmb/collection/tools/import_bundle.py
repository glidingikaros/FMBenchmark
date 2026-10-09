from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.collection.tools.envelope import validate_external_tool_bundle
from fmb.index.contract.evidence_index import inventory_collector_output, assemble_evidence_index
from fmb.index.kape.discovery import discover_kape_parser_runs
from fmb.core.json_io import write_json
from fmb.core.schemas import validate_payload

EVIDENCE_INDEX_FILENAME = "evidence_index.json"
IMPORT_REPORT_FILENAME = "evidence_index_import_report.json"


@dataclass(frozen=True)
class EvidenceIndexImportInput:
    request_path: Path
    result_path: Path
    manifest_path: Path
    output_dir: Path
    collector_output_root: Path | None = None
    require_source_hash_verified: bool = True
    bounded_content_subject_limit: int | None = None
    bounded_i30_directory_paths: tuple[str, ...] | None = ()
    parser_kinds: set[str] | None = None


def build_collector_run(
    *,
    request: dict[str, Any],
    envelope: dict[str, Any],
    collector_output_root: Path,
) -> dict[str, Any]:
    return inventory_collector_output(
        collector=str(request["collector"]),
        output_root=collector_output_root,
        target_or_profile=envelope.get("target_or_profile"),
        command_line=envelope.get("command_line"),
        adapter_scope="inventory_existing_tool_output_no_collection_execution",
        execution_envelope=envelope,
    )


def build_import_report(
    *,
    request: dict[str, Any],
    envelope: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "evidence_index_import.v1",
        "run_id": str(request["run_id"]),
        "request_id": str(request["request_id"]),
        "collector": str(request["collector"]),
        "evidence_index_status": "materialized",
        "bundle_validation": envelope["bundle_validation"],
    }


def import_tool_bundle(import_input: EvidenceIndexImportInput) -> dict[str, Any]:
    verified = validate_external_tool_bundle(
        request_path=import_input.request_path,
        result_path=import_input.result_path,
        manifest_path=import_input.manifest_path,
        collector_output_root=import_input.collector_output_root,
        require_source_hash_verified=import_input.require_source_hash_verified,
    )
    request = verified["request"]
    envelope = verified["execution_envelope"]
    collector_run = build_collector_run(
        request=request,
        envelope=envelope,
        collector_output_root=verified["collector_output_root"],
    )
    evidence_index = assemble_evidence_index(
        run_id=str(request["run_id"]),
        question_id=str(request["question"]["question_id"]),
        question_text=str(request["question"]["question_text"]),
        collector_runs=[collector_run],
        rule_runs=[],
        parser_runs=discover_kape_parser_runs(
            [collector_run],
            normalized_output_dir=import_input.output_dir / "parser-normalized",
            bounded_content_subject_limit=(import_input.bounded_content_subject_limit),
            bounded_i30_directory_paths=import_input.bounded_i30_directory_paths,
            parser_kinds=import_input.parser_kinds,
        ),
    )
    validate_payload(evidence_index, "evidence_index.schema.json")
    return {
        "evidence_index": evidence_index,
        "import_report": build_import_report(request=request, envelope=envelope),
    }


def write_import_outputs(
    output_dir: Path,
    imported: dict[str, Any],
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_index_path = output_dir / EVIDENCE_INDEX_FILENAME
    write_json(evidence_index_path, imported["evidence_index"])
    report_path = output_dir / IMPORT_REPORT_FILENAME
    write_json(report_path, imported["import_report"])
    return evidence_index_path, report_path
