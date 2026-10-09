from __future__ import annotations

from typing import Any

from fmb.core.hashing import sha256_text

SOURCE_SURFACE_KAPE_MODULE_OUTPUT = "kape_module_output"
SOURCE_SURFACE_PARSER_RAW_OUTPUT = "parser_raw_output"
SOURCE_SURFACE_PARSER_NORMALIZED_OUTPUT = "parser_normalized_output"
SOURCE_SURFACE_TOOL_LOG = "tool_log"
SOURCE_SURFACE_COLLECTOR_OUTPUT = "collector_output"
SOURCE_SURFACE_COLLECTOR_PLAN = "collector_plan"

COVERAGE_ROLE_DIRECT = "direct"
COVERAGE_ROLE_SUPPORTING_SOURCE = "supporting_source"

GENERIC_ARTIFACT_FAMILY = "collection.artifact"
TOOL_LOG_ARTIFACT_FAMILY = "tool.log"

SUPPORTING_SOURCE_SURFACES = frozenset(
    {
        SOURCE_SURFACE_KAPE_MODULE_OUTPUT,
        SOURCE_SURFACE_PARSER_RAW_OUTPUT,
        SOURCE_SURFACE_PARSER_NORMALIZED_OUTPUT,
        SOURCE_SURFACE_TOOL_LOG,
    }
)


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def family_coverage_role(source_surface: str) -> str:
    if source_surface in SUPPORTING_SOURCE_SURFACES:
        return COVERAGE_ROLE_SUPPORTING_SOURCE
    return COVERAGE_ROLE_DIRECT


def default_families_for_surface(
    *,
    source_surface: str,
) -> list[str]:
    if source_surface == SOURCE_SURFACE_TOOL_LOG:
        return [TOOL_LOG_ARTIFACT_FAMILY]
    return [GENERIC_ARTIFACT_FAMILY]


def sanitize_families(values: list[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        if isinstance(value, str) and value:
            _append_unique(result, value)
    return result


def _family_from_declaration(
    declaration: dict[str, Any],
    *,
    required: bool = False,
) -> str | None:
    family = declaration.get("artifact_family")
    if isinstance(family, str) and family:
        return family
    if required:
        raise ValueError("artifact declaration is missing artifact_family")
    return None


def _families_from_declarations(
    declarations: list[Any],
    *,
    required: bool = False,
) -> list[str]:
    families: list[str] = []
    for declaration in declarations:
        if not isinstance(declaration, dict):
            if required:
                raise ValueError("artifact declaration is not an object")
            continue
        family = _family_from_declaration(declaration, required=required)
        if family is not None:
            _append_unique(families, family)
    return families


def _families_from_existing_record(record: dict[str, Any]) -> list[str]:
    families = sanitize_families(record.get("artifact_families"))
    if families:
        return families

    declarations = record.get("artifact_family_declarations", [])
    if not isinstance(declarations, list):
        return []
    return _families_from_declarations(declarations)


def source_artifact_id(record: dict[str, Any]) -> str:
    families = _families_from_existing_record(record)
    serialized = (
        f"relative_path={record.get('relative_path')}\n"
        f"size_bytes={record.get('size_bytes')}\n"
        f"sha256={record.get('sha256')}\n"
        f"families={','.join(families)}"
    )
    return f"source-artifact:{sha256_text(serialized)[:24]}"


def family_declaration(
    *,
    artifact_family: str,
    source_surface: str,
    coverage_role: str,
    method: str,
    source_field: str,
    basis: str,
    request_expected: bool = False,
) -> dict[str, Any]:
    record = {
        "artifact_family": artifact_family,
        "source_surface": source_surface,
        "coverage_role": coverage_role,
        "method": method,
        "source_field": source_field,
        "basis": basis,
    }
    if request_expected:
        record["request_expected"] = True
    return record


def _family_declarations(
    *,
    artifact_families: list[str],
    source_surface: str,
    coverage_role: str,
    method: str,
    source_field: str,
    basis: str,
    request_expected: bool = False,
) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for family in artifact_families:
        declarations.append(
            family_declaration(
                artifact_family=family,
                source_surface=source_surface,
                coverage_role=coverage_role,
                method=method,
                source_field=source_field,
                basis=basis,
                request_expected=request_expected,
            )
        )
    return declarations


def collected_artifact_family_evidence(
    *,
    artifact_families: list[str] | None = None,
    source_surface: str = SOURCE_SURFACE_COLLECTOR_OUTPUT,
    source_field: str = "collector_manifest.artifacts[].artifact_families",
    basis: str | None = None,
) -> list[dict[str, Any]]:
    coverage_role = family_coverage_role(source_surface)
    families = sanitize_families(artifact_families) or default_families_for_surface(
        source_surface=source_surface,
    )
    return _family_declarations(
        artifact_families=families,
        source_surface=source_surface,
        coverage_role=coverage_role,
        method="collector_source_declaration",
        source_field=source_field,
        basis=basis or "producer_declared_collector_artifact",
    )


def collection_plan_basis(
    *,
    collector: str,
    requested_collection: dict[str, Any] | None = None,
) -> str:
    if not isinstance(requested_collection, dict):
        return f"collector={collector}"
    parts = [f"collector={requested_collection.get('collector') or collector}"]
    for field in ("targets", "modules", "profile"):
        value = requested_collection.get(field)
        if isinstance(value, str) and value:
            parts.append(f"{field}={value}")
    return " ".join(parts)


def expected_collection_family_evidence(
    *,
    collector: str,
    expected_artifact_families: list[str] | None,
    requested_collection: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    basis = collection_plan_basis(
        collector=collector,
        requested_collection=requested_collection,
    )
    return _family_declarations(
        artifact_families=sanitize_families(expected_artifact_families),
        source_surface=SOURCE_SURFACE_COLLECTOR_PLAN,
        coverage_role=COVERAGE_ROLE_DIRECT,
        method="collector_plan_declaration",
        source_field="requested_collection.expected_artifact_families",
        basis=basis,
        request_expected=True,
    )


def parser_output_family_evidence(
    *,
    artifact_families: list[str],
    source_surface: str,
    basis: str,
) -> list[dict[str, Any]]:
    coverage_role = family_coverage_role(source_surface)
    return _family_declarations(
        artifact_families=sanitize_families(artifact_families),
        source_surface=source_surface,
        coverage_role=coverage_role,
        method="parser_output_declaration",
        source_field="parser_kind",
        basis=basis,
    )


def _families_from_required_declarations(
    declarations: list[dict[str, Any]],
) -> list[str]:
    if not declarations:
        raise ValueError("artifact declaration list must not be empty")
    return _families_from_declarations(declarations, required=True)


def _artifact_family_evidence_fields(
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    families = _families_from_required_declarations(declarations)
    return {
        "artifact_family": families[0],
        "artifact_families": families,
        "artifact_family_declarations": declarations,
    }


def stamp_artifact_family_evidence(
    record: dict[str, Any],
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    record.update(_artifact_family_evidence_fields(declarations))
    record["artifact_id"] = source_artifact_id(record)
    return record


__all__ = [
    "GENERIC_ARTIFACT_FAMILY",
    "SOURCE_SURFACE_COLLECTOR_PLAN",
    "SOURCE_SURFACE_KAPE_MODULE_OUTPUT",
    "SOURCE_SURFACE_PARSER_NORMALIZED_OUTPUT",
    "SOURCE_SURFACE_PARSER_RAW_OUTPUT",
    "SOURCE_SURFACE_TOOL_LOG",
    "collected_artifact_family_evidence",
    "expected_collection_family_evidence",
    "parser_output_family_evidence",
    "source_artifact_id",
    "stamp_artifact_family_evidence",
]
