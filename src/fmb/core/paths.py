from __future__ import annotations

from pathlib import Path

from fmb.core.json_io import load_json
from fmb.core.schema_registry import (
    schema_contract_ref,
    schema_contract_refs,
    split_schema_contract_ref,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR_NAME = ".fmb"
RUNS_DIR_NAME = "outputs"


def default_current_root() -> Path:
    return Path.cwd() / RUNTIME_DIR_NAME


def _schema_ref_parts(schema_name: str) -> tuple[str, str | None]:
    try:
        ref = schema_contract_ref(schema_name)
    except KeyError as error:
        raise FileNotFoundError(f"schema is not registered: {schema_name}") from error
    return split_schema_contract_ref(ref)


def _schema_document_path(schema_name: str, relative_path: str) -> Path:
    path = PROJECT_ROOT / relative_path
    if not path.is_file():
        raise FileNotFoundError(
            f"registered schema is missing: {schema_name} -> {path}"
        )
    return path


def schema_path(schema_name: str) -> Path:
    relative_path, _definition = _schema_ref_parts(schema_name)
    return _schema_document_path(schema_name, relative_path)


def schema_paths() -> tuple[Path, ...]:
    result: list[Path] = []
    seen: set[Path] = set()
    for ref in schema_contract_refs():
        relative_path, _definition = split_schema_contract_ref(ref)
        path = PROJECT_ROOT / relative_path
        if path in seen:
            continue
        seen.add(path)
        result.append(path)
    return tuple(result)


def load_schema_payload(schema_name: str) -> dict:
    relative_path, definition = _schema_ref_parts(schema_name)
    schema = load_json(_schema_document_path(schema_name, relative_path))
    if definition is None:
        return schema
    schema_id = schema.get("$id")
    if not isinstance(schema_id, str) or not schema_id:
        raise ValueError(f"schema has no $id: {schema_name}")
    return {
        "$schema": schema.get(
            "$schema",
            "https://json-schema.org/draft/2020-12/schema",
        ),
        "$ref": f"{schema_id}#/$defs/{definition}",
    }


def load_schema_definition_payload(schema_name: str, definition_name: str) -> dict:
    schema = load_json(schema_path(schema_name))
    definitions = schema.get("$defs", {})
    if definition_name not in definitions:
        raise KeyError(f"{schema_name} does not define $defs/{definition_name}")
    return {
        "$schema": schema.get(
            "$schema",
            "https://json-schema.org/draft/2020-12/schema",
        ),
        "$ref": f"#/$defs/{definition_name}",
        "$defs": definitions,
    }
