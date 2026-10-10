from __future__ import annotations
import pytest


from fmb.core import paths


def test_schema_helpers_find_unique_schema_and_definition() -> None:
    schema = paths.load_schema_payload("shared_factual_evidence.schema.json")

    assert schema["$schema"].startswith("https://json-schema.org/")
    assert paths.schema_path("shared_factual_evidence.schema.json").name == "shared_factual_evidence.schema.json"
    with pytest.raises(FileNotFoundError):
        paths.schema_path("definitely_missing.schema.json")
    with pytest.raises(KeyError):
        paths.load_schema_definition_payload(
            "shared_factual_evidence.schema.json", "definitely_missing"
        )


def test_schema_registry_paths_exist() -> None:
    schema_paths = paths.schema_paths()

    assert schema_paths
    assert all(path.is_file() for path in schema_paths)


