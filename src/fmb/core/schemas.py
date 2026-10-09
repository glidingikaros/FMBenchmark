from __future__ import annotations
import re


from collections.abc import Iterable


from datetime import datetime


from functools import lru_cache


from typing import Any


from jsonschema import Draft202012Validator, FormatChecker


from jsonschema.exceptions import ValidationError


from referencing import Registry, Resource


from referencing.jsonschema import DRAFT202012


from fmb.core.errors import SchemaValidationError


from fmb.core.json_io import load_json


from fmb.core.paths import load_schema_payload, schema_paths


RFC3339_DATE_TIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


def is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    text = value
    if not RFC3339_DATE_TIME_PATTERN.fullmatch(text):
        return False
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = text.replace("t", "T", 1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    return parsed.tzinfo is not None


_FORMAT_CHECKER = FormatChecker()
_FORMAT_CHECKER.checks("date-time")(is_rfc3339_date_time)


@lru_cache(maxsize=1)
def _schema_ref_registry() -> Registry:
    resources = []
    for path in schema_paths():
        payload = load_json(path)
        schema_id = payload.get("$id")
        if isinstance(schema_id, str) and schema_id:
            resources.append(
                (
                    schema_id,
                    Resource.from_contents(
                        payload,
                        default_specification=DRAFT202012,
                    ),
                )
            )
    return Registry().with_resources(resources)


def _validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(
        schema,
        format_checker=_FORMAT_CHECKER,
        registry=_schema_ref_registry(),
    )


def _validation_error_location(error: ValidationError) -> str:
    return ".".join(str(part) for part in error.path) or "<root>"


def _validation_error_sort_key(error: ValidationError) -> tuple[str, ...]:
    return tuple(str(part) for part in error.path)


def _validation_error_messages(
    errors: Iterable[ValidationError],
    *,
    label: str,
) -> list[str]:
    return [
        (
            f"{label} validation failed at "
            f"{_validation_error_location(error)}: {error.message}"
        )
        for error in sorted(errors, key=_validation_error_sort_key)
    ]


def schema_validation_errors(payload: Any, schema_name: str) -> list[str]:
    validator = _validator(load_schema_payload(schema_name))
    errors = _validation_error_messages(
        validator.iter_errors(payload), label=schema_name
    )
    return errors


def validate_payload(payload: Any, schema_name: str) -> None:
    errors = schema_validation_errors(payload, schema_name)
    if errors:
        raise SchemaValidationError(schema_name, errors)


@lru_cache(maxsize=512)
def _response_validator(schema_json: str):
    import json
    from jsonschema.validators import validator_for

    schema = json.loads(schema_json)
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def validate_response_schema(instance, schema):
    from jsonschema.exceptions import best_match
    from fmb.core.sealed_records import canonical_json

    error = best_match(_response_validator(canonical_json(schema)).iter_errors(instance))
    if error is not None:
        raise error
