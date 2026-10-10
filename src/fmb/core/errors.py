from __future__ import annotations

import json
import sys
from math import isfinite
from typing import Any, Callable

__all__ = [
    "ConfigurationError",
    "ExternalToolError",
    "FmbError",
    "FmbInputError",
    "FmbInternalError",
    "SchemaValidationError",
    "add_exception_note",
    "exception_notes",
    "print_cli_error",
    "run_cli",
]


class FmbError(RuntimeError):

    error_kind = "fmb_error"
    exit_code = 2

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "error_kind": self.error_kind,
            "error_type": type(self).__name__,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        notes = exception_notes(self)
        if notes:
            payload["notes"] = notes
        return payload


class FmbInputError(FmbError):

    error_kind = "input_error"


class FmbInternalError(FmbError):

    error_kind = "internal_error"
    exit_code = 1


class ConfigurationError(FmbInputError):

    error_kind = "configuration_error"


class ExternalToolError(FmbError):

    error_kind = "external_tool_error"


class SchemaValidationError(FmbError):

    error_kind = "schema_validation_failed"

    def __init__(
        self,
        schema_name: str,
        errors: list[str],
        *,
        max_display: int = 5,
    ) -> None:
        self.schema_name = schema_name
        self.errors = errors
        displayed = errors[:max_display]
        if len(errors) > max_display:
            remaining = len(errors) - max_display
            displayed.append(f"... {remaining} more validation error(s)")
        if not displayed:
            message = f"{schema_name} validation failed with no details"
        else:
            message = displayed[0] if len(displayed) == 1 else "; ".join(displayed)
        super().__init__(
            message,
            details={
                "schema_name": schema_name,
                "error_count": len(errors),
                "errors": errors,
            },
        )


def exception_notes(error: BaseException) -> list[str]:
    return [str(note) for note in getattr(error, "__notes__", []) or []]


def add_exception_note(error: BaseException, note: str) -> None:
    error.add_note(note)


def _copy_notes(source: BaseException, target: BaseException) -> None:
    for note in exception_notes(source):
        add_exception_note(target, note)


def _unexpected_error_details(error: BaseException) -> dict[str, str]:
    return {
        "error_type": type(error).__name__,
        "error": str(error),
    }


def _internal_error_from(
    error: BaseException,
    *,
    message: str = "unexpected internal failure",
) -> FmbInternalError:
    internal = FmbInternalError(message, details=_unexpected_error_details(error))
    _copy_notes(error, internal)
    return internal


def _sanitize_for_json(value: Any, seen: set[int] | None = None) -> Any:
    seen = set() if seen is None else seen
    if isinstance(value, float):
        return value if isfinite(value) else str(value)
    if isinstance(value, (dict, list, tuple, set)):
        if id(value) in seen:
            return "<recursive>"
        seen.add(id(value))
        try:
            if isinstance(value, dict):
                sanitized: dict[str, Any] = {}
                for key, item in value.items():
                    sanitized[str(key)] = _sanitize_for_json(item, seen)
                return sanitized
            items = sorted(value, key=repr) if isinstance(value, set) else value
            return [_sanitize_for_json(item, seen) for item in items]
        finally:
            seen.remove(id(value))
    if value is None or isinstance(value, (bool, int, str)):
        return value
    return str(value)


def _json_error_text(payload: Any, *, indent: int | None = None) -> str:
    return json.dumps(
        _sanitize_for_json(payload),
        allow_nan=False,
        indent=indent,
        sort_keys=True,
    )


def _error_payload_and_message(error: BaseException) -> tuple[dict[str, Any], str]:
    if isinstance(error, FmbError):
        return error.to_payload(), error.message

    payload: dict[str, Any] = {
        "error_kind": "unexpected_error",
        "error_type": type(error).__name__,
        "message": str(error),
    }
    notes = exception_notes(error)
    if notes:
        payload["notes"] = notes
    return payload, str(error)


def print_cli_error(
    prefix: str,
    error: BaseException,
    *,
    json_output: bool = False,
) -> None:
    payload, message = _error_payload_and_message(error)
    if json_output:
        print(_json_error_text(payload, indent=2), file=sys.stderr)
    else:
        print(f"{prefix}: {message}", file=sys.stderr)
        if isinstance(error, FmbError) and error.details:
            print(
                f"{prefix}: details: {_json_error_text(error.details)}",
                file=sys.stderr,
            )
        for note in exception_notes(error):
            print(f"{prefix}: note: {note}", file=sys.stderr)


def run_cli(
    prefix: str,
    callback: Callable[[], Any],
    *,
    json_errors: bool = False,
    internal_message: str = "unexpected internal failure",
    input_exceptions: tuple[type[BaseException], ...] = (OSError, ValueError),
) -> int:
    try:
        result = callback()
    except KeyboardInterrupt as error:
        interrupted = FmbError(f"interrupted: {error}")
        _copy_notes(error, interrupted)
        print_cli_error(prefix, interrupted, json_output=json_errors)
        return 130
    except FmbError as error:
        print_cli_error(prefix, error, json_output=json_errors)
        return error.exit_code
    except input_exceptions as error:
        input_error = FmbInputError(str(error))
        _copy_notes(error, input_error)
        print_cli_error(prefix, input_error, json_output=json_errors)
        return input_error.exit_code
    except Exception as error:
        internal = _internal_error_from(error, message=internal_message)
        print_cli_error(prefix, internal, json_output=json_errors)
        return internal.exit_code
    if isinstance(result, int):
        return result
    return 0
