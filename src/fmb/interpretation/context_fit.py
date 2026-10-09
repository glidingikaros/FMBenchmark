from __future__ import annotations
from typing import Any


from fmb.core.errors import FmbInputError


class ContextLimitError(FmbInputError):

    error_kind = "context_limit"


def _integer(name: str, value: object, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def preflight_context_fit(
    *,
    request_body: bytes,
    context_window_tokens: int,
    output_reserve_tokens: int,
    safety_reserve_tokens: int,
    exact_input_tokens: int | None = None,
) -> dict[str, Any]:

    if not isinstance(request_body, bytes):
        raise TypeError("request_body must be bytes")
    try:
        character_count = len(request_body.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("request_body must contain valid UTF-8") from error
    context_window = _integer("context_window_tokens", context_window_tokens, minimum=1)
    output_reserve = _integer("output_reserve_tokens", output_reserve_tokens, minimum=0)
    safety_reserve = _integer("safety_reserve_tokens", safety_reserve_tokens, minimum=0)
    if exact_input_tokens is None:
        input_tokens = len(request_body)
        input_token_basis = "utf8_byte_upper_bound"
        input_token_upper_bound: int | None = input_tokens
    else:
        input_tokens = _integer("exact_input_tokens", exact_input_tokens, minimum=0)
        input_token_basis = "exact"
        input_token_upper_bound = None
    required = input_tokens + output_reserve + safety_reserve
    margin = context_window - required
    return {
        "schema_version": "model_context_fit.v1",
        "request_bytes": len(request_body),
        "request_characters": character_count,
        "estimated_input_tokens": (character_count + 2) // 3,
        "exact_input_tokens": exact_input_tokens,
        "input_token_upper_bound": input_token_upper_bound,
        "input_tokens": input_tokens,
        "input_token_basis": input_token_basis,
        "context_window_tokens": context_window,
        "output_reserve_tokens": output_reserve,
        "safety_reserve_tokens": safety_reserve,
        "required_total_tokens": required,
        "margin_tokens": margin,
        "fits": margin >= 0,
    }


