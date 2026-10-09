from __future__ import annotations
from typing import Any
from fmb.core.case_contract import SYSTEM_PROMPT
from fmb.core.paper_protocol import DEFAULT_CONTEXT_WINDOW_TOKENS, SAFETY_RESERVE_TOKENS
from fmb.interpretation.provider import provider_request_body


def _provider_payload_kwargs(call_kwargs: dict[str, Any]) -> dict[str, Any]:
    payload_keys = {
        "json_mode",
        "max_output_tokens",
        "model",
        "prompt",
        "provider",
        "reasoning_effort",
        "seed",
        "response_schema",
        "route",
        "structured_output",
        "system_prompt",
        "temperature",
        "top_p",
    }
    request_kwargs = {
        key: value for key, value in call_kwargs.items() if key in payload_keys
    }
    request_kwargs.setdefault("reasoning_effort", None)
    request_kwargs.setdefault("route", None)
    request_kwargs.setdefault("structured_output", None)
    return request_kwargs


def wire(kwargs):
    return provider_request_body(**_provider_payload_kwargs(kwargs))


def request_kwargs(case_text: str, schema: dict, settings: dict) -> dict:
    for name in (
        "provider",
        "model",
        "reasoning_effort",
        "max_output_tokens",
        "timeout_seconds",
    ):
        if name not in settings:
            raise ValueError("missing explicit condition setting: " + name)
    kwargs = {
        "provider": settings["provider"],
        "model": settings["model"],
        "prompt": case_text,
        "system_prompt": SYSTEM_PROMPT,
        "temperature": settings.get("temperature"),
        "response_schema": schema,
        "json_mode": True,
        "structured_output": settings.get("structured_output", "json_schema"),
        "timeout_seconds": settings["timeout_seconds"],
        "max_output_tokens": settings["max_output_tokens"],
        "reasoning_effort": settings["reasoning_effort"],
        "base_url": settings.get("base_url"),
        "context_window_tokens": settings.get("context_window_tokens", DEFAULT_CONTEXT_WINDOW_TOKENS),
        "safety_reserve_tokens": SAFETY_RESERVE_TOKENS,
    }
    if settings.get("route"):
        kwargs["route"] = settings["route"]
    kwargs.update({key: settings[key] for key in ("top_p", "seed") if key in settings})
    return kwargs
