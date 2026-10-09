from __future__ import annotations
from dataclasses import dataclass, field


from typing import Any, Protocol


from fmb.core.errors import ConfigurationError, ExternalToolError


from fmb.interpretation.model_catalog import expected_openrouter_upstream


from fmb.interpretation.model_catalog import validate_catalog_request


@dataclass(frozen=True)
class LLMResponse:
    provider: str
    model: str
    text: str
    raw_response: dict[str, Any]
    response_id: str | None = None
    response_model: str | None = None
    route: str | None = None
    finish_reason: str | None = None
    usage: dict[str, int | float] = field(default_factory=dict)
    latency_ms: float | None = None


@dataclass(frozen=True)
class ProviderRequest:
    provider: str
    model: str
    prompt: str
    system_prompt: str
    temperature: float | None
    max_output_tokens: int | None
    json_mode: bool
    response_schema: dict[str, Any] | None
    structured_output: str | None
    reasoning_effort: str | None
    route: str | None
    top_p: float | None = None
    seed: int | None = None


class ProviderAdapter(Protocol):
    provider: str

    def request_payload(self, request: ProviderRequest) -> dict[str, Any]: ...

    def response_text(self, raw: dict[str, Any]) -> str: ...

    def finish_reason(self, raw: dict[str, Any]) -> str | None: ...

    def normalized_usage(self, raw: dict[str, Any]) -> dict[str, int | float]: ...


def chat_messages(system_prompt: str, prompt: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]


def project_response_schema(response_schema: dict[str, Any]) -> dict[str, Any]:

    def project(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: project(item)
                for key, item in value.items()
                if key != "uniqueItems"
            }
        if isinstance(value, list):
            return [project(item) for item in value]
        return value

    return project(response_schema)


def _nonnegative_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return value


def _normalized_usage(
    raw: dict[str, Any], *, provider: str
) -> dict[str, int | float]:
    usage = raw.get("usage")
    if not isinstance(usage, dict):
        usage = {}
    if provider == "openai":
        raw_input = usage.get("input_tokens")
        raw_output = usage.get("output_tokens")
    else:
        raw_input = usage.get("prompt_tokens")
        raw_output = usage.get("completion_tokens")
    input_tokens = _nonnegative_number(raw_input)
    output_tokens = _nonnegative_number(raw_output)
    total_tokens = _nonnegative_number(usage.get("total_tokens"))
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    normalized: dict[str, int | float] = {}
    if input_tokens is not None:
        normalized["input_tokens"] = input_tokens
    if output_tokens is not None:
        normalized["output_tokens"] = output_tokens
    if total_tokens is not None:
        normalized["total_tokens"] = total_tokens
    cost = _nonnegative_number(usage.get("cost"))
    if cost is not None:
        normalized["cost_usd"] = cost
    return normalized


def _chat_finish_reason(raw: dict[str, Any]) -> str | None:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    value = choices[0].get("finish_reason")
    return value if isinstance(value, str) and value else None


def chat_response_text(raw: dict[str, Any]) -> str:
    choices = raw.get("choices", [])
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    return ""


def openai_response_text(raw: dict[str, Any]) -> str:
    output_text = raw.get("output_text")
    if isinstance(output_text, str):
        return output_text
    output = raw.get("output")
    if not isinstance(output, list):
        return ""
    parts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if (
                isinstance(part, dict)
                and part.get("type") == "output_text"
                and isinstance(part.get("text"), str)
            ):
                parts.append(part["text"])
    return "".join(parts)


class OpenAIResponsesAdapter:
    provider = "openai"

    def request_payload(self, request: ProviderRequest) -> dict[str, Any]:
        if request.response_schema is None:
            raise ConfigurationError(
                "json_schema structured output requires a response schema"
            )
        return {
            "model": request.model,
            "instructions": request.system_prompt,
            "input": request.prompt,
            "stream": False,
            "store": False,
            "truncation": "disabled",
            "reasoning": {"effort": request.reasoning_effort},
            "max_output_tokens": request.max_output_tokens,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "forensic_roster_assessment",
                    "strict": True,
                    "schema": project_response_schema(request.response_schema),
                }
            },
        }

    def response_text(self, raw: dict[str, Any]) -> str:
        return openai_response_text(raw)

    def finish_reason(self, raw: dict[str, Any]) -> str | None:
        status = raw.get("status")
        return status if isinstance(status, str) and status else None

    def normalized_usage(self, raw: dict[str, Any]) -> dict[str, int | float]:
        return _normalized_usage(raw, provider=self.provider)


class OpenRouterAdapter:
    provider = "openrouter"

    def request_payload(self, request: ProviderRequest) -> dict[str, Any]:
        if request.response_schema is None:
            raise ConfigurationError(
                "json_schema structured output requires a response schema"
            )
        return {
            "model": request.model,
            "stream": False,
            "messages": chat_messages(request.system_prompt, request.prompt),
            "max_tokens": request.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "forensic_roster_assessment",
                    "strict": True,
                    "schema": project_response_schema(request.response_schema),
                },
            },
            "reasoning": {"effort": request.reasoning_effort, "exclude": True},
            "plugins": [
                {"id": "context-compression", "enabled": False},
                {"id": "response-healing", "enabled": False},
                {"id": "web", "enabled": False},
            ],
            "provider": {
                "allow_fallbacks": False,
                "require_parameters": True,
                "order": [request.route],
                "only": [request.route],
            },
        }

    def response_text(self, raw: dict[str, Any]) -> str:
        return chat_response_text(raw)

    def finish_reason(self, raw: dict[str, Any]) -> str | None:
        return _chat_finish_reason(raw)

    def normalized_usage(self, raw: dict[str, Any]) -> dict[str, int | float]:
        return _normalized_usage(raw, provider=self.provider)


_ADAPTERS: dict[str, ProviderAdapter] = {
    "openai": OpenAIResponsesAdapter(),
    "openrouter": OpenRouterAdapter(),
}


def provider_adapter(provider: str) -> ProviderAdapter:
    try:
        return _ADAPTERS[provider]
    except KeyError as error:
        raise ConfigurationError(f"unsupported LLM provider: {provider}") from error


def provider_request_payload(
    *,
    provider: str,
    model: str,
    prompt: str,
    system_prompt: str,
    temperature: float | None,
    max_output_tokens: int | None,
    json_mode: bool,
    response_schema: dict[str, Any] | None,
    structured_output: str | None,
    reasoning_effort: str | None,
    route: str | None,
    top_p: float | None = None,
    seed: int | None = None,
) -> dict[str, Any]:

    request = ProviderRequest(
        provider=provider,
        model=model,
        prompt=prompt,
        system_prompt=system_prompt,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        json_mode=json_mode,
        response_schema=response_schema,
        structured_output=structured_output,
        reasoning_effort=reasoning_effort,
        route=route,
        top_p=top_p,
        seed=seed,
    )
    adapter = provider_adapter(provider)
    validate_catalog_request(
        provider=provider,
        model=model,
        route=route,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        json_mode=json_mode,
        structured_output=structured_output,
        reasoning_effort=reasoning_effort,
        top_p=top_p,
        seed=seed,
    )
    return adapter.request_payload(request)


def _attested_openrouter_route(
    raw: dict[str, Any], *, model: str, pinned_route: str
) -> str:

    def reject(detail: str) -> None:
        raise ExternalToolError(
            f"OpenRouter router metadata {detail}",
            details={"provider_failure_kind": "provider_error"},
        )

    metadata = raw.get("openrouter_metadata")
    if not isinstance(metadata, dict):
        reject("is missing from a pinned-route response")
    if metadata.get("requested") != model:
        reject("does not identify the requested model")
    if metadata.get("strategy") != "direct":
        reject("does not report direct routing")
    attempt = metadata.get("attempt")
    if isinstance(attempt, bool) or attempt != 1:
        reject("does not report a single successful attempt")

    endpoints = metadata.get("endpoints")
    available = endpoints.get("available") if isinstance(endpoints, dict) else None
    if not isinstance(available, list):
        reject("does not contain an endpoint roster")
    selected = [
        endpoint
        for endpoint in available
        if isinstance(endpoint, dict) and endpoint.get("selected") is True
    ]
    if len(selected) != 1:
        reject("does not identify exactly one selected endpoint")
    selected_provider = selected[0].get("provider")
    selected_model = selected[0].get("model")
    if not isinstance(selected_provider, str) or not selected_provider:
        reject("does not identify the selected provider")
    expected_provider = expected_openrouter_upstream(model, pinned_route)
    attested_provider = expected_provider or pinned_route
    if selected_provider.casefold() != attested_provider.casefold():
        reject("does not match the pinned route")
    if not isinstance(selected_model, str) or not selected_model:
        reject("does not identify the selected endpoint model")

    attempts = metadata.get("attempts")
    if attempts is not None:
        if not isinstance(attempts, list) or len(attempts) != 1:
            reject("reports an unexpected attempt history")
        recorded_attempt = attempts[0]
        if (
            not isinstance(recorded_attempt, dict)
            or recorded_attempt.get("provider") != selected_provider
            or recorded_attempt.get("model") != selected_model
            or recorded_attempt.get("status") != 200
        ):
            reject("reports an inconsistent attempt history")

    pipeline = metadata.get("pipeline", [])
    if not isinstance(pipeline, list):
        reject("contains an invalid pipeline receipt")
    if pipeline:
        reject("reports a request or response altering pipeline stage")

    raw_route = raw.get("provider")
    if raw_route is not None and (
        not isinstance(raw_route, str)
        or raw_route.casefold() != selected_provider.casefold()
    ):
        reject("conflicts with the response provider field")
    return pinned_route if expected_provider is not None else selected_provider


def _normalized_response(
    *,
    provider: str,
    model: str,
    text: str,
    raw: dict[str, Any],
    latency_ms: float,
    pinned_route: str | None = None,
) -> LLMResponse:
    raw_model = raw.get("model")
    response_model = raw_model if isinstance(raw_model, str) and raw_model else None
    if response_model is not None and response_model != model:
        raise ExternalToolError(
            f"{provider} response model does not match the requested model",
            details={"provider_failure_kind": "provider_error"},
        )
    raw_route = raw.get("provider") if provider == "openrouter" else None
    response_route = raw_route if isinstance(raw_route, str) and raw_route else None
    if provider == "openrouter" and pinned_route is not None:
        response_route = _attested_openrouter_route(
            raw,
            model=model,
            pinned_route=pinned_route,
        )
    if (
        pinned_route is not None
        and response_route is not None
        and response_route.casefold() != pinned_route.casefold()
    ):
        raise ExternalToolError(
            "OpenRouter response provider does not match the pinned route",
            details={"provider_failure_kind": "provider_error"},
        )
    response_id = raw.get("id")
    if not isinstance(response_id, str) or not response_id:
        response_id = None
    adapter = provider_adapter(provider)
    return LLMResponse(
        provider=provider,
        model=model,
        text=text,
        raw_response=raw,
        response_id=response_id,
        response_model=response_model,
        route=response_route or pinned_route,
        finish_reason=adapter.finish_reason(raw),
        usage=adapter.normalized_usage(raw),
        latency_ms=latency_ms,
    )
