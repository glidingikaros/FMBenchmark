from __future__ import annotations
import errno
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from time import perf_counter
from typing import Any

from fmb.core.errors import ConfigurationError, ExternalToolError
from fmb.core.sealed_records import canonical_json, parse_json
from fmb.interpretation.context_fit import ContextLimitError, preflight_context_fit
from fmb.interpretation.provider_adapters import LLMResponse, _chat_finish_reason, _normalized_response, _normalized_usage, provider_adapter, provider_request_payload


PROVIDER_ENDPOINTS = {
    "openai": {"env": "OPENAI", "label": "OpenAI", "host": "api.openai.com",
               "base_url": "https://api.openai.com/v1", "path": "/responses", "headers": {}},
    "openrouter": {"env": "OPENROUTER", "label": "OpenRouter", "host": "openrouter.ai",
                   "base_url": "https://openrouter.ai/api/v1", "path": "/chat/completions",
                   "headers": {"X-OpenRouter-Cache": "false", "X-OpenRouter-Metadata": "enabled"}},
}


MAX_PROVIDER_ERROR_DETAIL_CHARS = 500


CONTEXT_LIMIT_HTTP_STATUSES = {400, 413, 422}


CONTEXT_LIMIT_MARKERS = (
    "context length",
    "context window",
    "maximum context",
    "max context",
    "prompt is too long",
    "too many tokens",
)


def is_retryable_http_status(status) -> bool:
    return isinstance(status, int) and not isinstance(status, bool) and (status in {408, 429} or 500 <= status <= 599)


BILLING_ERROR_MARKERS = (
    "billing",
    "credit balance",
    "credits exhausted",
    "exceeded your current quota",
    "insufficient credits",
    "insufficient funds",
    "insufficient_quota",
    "payment_required",
    "quota exceeded",
    "payment required",
)


NONRETRYABLE_PROVIDER_MARKERS = (
    *BILLING_ERROR_MARKERS,
    "invalid api key",
    "invalid_api_key",
    "no endpoints found that can handle requested parameters",
)


NONRETRYABLE_EMPTY_CONTENT_FINISH_REASONS = {
    "cancelled",
    "content_filter",
    "failed",
    "incomplete",
    "length",
    "max_output_tokens",
    "max_tokens",
}


TRANSIENT_PROVIDER_MARKERS = (
    "engine_overloaded",
    "overloaded",
    "rate limit",
    "temporarily unavailable",
    "temporary unavailable",
    "timed out",
    "timeout",
    "try again",
)


TRANSIENT_SOCKET_ERRNOS = frozenset(
    getattr(errno, name)
    for name in (
        "ECONNABORTED",
        "ECONNREFUSED",
        "ECONNRESET",
        "EHOSTDOWN",
        "EHOSTUNREACH",
        "ENETDOWN",
        "ENETRESET",
        "ENETUNREACH",
        "EPIPE",
        "ETIMEDOUT",
    )
    if hasattr(errno, name)
)


TRANSIENT_TLS_MARKERS = (
    "bad record mac",
    "eof occurred in violation of protocol",
    "unexpected eof while reading",
)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def display_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme and parsed.netloc:
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, "", "")
        )
    return url.split("?", 1)[0]


def truncate_detail(value: str, *, limit: int = MAX_PROVIDER_ERROR_DETAIL_CHARS) -> str:
    text = value.replace("\x00", "\\0")
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def parse_json_object_response(body: str, url: str) -> dict[str, Any]:
    try:
        parsed = parse_json(body)
    except ValueError as error:
        raise ExternalToolError(
            f"LLM provider returned non-JSON from {display_url(url)}: {truncate_detail(body)}"
        ) from error
    if not isinstance(parsed, dict):
        raise ExternalToolError(
            f"LLM provider returned non-object JSON from {display_url(url)}"
        )
    return parsed


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload).encode()


def _is_loopback(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_provider_target(url: str, headers: dict[str, str] | None) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError("LLM provider URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("LLM provider URL must not contain credentials")
    for name, value in (headers or {}).items():
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise ConfigurationError("LLM provider headers must not contain newlines")
    authenticated = any(name.casefold() == "authorization" for name in (headers or {}))
    if authenticated and parsed.scheme.casefold() != "https":
        raise ConfigurationError("LLM provider credentials require HTTPS")
    if parsed.scheme.casefold() == "http" and not _is_loopback(parsed.hostname):
        raise ConfigurationError(
            "plain HTTP LLM endpoints are permitted only on loopback"
        )


def _open_provider_request(
    request: urllib.request.Request, timeout_seconds: int
) -> Any:
    return urllib.request.build_opener(_RejectRedirects()).open(
        request, timeout=timeout_seconds
    )


def _provider_error_code(detail: str) -> int | str | None:
    try:
        payload = json.loads(detail)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    if isinstance(code, bool) or not isinstance(code, (int, str)):
        return None
    return code


def _retry_after_seconds(headers: Any) -> float | None:
    if headers is None:
        return None
    raw = headers.get("Retry-After")
    if not isinstance(raw, str) or not raw.strip():
        return None
    value = raw.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, seconds)


def _http_failure_details(
    *,
    status: int,
    detail: str,
    raw_body: bytes,
    headers: Any,
) -> dict[str, Any]:
    folded = detail.casefold()
    code = _provider_error_code(detail)
    billing_error = status == 402 or any(
        marker in folded for marker in BILLING_ERROR_MARKERS
    )
    failure_kind = (
        "context_limit"
        if status in CONTEXT_LIMIT_HTTP_STATUSES
        and any(marker in folded for marker in CONTEXT_LIMIT_MARKERS)
        else "billing_error"
        if billing_error
        else "provider_error"
    )
    retryable = (
        failure_kind == "provider_error"
        and is_retryable_http_status(status)
        and not any(marker in folded for marker in NONRETRYABLE_PROVIDER_MARKERS)
    )
    result: dict[str, Any] = {
        "provider_failure_kind": failure_kind,
        "provider_failure_stage": "http",
        "http_status": status,
        "provider_response_body": detail,
        "provider_response_sha256": hashlib.sha256(raw_body).hexdigest(),
    }
    if code is not None:
        result["provider_error_code"] = code
    result["retryable"] = retryable
    retry_after = _retry_after_seconds(headers)
    if retry_after is not None:
        result["retry_after_seconds"] = retry_after
    return result


def _missing_content_error(
    provider_name: str, raw: dict[str, Any]
) -> ExternalToolError:
    raw_bytes = _json_bytes(raw)
    error = raw.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    provider_code = (
        code if isinstance(code, (int, str)) and not isinstance(code, bool) else None
    )
    finish_reason = _chat_finish_reason(raw)
    error_message = error.get("message") if isinstance(error, dict) else None
    explicit_error_text = " ".join(
        str(value)
        for value in (provider_code, error_message)
        if isinstance(value, (int, str)) and not isinstance(value, bool)
    ).casefold()
    billing_error = isinstance(error, dict) and any(
        marker in explicit_error_text for marker in BILLING_ERROR_MARKERS
    )
    permanent_marker = billing_error or any(
        marker in explicit_error_text for marker in NONRETRYABLE_PROVIDER_MARKERS
    )
    nonterminal = (
        isinstance(finish_reason, str)
        and finish_reason.casefold() in NONRETRYABLE_EMPTY_CONTENT_FINISH_REASONS
    )
    numeric_code = provider_code if isinstance(provider_code, int) else None
    if isinstance(provider_code, str) and provider_code.isdecimal():
        numeric_code = int(provider_code)
    positively_transient = isinstance(error, dict) and (
        is_retryable_http_status(numeric_code)
        or any(marker in explicit_error_text for marker in TRANSIENT_PROVIDER_MARKERS)
    )
    retryable = False if permanent_marker or nonterminal else positively_transient
    details: dict[str, Any] = {
        "provider_failure_kind": (
            "billing_error" if billing_error else "provider_error"
        ),
        "provider_failure_stage": "response_shape",
        "retryable": retryable,
        "provider_response": raw,
        "provider_response_sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    if provider_code is not None:
        details["provider_error_code"] = provider_code
    if finish_reason is not None:
        details["finish_reason"] = finish_reason
    usage = _normalized_usage(raw, provider="openrouter")
    if not retryable and "input_tokens" in usage and "output_tokens" in usage:
        details["usage"] = usage
    return ExternalToolError(
        f"{provider_name} response did not include choices[0].message.content",
        details=details,
    )


def _retryable_transport_cause(cause: Any) -> bool:
    if isinstance(
        cause,
        (PermissionError, ssl.CertificateError, ssl.SSLCertVerificationError),
    ):
        return False
    if isinstance(cause, ssl.SSLError):
        if isinstance(
            cause,
            (
                ssl.SSLEOFError,
                ssl.SSLWantReadError,
                ssl.SSLWantWriteError,
                ssl.SSLZeroReturnError,
            ),
        ):
            return True
        folded = str(cause).casefold()
        return any(marker in folded for marker in TRANSIENT_TLS_MARKERS)
    if isinstance(cause, TimeoutError):
        return True
    if isinstance(cause, http.client.IncompleteRead):
        return True
    if isinstance(cause, socket.gaierror):
        return cause.errno == socket.EAI_AGAIN
    if isinstance(cause, ConnectionError):
        return True
    return isinstance(cause, OSError) and cause.errno in TRANSIENT_SOCKET_ERRNOS


def _transport_failure_details(error: BaseException) -> dict[str, Any]:
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    return {
        "provider_failure_kind": "transport_error",
        "provider_failure_stage": "transport",
        "transport_error_type": type(cause).__name__,
        "retryable": _retryable_transport_cause(cause),
    }


def post_json(
    url: str,
    payload: dict[str, Any],
    timeout_seconds: int,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    data = _json_bytes(payload)
    _validate_provider_target(url, headers)
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": str(len(data)),
            "User-Agent": "fmb/0.1",
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with _open_provider_request(request, timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        try:
            raw_body = error.read()
        except http.client.IncompleteRead as cut:
            raw_body = cut.partial
        detail = raw_body.decode("utf-8", errors="replace")
        raise ExternalToolError(
            f"LLM provider HTTP {error.code} from {display_url(url)}: {truncate_detail(detail)}",
            details=_http_failure_details(
                status=error.code,
                detail=detail,
                raw_body=raw_body,
                headers=error.headers,
            ),
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as error:
        raise ExternalToolError(
            f"LLM provider request failed for {display_url(url)}: {error}",
            details=_transport_failure_details(error),
        ) from error
    return parse_json_object_response(body, url)


def _trusted_https_origin(base_url: str, hosts: set[str]) -> bool:
    parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
    try:
        port = parsed.port or 443
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and (parsed.hostname or "").casefold() in hosts
        and port == 443
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _base_url(provider: str, base_url: str | None = None) -> str:
    endpoint = PROVIDER_ENDPOINTS[provider]
    return (base_url or os.environ.get(endpoint["env"] + "_BASE_URL", endpoint["base_url"])).rstrip("/")


def _api_key(provider: str, base_url: str) -> str:
    endpoint = PROVIDER_ENDPOINTS[provider]
    env, label, host = endpoint["env"], endpoint["label"], endpoint["host"]
    if _trusted_https_origin(base_url, {host}):
        api_key = os.environ.get(env + "_API_KEY", "").strip()
        if not api_key:
            raise ConfigurationError(f"{env}_API_KEY is required for the {provider} LLM provider")
        return api_key
    if os.environ.get(env + "_ALLOW_CUSTOM_BASE_URL", "").strip().casefold() not in {"1", "true", "yes"}:
        raise ConfigurationError(f"custom {label}-compatible base URLs require {env}_ALLOW_CUSTOM_BASE_URL=1")
    api_key = os.environ.get(env + "_COMPAT_API_KEY", "").strip()
    if not api_key:
        raise ConfigurationError(
            f"custom {label}-compatible base URLs require {env}_COMPAT_API_KEY; {env}_API_KEY is only sent to {host}"
        )
    return api_key


def provider_request_body(**kwargs: Any) -> bytes:
    return _json_bytes(provider_request_payload(**kwargs))


def _openai_empty_output_error(raw: dict[str, Any], latency_ms: float) -> ExternalToolError:
    incomplete = raw.get("incomplete_details")
    return ExternalToolError(
        "OpenAI response did not include output text",
        details={
            "provider_failure_stage": "response_shape",
            "provider_failure_kind": "provider_error",
            "provider_failure_reason": "output_limit"
            if isinstance(incomplete, dict)
            and incomplete.get("reason") == "max_output_tokens"
            else "empty_output",
            "provider_status": raw.get("status"),
            "incomplete_details": incomplete,
            "response_id": raw.get("id"),
            "response_model": raw.get("model"),
            "usage": raw.get("usage", {}),
            "latency_ms": latency_ms,
        },
    )


OPENAI_COUNT_FIELDS = ("model", "input", "instructions", "reasoning", "text", "tools", "tool_choice")


def count_openai_input_tokens(body: bytes, *, base_url: str | None = None, timeout_seconds: int = 60) -> int:
    payload = json.loads(body)
    resolved_base_url = _base_url("openai", base_url)
    raw = post_json(
        f"{resolved_base_url}/responses/input_tokens",
        {key: payload[key] for key in OPENAI_COUNT_FIELDS if key in payload},
        timeout_seconds,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {_api_key('openai', resolved_base_url)}",
        },
    )
    count = raw.get("input_tokens")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ExternalToolError(
            "OpenAI token count did not include input_tokens",
            details={"provider_failure_kind": "provider_error"},
        )
    return count


def exact_input_tokens(kwargs: dict, body: bytes) -> int | None:
    if kwargs.get("provider") == "openai":
        return count_openai_input_tokens(body)
    return None


def call_llm(
    *,
    provider: str,
    prompt: str,
    model: str | None = None,
    system_prompt: str = "You are a concise assistant.",
    base_url: str | None = None,
    temperature: float | None = 0.2,
    timeout_seconds: int = 180,
    max_output_tokens: int | None = None,
    json_mode: bool = False,
    response_schema: dict[str, Any] | None = None,
    structured_output: str | None = None,
    reasoning_effort: str | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    route: str | None = None,
    context_window_tokens: int | None = None,
    safety_reserve_tokens: int = 0,
) -> LLMResponse:
    if not isinstance(model, str) or not model:
        raise ConfigurationError("paper execution requires an explicit model")
    payload = provider_request_payload(
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
    if context_window_tokens is not None:
        context_fit = preflight_context_fit(
            request_body=_json_bytes(payload),
            context_window_tokens=context_window_tokens,
            output_reserve_tokens=max_output_tokens if isinstance(max_output_tokens, int) else 0,
            safety_reserve_tokens=safety_reserve_tokens,
        )
        if context_fit["fits"] is not True:
            raise ContextLimitError(
                "complete model request exceeds the configured context window",
                details=context_fit,
            )
    endpoint = PROVIDER_ENDPOINTS[provider]
    resolved_base_url = _base_url(provider, base_url)
    started = perf_counter()
    raw = post_json(
        resolved_base_url + endpoint["path"],
        payload,
        timeout_seconds,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {_api_key(provider, resolved_base_url)}",
            **endpoint["headers"],
        },
    )
    latency_ms = (perf_counter() - started) * 1000
    text = provider_adapter(provider).response_text(raw)
    if not text:
        if provider == "openai":
            raise _openai_empty_output_error(raw, latency_ms)
        raise _missing_content_error("OpenRouter", raw)
    return _normalized_response(
        provider=provider,
        model=model,
        text=text,
        raw=raw,
        latency_ms=latency_ms,
        pinned_route=route,
    )
