from copy import deepcopy

from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import read_json

DEFAULT_CONTEXT_WINDOW_TOKENS = 1050000
SAFETY_RESERVE_TOKENS = 2048


def paper_protocol():
    return read_json(PROJECT_ROOT / "contracts/paper/protocol.json")


def condition_settings(condition, *, completion=False, protocol=None):
    protocol = protocol or paper_protocol()
    if condition not in protocol["conditions"]:
        raise ValueError("unknown paper condition")
    declared = protocol["conditions"][condition]
    settings = deepcopy(declared["settings"])
    if completion:
        policy = declared.get("completion_policy")
        if not policy:
            raise ValueError("no completion policy declared for this condition")
        if "companion_route" in policy:
            settings["route"] = policy["companion_route"]
        if "context_precheck_allowance" in policy:
            settings["context_window_tokens"] = policy["context_precheck_allowance"]
    return settings


def _condition_values(settings):
    return {
        **{key: settings.get(key) for key in (
            "provider", "model", "reasoning_effort", "max_output_tokens",
            "timeout_seconds", "route",
        )},
        "context_window_tokens": settings.get("context_window_tokens", DEFAULT_CONTEXT_WINDOW_TOKENS),
        "structured_output": settings.get("structured_output", "json_schema"),
    }


def validate_condition(settings, *, condition=None, completion=None):
    if not isinstance(settings, dict):
        raise ValueError("missing paper condition settings")
    if any(settings.get(key) is not None for key in ("temperature", "top_p", "seed")):
        raise ValueError("settings outside the fixed paper condition")
    protocol = paper_protocol()
    candidates = [condition] if condition is not None else list(protocol["conditions"])
    for name in candidates:
        if name not in protocol["conditions"]:
            raise ValueError("unknown paper condition")
        modes = [completion] if completion is not None else [False, True]
        for mode in modes:
            if mode and not protocol["conditions"][name].get("completion_policy"):
                continue
            wanted = condition_settings(name, completion=mode, protocol=protocol)
            if _condition_values(settings) == _condition_values(wanted):
                return name, mode
    raise ValueError("settings differ from the declared paper condition")


def validate_request_settings(body, settings, *, kwargs=None):
    is_openrouter = settings["provider"] == "openrouter"
    if ("messages" in body) != is_openrouter or ("input" in body) == is_openrouter:
        raise ValueError("request provider differs from condition")
    reasoning = {"effort": settings["reasoning_effort"]}
    if is_openrouter:
        reasoning["exclude"] = True
    token_field = "max_tokens" if is_openrouter else "max_output_tokens"
    if (
        body.get("model") != settings["model"]
        or body.get("reasoning") != reasoning
        or body.get(token_field) != settings["max_output_tokens"]
        or ("max_output_tokens" if is_openrouter else "max_tokens") in body
    ):
        raise ValueError("request model/effort/output cap differs from condition")
    if any(key in body for key in ("temperature", "top_p", "seed")) or body.get("stream") is not False:
        raise ValueError("request sampling/stream settings differ from paper")
    if is_openrouter and body.get("provider") != {
        "order": [settings["route"]], "only": [settings["route"]],
        "allow_fallbacks": False, "require_parameters": True,
    }:
        raise ValueError("request route differs from condition")
    if kwargs is not None:
        if _condition_values(kwargs) != _condition_values(settings):
            raise ValueError("request kwargs differ from condition")
        if any(kwargs.get(key) is not None for key in ("temperature", "top_p", "seed")):
            raise ValueError("request kwargs override the paper condition")
        if kwargs.get("safety_reserve_tokens") != SAFETY_RESERVE_TOKENS:
            raise ValueError("request context reserve differs from paper")


def validate_completion_policy(primary, companion):
    name, _ = validate_condition(primary, completion=False)
    validate_condition(companion, condition=name, completion=True)
