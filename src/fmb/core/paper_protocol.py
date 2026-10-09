from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import math
import re

from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import read_json

DEFAULT_CONTEXT_WINDOW_TOKENS = 1050000
SAFETY_RESERVE_TOKENS = 2048
MAX_PASSES = 10
SAMPLING = ("temperature", "top_p", "seed")
REQUIRED_SETTINGS = ("provider", "model", "reasoning_effort", "max_output_tokens", "timeout_seconds")
USER_SETTINGS = {*REQUIRED_SETTINGS, "route", "context_window_tokens", "structured_output", "price_usd_per_million",
                 *SAMPLING}
REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
CONDITION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PRICE = re.compile(r"\d+(\.\d+)?")
_USER_CONDITIONS = ContextVar("fmb_user_conditions", default={})


def paper_protocol():
    return read_json(PROJECT_ROOT / "contracts/paper/protocol.json")


def checked_passes(passes):
    if type(passes) is not int or not 1 <= passes <= MAX_PASSES:
        raise ValueError(f"passes must be a whole number from 1 to {MAX_PASSES}")
    return passes


def _text(value):
    return isinstance(value, str) and bool(value) and value == value.strip()


def _number(value, low, high):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def _price(value):
    return bool(PRICE.fullmatch(value)) if isinstance(value, str) else _number(value, 0, math.inf)


def _check_declaration(name, declaration):
    if not isinstance(declaration, dict) or "settings" not in declaration or set(declaration) - {
            "settings", "upstream_provider"}:
        raise ValueError(f"{name}: a condition has settings and, for openrouter, an optional upstream_provider")
    settings = declaration["settings"]
    if not isinstance(settings, dict) or set(settings) - USER_SETTINGS:
        raise ValueError(f"{name}: settings may name only " + ", ".join(sorted(USER_SETTINGS)))
    missing = [key for key in REQUIRED_SETTINGS if key not in settings]
    if missing:
        raise ValueError(f"{name}: settings need " + ", ".join(missing))
    provider = settings["provider"]
    if provider not in ("openai", "openrouter"):
        raise ValueError(f"{name}: provider is openai or openrouter")
    if not _text(settings["model"]):
        raise ValueError(f"{name}: model is the provider's name for the model")
    if settings["reasoning_effort"] not in REASONING_EFFORTS:
        raise ValueError(f"{name}: reasoning_effort is one of " + ", ".join(REASONING_EFFORTS))
    for key in ("max_output_tokens", "timeout_seconds", "context_window_tokens"):
        if key in settings and (type(settings[key]) is not int or settings[key] < 1):
            raise ValueError(f"{name}: {key} is a whole number above 0")
    if provider == "openrouter" and not _text(settings.get("route")):
        raise ValueError(f"{name}: an openrouter condition names its route, the one provider OpenRouter may use")
    if provider == "openai" and ("route" in settings or "upstream_provider" in declaration):
        raise ValueError(f"{name}: an openai condition has no route or upstream_provider")
    if "upstream_provider" in declaration and not _text(declaration["upstream_provider"]):
        raise ValueError(f"{name}: upstream_provider is the provider name OpenRouter reports for the route")
    if settings.get("structured_output", "json_schema") != "json_schema":
        raise ValueError(f"{name}: structured_output is json_schema, the only output the requests use")
    for key, low, high in (("temperature", 0, 2), ("top_p", 0, 1)):
        if key in settings and not _number(settings[key], low, high):
            raise ValueError(f"{name}: {key} is a number from {low} to {high}")
    if "seed" in settings and (type(settings["seed"]) is not int or not -2**63 <= settings["seed"] < 2**63):
        raise ValueError(f"{name}: seed is a 64-bit whole number")
    price = settings.get("price_usd_per_million", {"input": "0", "output": "0"})
    if not isinstance(price, dict) or set(price) != {"input", "output"} or not all(map(_price, price.values())):
        raise ValueError(f'{name}: price_usd_per_million is {{"input": ..., "output": ...}}, US dollars per million '
                         "tokens")


def _paper_upstreams(paper):
    upstreams = {}
    for row in paper.values():
        settings, policy = row["settings"], row.get("completion_policy") or {}
        if settings["provider"] == "openrouter":
            upstreams[settings["model"], settings["route"]] = row.get("upstream_provider")
            if policy.get("companion_route"):
                upstreams[settings["model"], policy["companion_route"]] = policy["upstream_provider"]
    return upstreams


def checked_conditions(conditions):
    if not isinstance(conditions, dict) or not conditions:
        raise ValueError("declare conditions as a JSON object that maps each name to its settings")
    paper = paper_protocol()["conditions"]
    taken, upstreams = {name.casefold() for name in paper}, _paper_upstreams(paper)
    for name, declaration in conditions.items():
        if not isinstance(name, str) or not CONDITION_NAME.fullmatch(name) or name == "rules":
            raise ValueError(f"{name!r}: a condition name has 1 to 64 letters, digits, '.', '_' or '-', and starts "
                             "with a letter or digit (and is not rules)")
        if name.casefold() in taken:
            raise ValueError(f"{name}: one of the paper's conditions or another of yours has this name (names must "
                             "differ beyond case)")
        taken.add(name.casefold())
        _check_declaration(name, declaration)
        if "upstream_provider" in declaration:
            route = declaration["settings"]["model"], declaration["settings"]["route"]
            if upstreams.setdefault(route, declaration["upstream_provider"]) != declaration["upstream_provider"]:
                raise ValueError(f"{name}: {route[0]} through {route[1]} is served by {upstreams[route]}")
    return deepcopy(conditions)


def user_conditions():
    return _USER_CONDITIONS.get()


@contextmanager
def declare_conditions(conditions):
    known = _USER_CONDITIONS.get()
    if any(known.get(name, declaration) != declaration for name, declaration in conditions.items()):
        raise ValueError("a condition is declared twice with different settings")
    token = _USER_CONDITIONS.set(checked_conditions({**known, **conditions}) if conditions else known)
    try:
        yield
    finally:
        _USER_CONDITIONS.reset(token)


def run_declaration(protocol):
    return {protocol.get("condition_id"): protocol["user_condition"]} if "user_condition" in protocol else {}


def condition_settings(condition, *, completion=False, protocol=None):
    protocol = protocol or paper_protocol()
    known = {**_USER_CONDITIONS.get(), **protocol["conditions"]}
    if condition not in known:
        raise ValueError("unknown paper condition")
    declared = known[condition]
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
    own = _USER_CONDITIONS.get()
    if condition in own:
        if completion or settings != own[condition]["settings"]:
            raise ValueError("settings differ from the declared condition")
        return condition, False
    if any(settings.get(key) is not None for key in SAMPLING):
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
    sampling = {key: settings[key] for key in SAMPLING if settings.get(key) is not None}
    if {key: body[key] for key in SAMPLING if key in body} != sampling or body.get("stream") is not False:
        raise ValueError("request sampling/stream settings differ from condition")
    if is_openrouter and body.get("provider") != {
        "order": [settings["route"]], "only": [settings["route"]],
        "allow_fallbacks": False, "require_parameters": True,
    }:
        raise ValueError("request route differs from condition")
    if kwargs is not None:
        if _condition_values(kwargs) != _condition_values(settings):
            raise ValueError("request kwargs differ from condition")
        if any(kwargs.get(key) != settings.get(key) for key in SAMPLING):
            raise ValueError("request kwargs override the condition's sampling")
        if kwargs.get("safety_reserve_tokens") != SAFETY_RESERVE_TOKENS:
            raise ValueError("request context reserve differs from paper")


def validate_completion_policy(primary, companion):
    name, _ = validate_condition(primary, completion=False)
    validate_condition(companion, condition=name, completion=True)
