from fmb.core.errors import ConfigurationError
from fmb.core.paper_protocol import paper_protocol, user_conditions


def endpoint(provider, model, route, *, effort=None):
    protocol = paper_protocol()
    for row in protocol["conditions"].values():
        settings = row["settings"]
        if settings["provider"] != provider or settings["model"] != model:
            continue
        if effort is not None and effort != settings["reasoning_effort"]:
            continue
        policy = row.get("completion_policy", {})
        if route == settings.get("route"):
            return settings, row.get("upstream_provider")
        if route is not None and route == policy.get("companion_route"):
            return settings, policy["upstream_provider"]
    raise ConfigurationError(
        "model, route or reasoning effort is outside the paper protocol"
    )


def declared_endpoints(provider, model, route):
    return [(row["settings"], row.get("upstream_provider")) for row in user_conditions().values()
            if (row["settings"]["provider"], row["settings"]["model"], row["settings"].get("route"))
            == (provider, model, route)]


def expected_openrouter_upstream(model, route):
    try:
        return endpoint("openrouter", model, route)[1]
    except ConfigurationError:
        declared = declared_endpoints("openrouter", model, route)
        if not declared:
            raise
        return next((upstream for _, upstream in declared if upstream is not None), None)


def validate_catalog_request(
    *,
    provider,
    model,
    route,
    temperature,
    max_output_tokens,
    json_mode,
    structured_output,
    reasoning_effort,
    top_p,
    seed,
):
    sampling = {"temperature": temperature, "top_p": top_p, "seed": seed}
    if any(
        settings["reasoning_effort"] == reasoning_effort
        and settings["max_output_tokens"] == max_output_tokens
        and settings.get("structured_output", "json_schema") == structured_output
        and all(settings.get(key) == value for key, value in sampling.items())
        for settings, _ in declared_endpoints(provider, model, route)
    ):
        return
    settings, _ = endpoint(provider, model, route, effort=reasoning_effort)
    if any(x is not None for x in (temperature, top_p, seed)):
        raise ConfigurationError("paper sampling settings must remain omitted")
    if (
        reasoning_effort != settings["reasoning_effort"]
        or max_output_tokens != settings["max_output_tokens"]
    ):
        raise ConfigurationError("request differs from the paper effort/output limit")
    if structured_output != "json_schema":
        raise ConfigurationError("paper requests require strict json_schema output")
