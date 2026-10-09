from fmb.core.errors import ConfigurationError
from fmb.core.paper_protocol import paper_protocol


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


def expected_openrouter_upstream(model, route):
    return endpoint("openrouter", model, route)[1]


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
