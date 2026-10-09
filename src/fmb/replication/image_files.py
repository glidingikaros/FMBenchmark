from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from fmb.core.paper_protocol import MAX_PASSES, SAMPLING, checked_conditions, paper_protocol
from fmb.core.sealed_records import read_json
from fmb.question_packs import load_packs

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
IMAGES = Path("images")
TEMPLATE = "template"
SETTINGS = {"clock_bias_minutes": (-840, 840, "auto"), "activity_count": (1, 500, None),
            "activity_seed": (0, 2**63 - 1, None), "hardware_seed": (0, 2**63 - 1, None)}
PROVIDER_KEYS = {"openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY"}
FIXED_OBJECTS = {
    "security_log_clear_event_01": (1, "the image has one Security log"),
    "event_record_sequence_gap_01": (1, "the image has one Security log"),
}


@dataclass(frozen=True)
class Image:
    name: str
    seed: int
    contract: dict
    path: Path
    paper: bool = False
    settings: dict = field(default_factory=dict)


def paper_definition(name: str) -> dict:
    from fmb.core.paths import PROJECT_ROOT
    from fmb.generation import population

    image = paper_protocol()["images"][name]
    contract = population.load_population_contract(PROJECT_ROOT / image["population_contract"])
    return {"seed": image["population_seed"], **contract}


def load(path: Path) -> Image:
    from fmb.generation import pilot_profile, population

    path = Path(path).expanduser().resolve()
    if not NAME.fullmatch(path.stem) or path.stem == TEMPLATE:
        raise ValueError(f"{path.name}: the file name is the image's name: a letter, then letters, digits or '_' "
                         f"(and not {TEMPLATE})")
    if not path.is_file():
        raise ValueError(f"no image file {path}")
    value = read_json(path)
    if path.stem in paper_protocol()["images"]:
        if value != paper_definition(path.stem):
            raise ValueError(f"{path.name} differs from the paper's {path.stem}: restore it (git checkout {path.name}) "
                             "or save your version under another name")
        seed = value.pop("seed")
        return Image(path.stem, seed, value, path, paper=True)
    seed = value.pop("seed", None) if isinstance(value, dict) else None
    if type(seed) is not int or seed < 0:
        raise ValueError(f"{path.name}: give the image a seed, a non-negative integer")
    settings = _settings(value.pop("generation", {}), path.name)
    try:
        contract = population.validate_population_contract(value)
    except ValueError as error:
        raise ValueError(f"{path.name}: {error}") from error
    if contract.get("native_pilot_profile") != pilot_profile.PROFILE:
        raise ValueError(f"{path.name}: an image uses the native profile {pilot_profile.PROFILE}")
    present = contract["experiments"]["full_scale"]
    if set(contract["scenarios"]) != set(present) or not set(present) <= set(population.SCENARIO_ANALYSIS):
        raise ValueError(f"{path.name}: experiments.full_scale lists the scenarios of the image and scenarios defines "
                         f"each of them; the scenarios are {', '.join(population.SCENARIO_ANALYSIS)}")
    for pack in load_packs():
        needed = pack["generation"]["scenarios"]
        if 0 < len(set(needed) & set(present)) < len(needed):
            raise ValueError(f"{path.name}: {pack['question_id']} needs all of its scenarios ({', '.join(needed)}) "
                             "or none of them")
    supplement = pilot_profile.resolve_parameters(contract.get("native_pilot_parameters"))["case_classes"]
    unasked = sorted(set(supplement) - set(questions(contract)))
    if unasked:
        raise ValueError(f"{path.name}: native_pilot_parameters.case_classes has cases for {', '.join(unasked)}, "
                         "which the image does not ask; remove them")
    for scenario, (configured, reason) in FIXED_OBJECTS.items():
        if scenario in present and contract["scenarios"][scenario]["configured_count"] != configured:
            raise ValueError(f"{path.name}: {scenario} keeps {configured} object(s): {reason}")
    return Image(path.stem, seed, contract, path, settings=settings)


def questions(contract: dict) -> list[str]:
    present = set(contract["experiments"]["full_scale"])
    return [pack["question_id"] for pack in load_packs() if set(pack["generation"]["scenarios"]) <= present]


def _settings(value, where: str) -> dict:
    if not isinstance(value, dict) or set(value) - set(SETTINGS):
        raise ValueError(f"{where}: generation takes only " + ", ".join(SETTINGS))
    for key, (low, high, extra) in SETTINGS.items():
        if key in value and value[key] != extra and (type(value[key]) is not int or not low <= value[key] <= high):
            raise ValueError(f"{where}: generation.{key} is an integer from {low} to {high}"
                             + (f", or {extra!r}" if extra else ""))
    return value


def check(image: Image) -> str:
    from fmb.generation import population, recipe

    config = recipe.image_config(image.seed, image.contract, settings=image.settings)
    try:
        contract = recipe.resolved_contract(config)
        manifest = population.build_public_manifest(experiment=config["experiment"], seed=image.seed,
                                                    contract=contract)
        assignment = population.select_private_assignment(manifest, entropy=bytes(32))
        guest_plan = population.build_guest_plan(manifest, assignment, case=config["case"])
        recipe.validate_resolved_inputs(config, manifest, assignment, guest_plan)
        recipe._factual_challenge_plan(config, guest_plan, manifest)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise ValueError(f"{image.path.name}: the generator cannot build this population: {error!r}") from error
    return f"{image.name}: " + population_line({"seed": image.seed, **contract})


def population_line(definition: dict) -> str:
    from fmb.generation.pilot_profile import resolve_parameters

    scenarios = [definition["scenarios"][scenario] for scenario in definition["experiments"]["full_scale"]]
    supplement = resolve_parameters(definition.get("native_pilot_parameters"))["case_classes"]
    asked = questions(definition)
    return (f"seed {definition['seed']}, {sum(item['configured_count'] for item in scenarios)} objects, "
            f"{sum(item['manipulation_count'] for item in scenarios)} manipulated, {len_cases(supplement)}"
            + ("" if len(asked) == len(load_packs()) else f", questions {', '.join(asked)}"))


def len_cases(supplement: dict) -> str:
    count = sum(len(kinds) for kinds in supplement.values())
    return f"{count} supplementary case{'' if count == 1 else 's'}"


def activate(recipe_directory: Path) -> bool:
    from fmb.core import paper_integrity
    from fmb.generation import recipe

    config = recipe.inspect_recipe(recipe_directory)["recipe"]["config"]
    if "population_contract" not in config:
        return False
    recipe.resolved_contract(config)
    paper_integrity.permit_modified_sources()
    return True


def resolve(name: str) -> Path:
    path = Path(name).expanduser() if name.endswith(".json") else IMAGES / f"{name}.json"
    if not path.is_file():
        raise ValueError(f"no image {name}: name a file in {IMAGES}/ without .json, or give a path ending in .json")
    return path


def available() -> list[tuple[str, str]]:
    rows = []
    for path in sorted(IMAGES.glob("*.json")):
        if path.stem == TEMPLATE:
            continue
        try:
            image = load(path)
            rows.append((image.name, ("paper image, " if image.paper else "") + check(image).split(", ", 1)[1]))
        except ValueError as error:
            rows.append((path.stem, str(error)))
    return rows


def read_conditions(path: Path) -> dict:
    path = Path(path).expanduser()
    if not path.is_file():
        raise ValueError(f"--conditions {path}: no such file")
    try:
        return checked_conditions(read_json(path))
    except ValueError as error:
        raise ValueError(f"--conditions {path}: {error}") from error


def available_conditions(own: dict | None = None) -> list[tuple[str, str]]:
    rows = []
    for name, condition in {**paper_protocol()["conditions"], **(own or {})}.items():
        settings = condition["settings"]
        price = settings.get("price_usd_per_million")
        sampling = "".join(f"{key} {settings[key]}, " for key in SAMPLING if key in settings)
        rows.append((name, ("yours: " if name in (own or {}) else "")
                     + f"{settings['model']} via {settings['provider']}, reasoning {settings['reasoning_effort']}, "
                     + sampling + (f"${price['input']} in / ${price['output']} out per million tokens" if price
                                   else "no recorded price")))
    return rows


def llm_dispatch(conditions: list[str], cap_usd: float | None, prices: list[str], environ: dict,
                 own: dict | None = None, passes: int | None = None) -> dict | None:
    from decimal import Decimal, InvalidOperation

    if not conditions:
        if cap_usd is not None or prices or own is not None or passes is not None:
            raise ValueError("--cap-usd, --price, --conditions and --passes go with --llm")
        return None
    if cap_usd is None or cap_usd <= 0:
        raise ValueError("--llm needs --cap-usd: the most the LLM requests of one image may cost, in US dollars")
    if passes is not None and (type(passes) is not int or not 1 <= passes <= MAX_PASSES):
        raise ValueError(f"--passes is how many times each LLM request is sent, from 1 to {MAX_PASSES}")
    declared, given = {**paper_protocol()["conditions"], **(own or {})}, {}
    for item in prices:
        name, _, pair = item.partition("=")
        try:
            given[name] = dict(zip(("input", "output"), (str(Decimal(value)) for value in pair.split(",")), strict=True))
        except (InvalidOperation, ValueError) as error:
            raise ValueError(f"--price {item}: give NAME=INPUT,OUTPUT in US dollars per million tokens") from error
    rates = {}
    for name in dict.fromkeys(conditions):
        if name not in declared:
            raise ValueError(f"no LLM condition {name}; the conditions are " + ", ".join(declared)
                             + ("" if own else "; declare your own in a JSON file given with --conditions FILE"))
        settings = declared[name]["settings"]
        price = given.get(name) or settings.get("price_usd_per_million")
        if price is None:
            raise ValueError(f"{name} has no recorded price; add --price {name}=INPUT,OUTPUT (US dollars per million "
                             "tokens)")
        key = PROVIDER_KEYS[settings["provider"]]
        if not environ.get(key, "").strip():
            raise ValueError(f"{name} calls {settings['provider']}: set {key}")
        rates[name] = {"input": str(price["input"]), "output": str(price["output"])}
    used = {name: own[name] for name in rates if name in (own or {})}
    return {"conditions": list(rates), "dispatch": {"execute": True, "cap_usd": str(cap_usd), "rates": rates},
            **({"user_conditions": used} if used else {}), **({"passes": passes} if passes is not None else {})}
