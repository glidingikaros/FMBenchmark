from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from fmb.core.paper_protocol import paper_protocol
from fmb.core.sealed_records import read_json

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
IMAGES = Path("images")
PROVIDER_KEYS = {"openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY"}
MANIPULATED = {
    "timestomp_01": 2, "ads_injection_01": 2, "prefetch_wipe_01": 1, "security_log_clear_event_01": 1,
    "usn_journal_01": 1, "shimcache_path_residue_01": 1, "typed_path_residue_01": 2, "shellbag_path_residue_01": 1,
    "ntfs_allocation_01": 1, "bitmap_trailing_data_01": 2, "usbstor_setupapi_discrepancy_01": 1,
    "usb_volume_activity_gap_01": 1, "event_record_sequence_gap_01": 1,
}
FIXED_OBJECTS = {
    "usbstor_setupapi_discrepancy_01": (3, "the native layout has three virtual USB drives"),
    "usb_volume_activity_gap_01": (3, "the native layout has three virtual USB drives"),
    "ntfs_allocation_01": (4, "its guest script builds one file for each of four storage modes"),
    "security_log_clear_event_01": (1, "the image has one Security log"),
    "event_record_sequence_gap_01": (1, "the image has one Security log"),
}


@dataclass(frozen=True)
class Image:
    name: str
    seed: int
    contract: dict
    path: Path


def load(path: Path) -> Image:
    from fmb.generation import pilot_profile, population

    path = Path(path).expanduser().resolve()
    paper = sorted(paper_protocol()["images"])
    if not NAME.fullmatch(path.stem) or path.stem in paper:
        raise ValueError(f"{path.name}: the file name is the image's name: a letter, then letters, digits or '_'; "
                         f"{', '.join(paper)} are the paper's")
    if not path.is_file():
        raise ValueError(f"no image file {path}")
    value = read_json(path)
    seed = value.pop("seed", None) if isinstance(value, dict) else None
    if type(seed) is not int or seed < 0:
        raise ValueError(f"{path.name}: give the image a seed, a non-negative integer")
    try:
        contract = population.validate_population_contract(value)
    except ValueError as error:
        raise ValueError(f"{path.name}: {error}") from error
    if contract.get("native_pilot_profile") != pilot_profile.PROFILE:
        raise ValueError(f"{path.name}: an image uses the native profile {pilot_profile.PROFILE}")
    if set(contract["experiments"]["full_scale"]) != set(population.SCENARIO_ANALYSIS):
        raise ValueError(f"{path.name}: experiments.full_scale keeps all {len(population.SCENARIO_ANALYSIS)} "
                         "scenarios, which the native profile builds on; change their counts instead")
    for scenario, manipulated in MANIPULATED.items():
        if contract["scenarios"][scenario]["manipulation_count"] != manipulated:
            raise ValueError(f"{path.name}: {scenario} manipulates {manipulated} object(s), which its guest script "
                             "fixes; change configured_count, the objects around them, instead")
    for scenario, (configured, reason) in FIXED_OBJECTS.items():
        if contract["scenarios"][scenario]["configured_count"] != configured:
            raise ValueError(f"{path.name}: {scenario} keeps {configured} object(s): {reason}")
    return Image(path.stem, seed, contract, path)


def check(image: Image) -> str:
    from fmb.generation import population, recipe
    from fmb.generation.pilot_profile import resolve_parameters

    config = recipe.image_config(image.seed, image.contract)
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
    scenarios = [contract["scenarios"][scenario] for scenario in contract["experiments"][config["experiment"]]]
    supplement = resolve_parameters(contract.get("native_pilot_parameters"))["case_classes"]
    return (f"{image.name}: seed {image.seed}, {sum(item['configured_count'] for item in scenarios)} objects, "
            f"{sum(item['manipulation_count'] for item in scenarios)} manipulated, "
            f"{len_cases(supplement)}")


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


def paper_image(name: str) -> Image:
    from fmb.core.paths import PROJECT_ROOT
    from fmb.generation import population

    image = paper_protocol()["images"][name]
    path = PROJECT_ROOT / image["population_contract"]
    return Image(name, image["population_seed"], population.load_population_contract(path), path)


def resolve_image(name: str) -> str:
    if name in paper_protocol()["images"] or name.endswith(".json"):
        return name
    path = IMAGES / f"{name}.json"
    if not path.is_file():
        raise ValueError(f"no image {name}: name I1, I2, I3, a file in {IMAGES}/ or a path ending in .json")
    return str(path)


def available_images() -> list[tuple[str, str]]:
    rows = []
    for name in paper_protocol()["images"]:
        rows.append((name, "paper, " + check(paper_image(name)).split(", ", 1)[1]))
    for path in sorted(IMAGES.glob("*.json")):
        try:
            rows.append((path.stem, f"{path}, " + check(load(path)).split(", ", 1)[1]))
        except ValueError as error:
            rows.append((path.stem, f"{path}: {error}"))
    return rows


def available_conditions() -> list[tuple[str, str]]:
    rows = []
    for name, condition in paper_protocol()["conditions"].items():
        settings = condition["settings"]
        price = settings.get("price_usd_per_million")
        rows.append((name, f"{settings['model']} via {settings['provider']}, reasoning {settings['reasoning_effort']}, "
                           + (f"${price['input']} in / ${price['output']} out per million tokens" if price
                              else "no recorded price")))
    return rows


def llm_dispatch(conditions: list[str], cap_usd: float | None, prices: list[str], environ: dict) -> dict | None:
    from decimal import Decimal, InvalidOperation

    if not conditions:
        if cap_usd is not None or prices:
            raise ValueError("--cap-usd and --price go with --llm")
        return None
    if cap_usd is None or cap_usd <= 0:
        raise ValueError("--llm needs --cap-usd: the most the LLM requests of one image may cost, in US dollars")
    declared, given = paper_protocol()["conditions"], {}
    for item in prices:
        name, _, pair = item.partition("=")
        try:
            given[name] = dict(zip(("input", "output"), (str(Decimal(value)) for value in pair.split(",")), strict=True))
        except (InvalidOperation, ValueError) as error:
            raise ValueError(f"--price {item}: give NAME=INPUT,OUTPUT in US dollars per million tokens") from error
    rates = {}
    for name in dict.fromkeys(conditions):
        if name not in declared:
            raise ValueError(f"no LLM condition {name}; `fmb list` shows them")
        settings = declared[name]["settings"]
        price = given.get(name) or settings.get("price_usd_per_million")
        if price is None:
            raise ValueError(f"{name} has no recorded price; add --price {name}=INPUT,OUTPUT (US dollars per million "
                             "tokens)")
        key = PROVIDER_KEYS[settings["provider"]]
        if not environ.get(key, "").strip():
            raise ValueError(f"{name} calls {settings['provider']}: set {key}")
        rates[name] = {"input": str(price["input"]), "output": str(price["output"])}
    return {"conditions": list(rates), "dispatch": {"execute": True, "cap_usd": str(cap_usd), "rates": rates}}


def scaffold(name: str, template: str, seed: int) -> Path:
    import json

    paper = sorted(paper_protocol()["images"])
    if not NAME.fullmatch(name) or name in paper:
        raise ValueError(f"an image name is a letter, then letters, digits or '_'; {', '.join(paper)} are the paper's")
    path = IMAGES / f"{name}.json"
    if path.exists():
        raise ValueError(f"{path} already exists")
    contract = json.loads(paper_image(template).path.read_text(encoding="utf-8"))
    contract["native_pilot_parameters"]["image_label"] = name
    IMAGES.mkdir(exist_ok=True)
    path.write_text(json.dumps({"seed": seed, **contract}, indent=2) + "\n", encoding="utf-8")
    return path
