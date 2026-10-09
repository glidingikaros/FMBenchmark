from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from fmb.core.paper_protocol import paper_protocol
from fmb.core.sealed_records import read_json

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
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
            f"{sum(len(kinds) for kinds in supplement.values())} supplementary cases")


def activate(recipe_directory: Path) -> bool:
    from fmb.core import paper_integrity
    from fmb.generation import recipe

    config = recipe.inspect_recipe(recipe_directory)["recipe"]["config"]
    if "population_contract" not in config:
        return False
    recipe.resolved_contract(config)
    paper_integrity.permit_modified_sources()
    return True
