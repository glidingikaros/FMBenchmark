from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from fmb.core.paper_protocol import paper_protocol
from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import read_json

SCHEMA = "fmb_study.v1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
FIXED_COUNTS = {
    "usbstor_setupapi_discrepancy_01": (3, 1, "the native layout has three virtual USB drives"),
    "usb_volume_activity_gap_01": (3, 1, "the native layout has three virtual USB drives"),
    "security_log_clear_event_01": (1, 1, "the image has one Security log"),
    "event_record_sequence_gap_01": (1, 1, "the image has one log of this kind"),
}


@dataclass(frozen=True)
class Image:
    label: str
    seed: int
    contract: dict
    population: Path


@dataclass(frozen=True)
class Study:
    name: str
    path: Path
    images: dict[str, Image]


def study_file(path: Path) -> Path:
    path = Path(path).expanduser().resolve()
    return path / "study.json" if path.is_dir() else path


def load(path: Path) -> Study:
    from fmb.generation import population

    file = study_file(path)
    if not file.is_file():
        raise ValueError(f"no study at {file}; start one with `fmb study new`")
    value = read_json(file)
    if (not isinstance(value, dict) or value.get("schema_version") != SCHEMA
            or set(value) != {"schema_version", "name", "images"}):
        raise ValueError(f"{file}: a study has a schema_version ({SCHEMA}), a name and images")
    name, images = value["name"], value["images"]
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError(f"{file}: a study name uses letters, digits, '.', '_' and '-'")
    if not isinstance(images, dict) or not images:
        raise ValueError(f"{file}: a study needs at least one image")
    paper = sorted(paper_protocol()["images"])
    loaded = {}
    for label, entry in images.items():
        where = f"{file}: image {label}"
        if not LABEL.fullmatch(label) or label in paper:
            raise ValueError(f"{where}: an image name starts with a letter and uses letters, digits and '_'; "
                             f"{', '.join(paper)} are the paper's")
        if not isinstance(entry, dict) or set(entry) != {"seed", "population"}:
            raise ValueError(f"{where}: give a seed and a population file")
        if type(entry["seed"]) is not int or entry["seed"] < 0:
            raise ValueError(f"{where}: the seed is a non-negative integer")
        source = _population_file(file.parent, entry["population"], where)
        try:
            contract = population.load_population_contract(source)
        except (OSError, ValueError) as error:
            raise ValueError(f"{where}: {source.name}: {error}") from error
        _check_population(contract, f"{where}: {source.name}")
        loaded[label] = Image(label, entry["seed"], contract, source)
    return Study(name, file, loaded)


def _check_population(contract: dict, where: str) -> None:
    from fmb.generation import pilot_profile, population

    if contract.get("native_pilot_profile") != pilot_profile.PROFILE:
        raise ValueError(f"{where}: a study image uses the native profile {pilot_profile.PROFILE}")
    if set(contract["experiments"]["full_scale"]) != set(population.SCENARIO_ANALYSIS):
        raise ValueError(f"{where}: experiments.full_scale keeps all {len(population.SCENARIO_ANALYSIS)} scenarios, "
                         "which the native profile builds on; change their counts instead")
    for scenario, (configured, manipulated, reason) in FIXED_COUNTS.items():
        item = contract["scenarios"][scenario]
        if (item["configured_count"], item["manipulation_count"]) != (configured, manipulated):
            raise ValueError(f"{where}: {scenario} stays at {configured} objects with {manipulated} manipulated: "
                             f"{reason}")


def _population_file(root: Path, relative, where: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"{where}: the population is a file in the study's folder")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"{where}: no population file {relative} in {root}")
    return path


def scaffold(directory: Path, *, template: str = "I3", label: str = "S1", seed: int | None = None) -> Path:
    directory = Path(directory).expanduser().resolve()
    file = directory / "study.json"
    if file.exists():
        raise ValueError(f"{file} already exists")
    images = paper_protocol()["images"]
    if template not in images:
        raise ValueError(f"the template is one of the paper's images: {', '.join(sorted(images))}")
    if not LABEL.fullmatch(label) or label in images:
        raise ValueError("an image name starts with a letter and uses letters, digits and '_'; "
                         f"{', '.join(sorted(images))} are the paper's")
    contract = json.loads((PROJECT_ROOT / images[template]["population_contract"]).read_text(encoding="utf-8"))
    if "native_pilot_parameters" in contract:
        contract["native_pilot_parameters"]["image_label"] = label
    population = f"population-{label.lower()}.json"
    if (directory / population).exists():
        raise ValueError(f"{directory / population} already exists")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", directory.name).strip("-.") or "study"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / population).write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    study = {"schema_version": SCHEMA, "name": name[:64],
             "images": {label: {"seed": secrets.randbelow(2**31) if seed is None else seed,
                                "population": population}}}
    file.write_text(json.dumps(study, indent=2) + "\n", encoding="utf-8")
    return file


def check(study: Study) -> list[dict]:
    from fmb.generation import population, recipe as recipes
    from fmb.generation.pilot_profile import resolve_parameters

    rows = []
    for image in study.images.values():
        config = recipes.study_config(image.seed, image.contract)
        contract = recipes.resolved_contract(config)
        manifest = population.build_public_manifest(experiment=config["experiment"], seed=image.seed,
                                                    contract=contract)
        assignment = population.select_private_assignment(manifest, entropy=bytes(32))
        guest_plan = population.build_guest_plan(manifest, assignment, case=config["case"])
        recipes.validate_resolved_inputs(config, manifest, assignment, guest_plan)
        recipes._factual_challenge_plan(config, guest_plan, manifest)
        scenarios = {scenario: (contract["scenarios"][scenario]["configured_count"],
                                contract["scenarios"][scenario]["manipulation_count"])
                     for scenario in contract["experiments"][config["experiment"]]}
        supplement = resolve_parameters(contract.get("native_pilot_parameters"))["case_classes"]
        rows.append({"image": image.label, "seed": image.seed, "scenarios": scenarios,
                     "supplement": {qid: list(kinds) for qid, kinds in supplement.items()}})
    return rows


def activate(recipe: Path) -> bool:
    from fmb.core import paper_integrity
    from fmb.generation import recipe as recipes

    config = recipes.inspect_recipe(recipe)["recipe"]["config"]
    if "population_contract" not in config:
        return False
    recipes.resolved_contract(config)
    paper_integrity.permit_modified_sources()
    return True
