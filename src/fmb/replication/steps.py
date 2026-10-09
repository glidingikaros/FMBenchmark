from __future__ import annotations

import json
import sys
from pathlib import Path

from fmb.core.errors import run_cli
from fmb.core.json_io import json_text
from fmb.core.paper_protocol import paper_protocol
from fmb.core.paths import PROJECT_ROOT, default_current_root

PAPER_GUEST = {"windows_build": "22000", "timezone": "Pacific Standard Time", "locale": "en-US"}


def _target(provider: str) -> tuple[str, str, str]:
    from fmb.generation import recipe

    config = recipe.paper_config("I1", provider)
    return config["provider"], config["windows_box"], paper_protocol()["generation"]["base_box_version"]


def _load_generation_pipeline():
    from fmb.generation import pipeline

    return pipeline


def _pipeline(config: dict, output: Path, *, recipe_path: Path | None = None, population_contract: Path | None = None,
              vm_work_root: Path | None = None):
    return _load_generation_pipeline().GenerationPipeline(
        config["provider"], "baseline", config["export_format"], False, config["randomize_hw"],
        experiment=config["experiment"], case=config["case"], population_seed=config["population_seed"],
        output_root=output, windows_box=config["windows_box"], vmware_bridge=config["vmware_bridge"],
        recipe=recipe_path, population_contract=population_contract, activity_count=config["activity_count"],
        vm_work_root=vm_work_root,
    )


def lock(path: str, provider: str, windows_build: str | None = None) -> dict:
    from fmb.generation import dependency_lock, recipe

    destination = Path(path).expanduser().absolute()
    if destination.exists():
        raise ValueError("dependency lock destination already exists")
    guest = dict(PAPER_GUEST, **({"windows_build": windows_build} if windows_build else {}))
    backend, box, version = _target(provider)
    _, imports = recipe.closure_modules(PROJECT_ROOT)
    built = dependency_lock.build_lock(backend_name=backend, box=box, version=version, guest=guest, imports=imports,
                                       cwd=PROJECT_ROOT / "generation")
    destination.parent.mkdir(parents=True, exist_ok=True)
    recipe.write_private(destination, built)
    return {
        "status": "completed", "path": str(destination), "schema_version": built["schema_version"],
        "pinned_inputs_sha256": dependency_lock.pinned_digest(built),
        "hypervisor": built["backend"]["hypervisor"], "base_location": built["base"]["location"],
        "base_files": len(built["base"]["files"]),
        "base_bytes": sum(row["size_bytes"] for row in built["base"]["files"]),
        "ansible_core": built["guest_code"]["ansible_core"]["version"],
        "collections": {name: row["version"] for name, row in built["guest_code"]["collections"].items()},
        "host_libraries": built["host_libraries"]["distributions"],
    }


def freeze(image: str, provider: str, lock: str, recipe: str, image_file: str | None = None) -> dict:
    from fmb.generation import recipe as recipes

    if image_file is None:
        config = recipes.paper_config(image, provider)
        contract = PROJECT_ROOT / paper_protocol()["images"][image]["population_contract"]
    else:
        from fmb.replication import image_files

        own = image_files.load(Path(image_file))
        config = recipes.image_config(own.seed, own.contract, provider)
        contract = own.contract
    pipeline = _pipeline(config, default_current_root() / "generated", population_contract=contract)
    try:
        pipeline.prepare_population()
        frozen = recipes.freeze_recipe(
            Path(recipe), source_root=pipeline.work_dir, config=config,
            population=pipeline.public_population_manifest, assignment=pipeline.private_population_assignment,
            guest_plan=pipeline.population_guest_plan, dependency_lock=recipes.read_json(Path(lock)),
            activity_seed=config["population_seed"], hardware_seed=config["population_seed"],
            assignment_origin=None,
        )
    finally:
        pipeline.cleanup_population_inputs()
    return {"status": "completed", "recipe_id": frozen["recipe_id"], "path": recipe,
            "schema_version": frozen["schema_version"]}


def generate(recipe: str, output_root: str, vm_work_root: str | None = None) -> dict:
    from fmb.generation import recipe as recipes

    bundle = recipes.load_recipe(Path(recipe), source_root=PROJECT_ROOT / "generation", verify_dependencies=False)
    pipeline = _pipeline(bundle["recipe"]["config"], Path(output_root), recipe_path=Path(recipe),
                         vm_work_root=Path(vm_work_root) if vm_work_root else None)
    pipeline.run()
    return {"status": "completed", "output_root": output_root}


def analyse(config: str, recipe: str | None = None, engine_file: str | None = None) -> dict:
    from fmb.pipeline.runner import load_config, run_pipeline

    if engine_file is not None:
        from fmb.assessment.stage import register_engine_file

        register_engine_file(Path(engine_file))
    if recipe is not None:
        from fmb.replication import image_files

        image_files.activate(Path(recipe))
    return run_pipeline(load_config(Path(config)))


STEPS = {"lock": lock, "freeze": freeze, "generate": generate, "analyse": analyse}


def main(argv: list[str] | None = None) -> int:
    name, arguments = argv if argv is not None else sys.argv[1:]

    def call() -> int:
        result = STEPS[name](**json.loads(arguments))
        sys.stdout.write(json_text(result, sort_keys=True))
        return 0 if result.get("status") == "completed" else 1

    return run_cli("fmb", call)


if __name__ == "__main__":
    raise SystemExit(main())
