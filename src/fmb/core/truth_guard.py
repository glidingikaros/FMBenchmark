from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import re
import sys

_READ_GUARD = ContextVar("paper_private_read_guard", default=None)


def _audit_open(event, args):
    state = _READ_GUARD.get()
    if (
        event != "open"
        or state is None
        or not isinstance(args[0], (str, bytes, os.PathLike))
    ):
        return
    path = Path(os.fsdecode(args[0])).resolve()
    name = path.name.casefold()
    if (
        name
        in {
            "ground_truth.json",
            "finding_reference.json",
            "factual-challenge-plan.json",
            "factual-challenge-receipt.json",
            "private.json",
            "private-generation.json",
            "recipe.json",
            "pilot-materialization.json",
            "private-native.log",
        }
        or any(part.casefold().startswith("private-recipe") for part in path.parts)
        or (path.is_relative_to(state["generation"]) and path not in state["allowed"])
    ):
        state["denied"].append(str(path))
        raise PermissionError("truth-blind stage refused private source: " + str(path))
    if path.is_relative_to(state["generation"]):
        state["opened"].add(str(path))


sys.addaudithook(_audit_open)


PUBLIC_GENERATION_NAMES = (
    "manifest.json",
    "population_manifest.json",
    "population-manifest.json",
    "factual-challenge-population.json",
    "native_media.vmdk",
    "native_media_binding.json",
)
DEFAULT_SYSTEM_IMAGE = "full_scale.vmdk"
IMAGE_SUFFIXES = (".vmdk", ".raw", ".img", ".dd")
COMPANION_MEDIA = re.compile(r"media_([0-9a-f]{12})\.(json|vmdk|raw|img|dd)")


def is_disk_image(name: str) -> bool:
    return Path(name).suffix.casefold() in IMAGE_SUFFIXES


def _system_image_name(name) -> bool:
    return (isinstance(name, str) and Path(name).name == name and "\\" not in name and is_disk_image(name)
            and name != "native_media.vmdk" and not COMPANION_MEDIA.fullmatch(name))


def system_image(manifest: dict) -> dict:
    rows = manifest.get("artifacts") if isinstance(manifest, dict) else None
    images = [row for row in rows if isinstance(row, dict) and _system_image_name(row.get("file"))
              ] if isinstance(rows, list) else []
    if len(images) != 1:
        raise ValueError("the generation manifest must record exactly one system image (.vmdk, .raw, .img or .dd)")
    return images[0]


def public_generation_files(generation: Path, image: str = DEFAULT_SYSTEM_IMAGE) -> set[Path]:
    generation = generation.resolve(strict=True)
    allowed = {generation / name for name in (*PUBLIC_GENERATION_NAMES, image)}
    for path in generation.iterdir():
        if not path.is_symlink() and COMPANION_MEDIA.fullmatch(path.name):
            allowed.add(path)
    return allowed


@contextmanager
def truth_blind_reads(generation: Path, image: str = DEFAULT_SYSTEM_IMAGE):
    generation = generation.resolve(strict=True)
    allowed = public_generation_files(generation, image)
    state = {
        "generation": generation,
        "allowed": allowed,
        "opened": set(),
        "denied": [],
    }
    token = _READ_GUARD.set(state)
    try:
        yield state
    finally:
        _READ_GUARD.reset(token)


