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
    "full_scale.vmdk",
    "native_media.vmdk",
    "native_media_binding.json",
)
COMPANION_MEDIA = re.compile(r"media_([0-9a-f]{12})\.(json|vmdk)")


def public_generation_files(generation: Path) -> set[Path]:
    generation = generation.resolve(strict=True)
    allowed = {generation / name for name in PUBLIC_GENERATION_NAMES}
    for path in generation.iterdir():
        if not path.is_symlink() and COMPANION_MEDIA.fullmatch(path.name):
            allowed.add(path)
    return allowed


@contextmanager
def truth_blind_reads(generation: Path):
    generation = generation.resolve(strict=True)
    allowed = public_generation_files(generation)
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


