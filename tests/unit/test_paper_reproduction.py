import hashlib
import json
from pathlib import Path

import pytest

from fmb.generation import population, recipe
from fmb.replication import image_files

ROOT = Path(__file__).resolve().parents[2]

PLANS = {
    "I1": {"config": "4c4da1a79862548600010be3b7d37969bcd16d955b60570cd87d185890c66f0d",
           "qemu": "04c0328313d5d23f6fcbe697e615e56f26dcaa0516ac0cf2944967bedc44e07b",
           "manifest": "1ab467c3cc5c901be7d5ad90f5fc3647ef1e6812fc34a375f7ec007bd75de845",
           "assignment": "56f58b89aff76eaf1cbde6cc35d60bb671c2021242c9968cf85098f3ca4c8e9a",
           "plan": "472d49d46875564bd8a3f517282f32a53282fbf09ee8b4b6404d0702d274c0d9",
           "challenge": "379b569de8c61f4eb024aa7081fc53266eae627af22eeabf5f349233003cc6b1",
           "activity": "ffddfc78166054c9658fa9395f0c098cd13a61c470cd7f3e9dd484eece020699",
           "hardware": "614df4d305f92a74a81fe891fc6f36d7b6defdc0290f08fdae914be8e44d2ed2"},
    "I2": {"config": "114500104318265e45fed273ce6ad08ccb1ad7f980ddca35da88c4080774c251",
           "qemu": "352cbf1022c7a5ca960439192b864e412cd7c7292a2a6d7cd0d875b82ae62fbf",
           "manifest": "a0c51f9306501ee05031fcb9f8547437e92c344e4fcdd49ff079f96f38a2cf29",
           "assignment": "d408df064065bda8335cbaeeef343f1b0f68c24f6d99b407b9268e22b6ea357d",
           "plan": "0f10f7a0ca85b04bb557785b1c2c4ab76d171d8193ecbe16f2cb6f24de53881a",
           "challenge": "5f30ba78835cf3a216994109f99c1917cc053fac5fda38473e74b44da8f92825",
           "activity": "1f6e7732b5e4666f5358e3b985f6eaea2aaffc80db7784dbbac5e730a0f5f93e",
           "hardware": "26abfdc2a1396000b4f951201f5d34ca8c9f576c18e96db9ed5a6d6923954670"},
    "I3": {"config": "cb3e148c1122f6cc6ff037b899627e9dd2f172447cfccfb799b6f3146949ce6e",
           "qemu": "3afd13dc54b1696bf4b6af53387059183a3ce9039301f0f8932bba5374e2cf49",
           "manifest": "5693712dfb76ade462fb7c32c0490a69e5f29ee3062acaed30dc6ecb0c7235d7",
           "assignment": "b093150af1b3a858003d3c67fae63756368b1ec805ea3d74b65aab06e9628bf7",
           "plan": "ea61cc9237ab5dbec9edc4453e708cdfbddbe61cfd5938c5b69fdd5d909950b5",
           "challenge": "679f0e68d4fd3b554f81e278e7d25c8ebb0e986d4061a24484f304d1f567809d",
           "activity": "ad5940d6df0b046b10dbf1b2b283ae9e19c778819fc168f9585c86e4344525b4",
           "hardware": "4336e345aacee8e4814d45db7d75f02665857af7bf7c282b98cdf081505f5984"},
}
PAPER_FILES = {
    "src/fmb/contracts/paper/protocol.json": "4b475590220bd4815fc45854dff76d1df15bec3751bd6afc021d9f5ddcb09751",
    "src/fmb/contracts/paper/collection.json": "4df6572d2f013ecc78e4db861989dfe07e7e996bf8089e9bd31c47764c5ef817",
    "src/fmb/contracts/paper/artifact_families.json": "41b78010ae7062cdf6f7ee8439f3c4d53af2d54b5e7c843474f9d56ad146b34d",
    "src/fmb/generation/populations.pilot-i1-20260918.json":
        "3cadcd9c5773b563a46e8bb8c932c33c8293f8ea019658ace0fa43866d15c0a2",
    "src/fmb/generation/populations.pilot-i2-20260918.json":
        "1053f7677975b78e02cdb1c516abdd8482e7cea3fcadfa1e6eb886fca7ac8303",
    "src/fmb/generation/populations.pilot-i3-20260918.json":
        "8c117d2e8ab430a6c72357f026a4100f209aa74b489239e71c4503d76cc06aa7",
    "src/fmb/contracts/questions/BQ-DELETE-01.json": "0525420e645559ce191ba923202a81e9d4378286684c69828c159e79dd56f454",
    "src/fmb/contracts/questions/BQ-DIRECTORY-01.json": "a540b240fadbe3afe603d0fec63e794532ccc58eb292b7ec6fbfbcfa982d5fea",
    "src/fmb/contracts/questions/BQ-EXEC-01.json": "3eae38ae57222f08ab7a117c78a711c52c09286a05f2f6405f9ffd8de568010b",
    "src/fmb/contracts/questions/BQ-FILE-01.json": "589ae19227d37843db108b4f3168b7705813a4a8bf91971f56bb837fd49aa1fc",
    "src/fmb/contracts/questions/BQ-LOG-01.json": "5772bc48a2a5a487960df199aedf439507cbcc296ff7bcedd860291635f09edc",
    "src/fmb/contracts/questions/BQ-SHELLBAG-01.json": "fea0ff9722ff86a1acf4f460a125e2601f2c77bbdefaf5e510148a5cc0277a5b",
    "src/fmb/contracts/questions/BQ-STREAM-01.json": "e76df836ee4ec661781723053c11516877c7347802bdc968d6db8bcfe72de89b",
    "src/fmb/contracts/questions/BQ-TIME-01.json": "59a0ecd0b2106d2e3dde8ba79dac9c3a784b47f6f504cf24e5d48d660223fd29",
    "src/fmb/contracts/questions/BQ-USB-01.json": "dd7a92324932e0de6a2c20e6e955087f5de90485531bccec816a7a6ff5ef8cdb",
}


def _scrub(value):
    if isinstance(value, dict):
        return {key: "<helper>" if key in {"native_helper_payload", "native_helper_sha256"} else _scrub(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(_scrub(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("name", sorted(PLANS))
def test_the_paper_images_generate_from_the_released_plans(name):
    image = image_files.load(ROOT / "images" / f"{name}.json")
    config = recipe.paper_config(name)
    contract = recipe.resolved_contract(config)
    manifest = population.build_public_manifest(experiment="full_scale", seed=image.seed, contract=contract)
    assignment = population.select_private_assignment(manifest, entropy=bytes(range(32)))
    plan = population.build_guest_plan(manifest, assignment, case="positive")
    assert {"config": _digest(config), "qemu": _digest(recipe.paper_config(name, "qemu", "fmb/windows-11-x64")),
            "manifest": manifest["manifest_sha256"], "assignment": _digest(assignment), "plan": _digest(plan),
            "challenge": _digest(recipe._factual_challenge_plan(config, plan, manifest)),
            "activity": _digest(recipe.resolved_activity(image.seed, count=12)),
            "hardware": _digest(recipe.resolved_hardware(image.seed))} == PLANS[name]


def test_an_image_of_your_own_with_a_paper_population_leaves_the_paper_plan_alone():
    population.register_population_contract(
        population.load_population_contract(ROOT / "src/fmb/generation/populations.pilot-i3-20260918.json"))
    test_the_paper_images_generate_from_the_released_plans("I3")


@pytest.mark.parametrize("name", sorted(PAPER_FILES))
def test_the_files_that_define_the_paper_are_unchanged(name):
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == PAPER_FILES[name]
