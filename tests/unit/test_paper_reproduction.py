import hashlib
import json
from pathlib import Path

import pytest

from fmb.core.paper_protocol import paper_protocol
from fmb.generation import population, recipe
from fmb.replication import image_files

ROOT = Path(__file__).resolve().parents[2]

PLANS = {
    "I1": {"config": "4c4da1a79862548600010be3b7d37969bcd16d955b60570cd87d185890c66f0d",
           "qemu": "04c0328313d5d23f6fcbe697e615e56f26dcaa0516ac0cf2944967bedc44e07b",
           "manifest": "5c3006ac96c735f937928108ea5d736dd0f680eb1b104186126ec8c39ad82ffa",
           "assignment": "583403f1af4b5b3abae86e2499cbe2a0fea8a1ff5170bb96cd22bd94ea6d57fd",
           "plan": "472d49d46875564bd8a3f517282f32a53282fbf09ee8b4b6404d0702d274c0d9",
           "challenge": "379b569de8c61f4eb024aa7081fc53266eae627af22eeabf5f349233003cc6b1",
           "activity": "ffddfc78166054c9658fa9395f0c098cd13a61c470cd7f3e9dd484eece020699",
           "hardware": "614df4d305f92a74a81fe891fc6f36d7b6defdc0290f08fdae914be8e44d2ed2"},
    "I2": {"config": "114500104318265e45fed273ce6ad08ccb1ad7f980ddca35da88c4080774c251",
           "qemu": "352cbf1022c7a5ca960439192b864e412cd7c7292a2a6d7cd0d875b82ae62fbf",
           "manifest": "9cec0eed57733ff8f4d976451210820b744a8f8e2224b558019ad60f2f88e046",
           "assignment": "d3206f6dfdbf17b1eb251d0fc981bac5fc896111ed508717d14eb7b98c9a0fed",
           "plan": "0f10f7a0ca85b04bb557785b1c2c4ab76d171d8193ecbe16f2cb6f24de53881a",
           "challenge": "5f30ba78835cf3a216994109f99c1917cc053fac5fda38473e74b44da8f92825",
           "activity": "1f6e7732b5e4666f5358e3b985f6eaea2aaffc80db7784dbbac5e730a0f5f93e",
           "hardware": "26abfdc2a1396000b4f951201f5d34ca8c9f576c18e96db9ed5a6d6923954670"},
    "I3": {"config": "cb3e148c1122f6cc6ff037b899627e9dd2f172447cfccfb799b6f3146949ce6e",
           "qemu": "3afd13dc54b1696bf4b6af53387059183a3ce9039301f0f8932bba5374e2cf49",
           "manifest": "6ef53c9c19b0f92e268f8d61f5bd1c7d2eb8fb22dbd7de9784adde1680ab885b",
           "assignment": "ebb209851a8aa4d4ab5cabbd0c43cf339c2c62673e9ee3872c7ef9df7bbe6664",
           "plan": "ea61cc9237ab5dbec9edc4453e708cdfbddbe61cfd5938c5b69fdd5d909950b5",
           "challenge": "679f0e68d4fd3b554f81e278e7d25c8ebb0e986d4061a24484f304d1f567809d",
           "activity": "ad5940d6df0b046b10dbf1b2b283ae9e19c778819fc168f9585c86e4344525b4",
           "hardware": "4336e345aacee8e4814d45db7d75f02665857af7bf7c282b98cdf081505f5984"},
}
STUDY_MANIFESTS = {
    "I1": "1ab467c3cc5c901be7d5ad90f5fc3647ef1e6812fc34a375f7ec007bd75de845",
    "I2": "a0c51f9306501ee05031fcb9f8547437e92c344e4fcdd49ff079f96f38a2cf29",
    "I3": "5693712dfb76ade462fb7c32c0490a69e5f29ee3062acaed30dc6ecb0c7235d7",
}
PAPER_FILES = {
    "src/fmb/contracts/paper/protocol.json": "4b475590220bd4815fc45854dff76d1df15bec3751bd6afc021d9f5ddcb09751",
    "src/fmb/contracts/paper/collection.json": "4df6572d2f013ecc78e4db861989dfe07e7e996bf8089e9bd31c47764c5ef817",
    "src/fmb/contracts/paper/artifact_families.json": "41b78010ae7062cdf6f7ee8439f3c4d53af2d54b5e7c843474f9d56ad146b34d",
    "src/fmb/generation/populations.pilot-i1-20260918.json":
        "a17358503b246ca30de4024eca60f2a50e163864b570fe2a0accfcf6b5a4916d",
    "src/fmb/generation/populations.pilot-i2-20260918.json":
        "16cdb73359b26f6bc31615a74483ffe7bef4aa437b47fc3d668abab725d5900b",
    "src/fmb/generation/populations.pilot-i3-20260918.json":
        "e5e56ef739d99e33d7793bb8532b6cbe7954c30903695b7dd5e9d4f8d71bc679",
    "src/fmb/contracts/questions/BQ-DELETE-01.json": "a2ce52987fd937d1eec58ff7e322552a6411b1af9babf7e36f9b9d5fe3b02ee0",
    "src/fmb/contracts/questions/BQ-DIRECTORY-01.json": "fa507931c3fa44c68adfbd048ca6b5e78eddb6967bb48b447714955a3d78ffee",
    "src/fmb/contracts/questions/BQ-EXEC-01.json": "044f5b0e77f7721f66bc7eadd68418a3380a526455e6f7cca2aef11be474e905",
    "src/fmb/contracts/questions/BQ-FILE-01.json": "eb5f7a76fbbebb6d6eb0b750788206bd2c8fcca60ad68453ad78b7382be1ff72",
    "src/fmb/contracts/questions/BQ-LOG-01.json": "f481b8adab46d3aef7e1e467300cc7310928b90b7996a36097e3cc2d13b8e91d",
    "src/fmb/contracts/questions/BQ-SHELLBAG-01.json": "ca70938e9b10f5155b32c343d6bf945fa4f550deda9424225a270c413d3e619f",
    "src/fmb/contracts/questions/BQ-STREAM-01.json": "626774c379120ac2470cbc0ca5df1b936cef6f6e2fe5d8f3d6825da71d27a7be",
    "src/fmb/contracts/questions/BQ-TIME-01.json": "f6730435699744dbc8ef23423a25a9d97db8bcc3ca21a08a1d01aa765e3d8b00",
    "src/fmb/contracts/questions/BQ-USB-01.json": "f5193881ac5bfde9801449637fab377b4936bcd2213791b09ffc59e0de3e3115",
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


@pytest.mark.parametrize("name", sorted(PLANS))
def test_the_paper_populations_differ_from_the_study_only_in_their_label(name):
    config = recipe.paper_config(name)
    manifest = population.build_public_manifest(experiment="full_scale", seed=config["population_seed"],
                                                contract=recipe.resolved_contract(config))
    file = Path(paper_protocol()["images"][name]["population_contract"]).name
    study = next(sha for sha, relabelled in population.RELABELLED_CONTRACTS.items() if relabelled == file)
    assert population.relabelled_manifest(manifest, {"contract_sha256": study})["manifest_sha256"] == STUDY_MANIFESTS[name]
