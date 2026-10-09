import json
from pathlib import Path

import pytest

from fmb.collection import usb_volume
from fmb.collection.analysis import collect_evidence_index
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import write_json
from fmb.core.truth_guard import public_generation_files, system_image, truth_blind_reads
from fmb.pipeline import stages
from fmb.pipeline.gates import write_gate
from fmb.preparation.native import image_binding

MEDIA = "0123456789ab"


def _row(name):
    return {"file": name, "sha256": "a" * 64, "size_bytes": 1}


def _generation(root: Path, image: str, companion: str) -> Path:
    root.mkdir()
    (root / image).write_bytes(b"system image")
    (root / companion).write_bytes(b"companion image")
    write_json(root / f"media_{MEDIA}.json", {"device_instance_id": "USBSTOR\\Disk\\X&0"})
    write_json(root / "population_manifest.json", {"members": []})
    write_json(root / "ground_truth.json", {"private": True})
    write_json(root / "manifest.json", {"artifacts": [
        {"file": name, "sha256": sha256_file(root / name), "size_bytes": (root / name).stat().st_size}
        for name in (image, companion, f"media_{MEDIA}.json", "population_manifest.json")]})
    return root


def test_the_system_image_is_the_one_top_level_image_the_manifest_records():
    paper = {"artifacts": [_row(name) for name in (
        "full_scale.vmdk", f"media_{MEDIA}.vmdk", f"media_{MEDIA}.json", "native_media.vmdk",
        "population_manifest.json", "factual-checkpoints/checkpoint-04.vmdk")]}
    assert system_image(paper)["file"] == "full_scale.vmdk"
    for name in ("disk.raw", "DISK.IMG", "evidence.dd", "laptop.vmdk"):
        assert system_image({"artifacts": [_row(name), _row(f"media_{MEDIA}.raw")]})["file"] == name


@pytest.mark.parametrize("manifest", [
    {}, {"artifacts": None}, {"artifacts": [_row("population_manifest.json")]},
    {"artifacts": [_row("a.raw"), _row("b.dd")]}, {"artifacts": [_row("disk.e01")]},
    {"artifacts": [_row("nested/disk.raw")]}, {"artifacts": [_row(f"media_{MEDIA}.img")]}, [],
])
def test_a_manifest_without_exactly_one_system_image_is_refused(manifest):
    with pytest.raises(ValueError, match="exactly one system image"):
        system_image(manifest)


def test_g1_and_the_truth_guard_take_a_raw_system_image_from_the_manifest(tmp_path):
    generation = _generation(tmp_path / "generation", "disk.raw", f"media_{MEDIA}.img")
    g1 = stages.evidence_gate(generation, "mine-01")
    assert Path(g1["system_image"]["path"]).name == "disk.raw"
    assert g1["system_image"]["sha256"] == sha256_file(generation / "disk.raw")
    assert [Path(row["image"]["path"]).name for row in g1["companion_media"]] == [f"media_{MEDIA}.img"]
    assert sorted(Path(p).name for p in g1["readable_paths"]) == sorted(
        ["disk.raw", f"media_{MEDIA}.img", f"media_{MEDIA}.json", "manifest.json", "population_manifest.json"])
    write_gate(tmp_path / "run", "G1", g1)
    with truth_blind_reads(generation, "disk.raw") as guard:
        assert (generation / "disk.raw").read_bytes() == b"system image"
        assert (generation / f"media_{MEDIA}.img").read_bytes() == b"companion image"
        with pytest.raises(PermissionError, match="truth-blind"):
            (generation / "ground_truth.json").read_bytes()
    assert guard["denied"] == [str((generation / "ground_truth.json").resolve())]
    with truth_blind_reads(generation), pytest.raises(PermissionError, match="truth-blind"):
        (generation / "disk.raw").read_bytes()


def test_the_guard_reads_no_manifest_and_allows_the_named_image_only(tmp_path):
    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / "manifest.json").write_text("not json")
    assert generation.resolve() / "full_scale.vmdk" in public_generation_files(generation)
    allowed = public_generation_files(generation, "disk.dd")
    assert generation.resolve() / "disk.dd" in allowed and generation.resolve() / "full_scale.vmdk" not in allowed


@pytest.mark.parametrize("name", ["disk.raw", "full_scale.vmdk"])
@pytest.mark.parametrize("other_read", [False, True])
def test_native_collection_may_read_only_the_image_it_was_given(tmp_path, monkeypatch, name, other_read):
    from fmb.collection import paper_collection
    from fmb.preparation.native import collect_native

    generation = tmp_path / "generated"
    generation.mkdir()
    evidence = generation / name
    evidence.write_bytes(b"public image")
    (generation / "other.raw").write_bytes(b"undeclared image")

    def collect(args, *, profile):
        assert args.evidence.read_bytes() == b"public image"
        if other_read:
            (generation / "other.raw").read_bytes()

    monkeypatch.setattr(paper_collection, "collect", collect)
    if other_read:
        with pytest.raises(PermissionError, match="truth-blind"):
            collect_native(evidence=evidence, output=tmp_path / "collection", windows_parsers=tmp_path / "parsers")
    else:
        collect_native(evidence=evidence, output=tmp_path / "collection", windows_parsers=tmp_path / "parsers")
    receipt = json.loads((tmp_path / "collection-truth-guard.json").read_text())
    assert receipt["status"] == ("failed" if other_read else "completed")
    assert receipt["generation_files_opened"] == [str(evidence.resolve())]
    assert receipt["denied_private_reads"] == ([str((generation / "other.raw").resolve())] if other_read else [])


def test_a_collection_binds_to_a_raw_system_image(tmp_path):
    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / "disk.img").write_bytes(b"image")
    image = sha256_file(generation / "disk.img")
    write_json(generation / "manifest.json", {"artifacts": [{"file": "disk.img", "sha256": image, "size_bytes": 5}]})
    analysis = tmp_path / "analysis"
    (analysis / "factual-supplement").mkdir(parents=True)
    write_json(analysis / "factual-collection.json", {"evidence": "/elsewhere/disk.img", "evidence_index_sha256": "7" * 64})
    for name in ("native-surface-preparation.json", "public-population-binding.json"):
        write_json(analysis / "factual-supplement" / name, {"evidence_sha256": image})
    assert image_binding(analysis=analysis, generation=generation)["image"] == "disk.img"
    write_json(analysis / "factual-collection.json", {"evidence": "/elsewhere/full_scale.vmdk",
                                                      "evidence_index_sha256": "7" * 64})
    with pytest.raises(ValueError, match="not the generation's system image"):
        image_binding(analysis=analysis, generation=generation)


@pytest.mark.parametrize("name,accepted", [("disk.raw", True), ("disk.IMG", True), ("disk.dd", True),
                                           ("full_scale.vmdk", True), ("disk.e01", False), ("disk.vhdx", False)])
def test_collection_accepts_vmdk_and_raw_images_only(tmp_path, name, accepted):
    evidence = tmp_path / name
    evidence.write_bytes(b"image")
    message = "bound public population" if accepted else "requires an existing VMDK or raw"
    with pytest.raises(ValueError, match=message):
        collect_evidence_index(evidence, profile={}, output_dir=tmp_path / "out", run_id="run",
                               windows_parsers=None)


@pytest.mark.parametrize("binding,companion,accepted", [
    (f"media_{MEDIA}.json", f"media_{MEDIA}.vmdk", True), (f"media_{MEDIA}.json", f"media_{MEDIA}.raw", True),
    (f"media_{MEDIA}.json", f"media_{MEDIA}.dd", True), (f"media_{MEDIA}.json", "media_ba9876543210.raw", False),
    (f"media_{MEDIA}.json", f"media_{MEDIA}.json", False), (f"media_{MEDIA}.json", f"media_{MEDIA}.e01", False),
    ("native_media_binding.json", "native_media.vmdk", True), ("native_media_binding.json", "native_media.raw", False),
])
def test_a_companion_medium_may_be_raw_when_named_after_its_binding(binding, companion, accepted):
    assert usb_volume._companion_of(binding, companion) is accepted


def test_a_generated_folder_keeps_exactly_its_former_readable_files(tmp_path):
    generation = _generation(tmp_path / "generation", "full_scale.vmdk", f"media_{MEDIA}.vmdk")
    names = {"manifest.json", "population_manifest.json", "population-manifest.json",
             "factual-challenge-population.json", "full_scale.vmdk", "native_media.vmdk", "native_media_binding.json",
             f"media_{MEDIA}.vmdk", f"media_{MEDIA}.json"}
    expected = {generation.resolve() / name for name in names}
    image = system_image(json.loads((generation / "manifest.json").read_text()))["file"]
    assert image == "full_scale.vmdk"
    assert public_generation_files(generation) == public_generation_files(generation, image) == expected
