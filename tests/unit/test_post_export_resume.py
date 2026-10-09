from __future__ import annotations
import hashlib


import importlib.util


import json


from pathlib import Path


import pytest


TESTS = Path(__file__).resolve().parent


ROOT = TESTS.parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pipeline():
    return load_module("post_export_resume_pipeline", ROOT / "src/fmb/generation" / "pipeline.py")


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def journal_entries(output_dir: Path) -> list[dict]:
    paths = sorted((output_dir / "post-export").glob("[0-9][0-9]-*.json"))
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


def test_journal_hashes_once_per_boundary_and_enforces_read_only(pipeline, tmp_path) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"one")
    hashed: list[str] = []

    def hasher(path):
        hashed.append(Path(path).name)
        return sha256(path)

    journal = pipeline.PostExportJournal(tmp_path / "post-export", hasher=hasher)
    journal.run("first", image, lambda: image.write_bytes(b"two"))
    journal.run("second", image, lambda: None, read_only=True)
    assert hashed == ["image.bin", "image.bin", "image.bin"]
    with pytest.raises(RuntimeError, match="read-only post-export intervention third changed"):
        journal.run("third", image, lambda: image.write_bytes(b"three"), read_only=True)
    entries = journal_entries(tmp_path)
    assert [entry["status"] for entry in entries] == ["completed", "completed", "failed"]
    assert entries[1]["sha256_before"] == entries[0]["sha256_after"] == entries[1]["sha256_after"]

    reloaded = pipeline.PostExportJournal(tmp_path / "post-export", hasher=hasher)
    with pytest.raises(ValueError, match="differs from its journaled state"):
        reloaded.verify_images(tmp_path)


@pytest.mark.parametrize("failure_boundary", ["action", "checkpoint"])
def test_resume_preserves_and_refuses_unsealed_created_image(pipeline, tmp_path, failure_boundary):
    image = tmp_path / "native_media.vmdk"
    journal_dir = tmp_path / "post-export"

    def interrupted():
        raise RuntimeError("public interruption")

    journal = pipeline.PostExportJournal(
        journal_dir, hasher=sha256,
        checkpoint=interrupted if failure_boundary == "checkpoint" else None,
    )

    def create():
        image.write_bytes(b"complete-looking public companion")
        if failure_boundary == "action":
            interrupted()

    with pytest.raises(RuntimeError, match="public interruption"):
        journal.run("native_media_export", image, create, creates_image=True)
    before = image.read_bytes()
    entry_before = (journal_dir / "01-native_media_export.json").read_bytes()
    reloaded = pipeline.PostExportJournal(journal_dir, hasher=sha256)
    with pytest.raises(ValueError, match="unsealed created image.*operator recovery"):
        reloaded.verify_images(tmp_path)
    assert image.read_bytes() == before
    assert (journal_dir / "01-native_media_export.json").read_bytes() == entry_before


def test_interrupted_creation_without_output_can_retry_but_completed_creation_is_not_repeated(pipeline, tmp_path):
    image = tmp_path / "native_media.vmdk"
    directory = tmp_path / "post-export"
    journal = pipeline.PostExportJournal(directory, hasher=sha256)

    def interrupted():
        raise RuntimeError("no published output")

    with pytest.raises(RuntimeError, match="no published output"):
        journal.run("native_media_export", image, interrupted, creates_image=True)
    assert not image.exists()
    resumed = pipeline.PostExportJournal(directory, hasher=sha256)
    resumed.verify_images(tmp_path)
    resumed.run("native_media_export", image, lambda: image.write_bytes(b"public converted bytes"), creates_image=True)
    completed = pipeline.PostExportJournal(directory, hasher=sha256)
    completed.verify_images(tmp_path)
    completed.run("native_media_export", image, lambda: pytest.fail("a verified completed conversion must not repeat"), creates_image=True)
    assert image.read_bytes() == b"public converted bytes"
    (entry,) = journal_entries(tmp_path)
    assert entry["status"] == "completed" and entry["attempt"] == 2
    assert entry["previous_attempts"][0]["status"] == "failed"


def test_native_media_export_does_not_adopt_an_unjournaled_existing_file(pipeline, tmp_path):
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.run_command = lambda *_args, **_kwargs: pytest.fail("existing output must fail before conversion")
    image = tmp_path / "native_media.vmdk"
    image.write_bytes(b"unsealed companion")
    with pytest.raises(FileExistsError, match="refusing to overwrite generated image"):
        instance.convert_and_publish(tmp_path / "source.vmdk", image, "vmdk")
    assert image.read_bytes() == b"unsealed companion"


@pytest.mark.parametrize('change', [None, {'provider': 'virtualbox'}, {'keep_vm': True},
                                   {'native_media_source': 'old-media.vmdk'}, {'case': 'benign'}])
def test_resume_restores_only_the_fixed_paper_checkpoint(pipeline, tmp_path, monkeypatch, change):
    state = {
        'schema_version': pipeline.POST_EXPORT_STATE_SCHEMA, 'provider': 'vmware_desktop',
        'experiment': 'full_scale', 'scenario': 'fixed-roster', 'case': 'positive',
        'export_format': 'vmdk', 'keep_vm': False, 'system_image': 'full_scale.vmdk',
        'native_media_source': None, 'native_media_binding': [],
        'public_population_manifest': False, 'recipe_directory': None,
        'guest_plan': {'native_pilot_profile': 'pilot_min.v1',
                       'scenario_inputs': {'usbstor_setupapi_discrepancy_01': {}}}, 'ground_truth': None,
        'native_media_sources': [{'path': f'media-{i}.vmdk', 'unit': i, 'port': i} for i in range(3)],
    }
    if change:
        state.update(change)
    directory = tmp_path / pipeline.POST_EXPORT_DIRECTORY
    directory.mkdir()
    (directory / pipeline.POST_EXPORT_STATE_NAME).write_text(json.dumps(state))
    monkeypatch.setattr(pipeline.GenerationPipeline, '_bind_host_runtime', lambda self: None)
    if change:
        with pytest.raises(ValueError, match='fixed paper configuration'):
            pipeline.GenerationPipeline.resume_post_export(tmp_path)
    else:
        restored = pipeline.GenerationPipeline.resume_post_export(tmp_path)
        assert restored.post_export_state() == state
        assert len(restored.native_media_sources) == 3
