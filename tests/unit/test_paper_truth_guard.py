import json
import pytest
from fmb.core.truth_guard import truth_blind_reads
from fmb.preparation.native import collect_native


@pytest.mark.parametrize(
    "name",
    [
        "ground_truth.json",
        "finding_reference.json",
        "factual-challenge-plan.json",
        "factual-challenge-receipt.json",
        "run.log",
        "private-generation.json",
        "pilot-materialization.json",
    ],
)
def test_guard_blocks_actual_private_opens_and_aliases(tmp_path, name):
    generation = tmp_path / "generated"
    generation.mkdir()
    private = generation / name
    private.write_text("private operation data")
    alias = tmp_path / "innocent.json"
    alias.symlink_to(private)
    public = generation / "manifest.json"
    public.write_text("{}")
    with truth_blind_reads(generation) as state:
        assert public.read_text() == "{}"
        for path in (private, alias):
            with pytest.raises(PermissionError, match="truth-blind"):
                path.read_bytes()
        assert str(public) in state["opened"]
    assert private.read_text() == "private operation data"


def test_public_binding_alias_cannot_bypass_private_guard(tmp_path):
    private = tmp_path / "operation-data.bin"
    private.write_bytes(b"private")
    alias = tmp_path / "media_000000000001.json"
    alias.symlink_to(private)
    with truth_blind_reads(tmp_path):
        with pytest.raises(PermissionError):
            alias.read_bytes()


@pytest.mark.parametrize(
    "name",
    [
        "private-generation.json",
        "recipe.json",
        "pilot-materialization.json",
        "private-native.log",
    ],
)
def test_guard_refuses_private_inputs_outside_the_generation_directory(tmp_path, name):
    generation = tmp_path / "generated"
    generation.mkdir()
    private = tmp_path / name
    private.write_text("private operation data")
    with (
        truth_blind_reads(generation),
        pytest.raises(PermissionError, match="truth-blind"),
    ):
        private.read_bytes()


@pytest.mark.parametrize("private_read", [False, True])
def test_collection_guard_wraps_actual_collector_boundary(
    tmp_path, monkeypatch, private_read
):
    from fmb.collection import paper_collection

    generation = tmp_path / "generated"
    generation.mkdir()
    evidence = generation / "full_scale.vmdk"
    evidence.write_bytes(b"public image")
    (generation / "ground_truth.json").write_text("{}")

    def collect(args, *, profile):
        assert len(profile["questions"]) == 9
        assert args.evidence.read_bytes() == b"public image"
        if private_read:
            (generation / "ground_truth.json").read_text()

    monkeypatch.setattr(paper_collection, "collect", collect)
    output = tmp_path / "collection"
    if private_read:
        with pytest.raises(PermissionError, match="truth-blind"):
            collect_native(evidence=evidence, output=output, windows_parsers=tmp_path / "windows-parsers")
    else:
        collect_native(evidence=evidence, output=output, windows_parsers=tmp_path / "windows-parsers")
    receipt = json.loads((tmp_path / "collection-truth-guard.json").read_text())
    assert receipt["status"] == ("failed" if private_read else "completed")
    assert bool(receipt["denied_private_reads"]) == private_read
    assert receipt["inference_calls"] == 0


def test_collection_profile_resolution_failure_finishes_guard_receipt(tmp_path, monkeypatch):
    from fmb import profiles
    from fmb.collection import paper_collection

    generation = tmp_path / "generated"
    generation.mkdir()
    evidence = generation / "full_scale.vmdk"
    evidence.write_bytes(b"public image")
    output = tmp_path / "collection"
    collected = []

    def invalid_profile():
        raise ValueError("malformed fixed collection profile")

    monkeypatch.setattr(profiles, "resolve_paper_profile", invalid_profile)
    monkeypatch.setattr(paper_collection, "collect", lambda *a, **kw: collected.append(a))
    with pytest.raises(ValueError, match="malformed fixed collection profile"):
        collect_native(evidence=evidence, output=output, windows_parsers=tmp_path / "windows-parsers")

    receipt = json.loads((tmp_path / "collection-truth-guard.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["finished_utc"]
    assert receipt["error_type"] == "ValueError"
    assert receipt["error"] == "malformed fixed collection profile"
    assert receipt["generation_files_opened"] == receipt["denied_private_reads"] == []
    assert receipt["inference_calls"] == 0
    assert collected == []
    assert not output.exists()
