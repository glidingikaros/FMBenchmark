import json

import pytest
from fmb.collection import paper_host as host
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import read_json
from fmb.profiles import resolve_paper_profile


def mocked(tmp_path, monkeypatch, failure=None):
    evidence = tmp_path / "image.vmdk"
    evidence.write_bytes(b"unchanged evidence")
    events = []
    kwargs_profile = resolve_paper_profile()
    monkeypatch.setattr(host, "default_current_root", lambda: tmp_path / "runtime")

    def preflight(**kwargs):
        assert kwargs["profile"] is kwargs_profile
        return {"status": "passed", "host": {"available": True}}

    monkeypatch.setattr(host, "preflight", preflight)

    def extract(**kwargs):
        events.append("extract")
        selection = kwargs_profile["collection_declaration"]["collection"]["kape"]
        assert kwargs["targets"] == selection["target_names"]
        assert kwargs["modules"] == selection["module_names"]
        assert kwargs["args"].expected_definitions_sha256 == (
            kwargs_profile["collection_declaration"]["kape_definitions"]["tree_sha256"]
        )
        assert kwargs["evidence_sha256"] == sha256_file(evidence)
        if failure == "extract":
            raise RuntimeError("failed extraction")
        return {"backend": "host-collector"}

    def validate(**kwargs):
        events.append("validate")
        assert kwargs["required_artifact_globs"]
        if failure == "validate":
            raise ValueError("bad native bundle")
        return {"status": "passed"}

    def materialize(config):
        events.append("import")
        assert config.require_source_hash_verified is True
        assert config.bounded_content_subject_limit == 24
        assert config.bounded_i30_directory_paths == ("directory",)
        return {
            "evidence_index": {"shared": "native"},
            "import_report": {"status": "materialized"},
        }

    monkeypatch.setattr(host, "run_host_collector_extraction", extract)
    monkeypatch.setattr(host, "validate_host_collector_bundle", validate)
    monkeypatch.setattr(host, "import_tool_bundle", materialize)
    kwargs = dict(
        profile=kwargs_profile,
        evidence=evidence,
        output=tmp_path / "collection",
        run_id="test",
        windows_parsers=tmp_path / "windows-parsers",
        expected_sha256=sha256_file(evidence),
        bounded_content_subject_limit=24,
        bounded_i30_directory_paths=("directory",),
    )
    return kwargs, events


@pytest.mark.parametrize("failure", [None, "extract", "validate", "hash"])
def test_collection_validation_is_mandatory_and_failure_releases_owner(
    tmp_path, monkeypatch, failure
):
    kwargs, events = mocked(tmp_path, monkeypatch, failure)
    if failure == "hash":
        kwargs["expected_sha256"] = "0" * 64
    if failure:
        with pytest.raises(Exception):
            host.collect_host(**kwargs)
    else:
        assert host.collect_host(**kwargs) == {"shared": "native"}
    receipt = read_json(kwargs["output"] / "collection.json")
    assert receipt["status"] == ("failed" if failure else "completed")
    assert receipt["truth_sources_used"] == []
    assert receipt["elapsed_seconds"] >= 0
    assert not list((tmp_path / "runtime").rglob("*.lock"))
    assert events == (
        {"hash": [], "extract": ["extract"], "validate": ["extract", "validate"]}.get(
            failure, ["extract", "validate", "import"]
        )
    )
    assert kwargs["evidence"].read_bytes() == b"unchanged evidence"
    if failure != "hash":
        assert (kwargs["output"] / "collection-profile.json").read_text() == (
            json.dumps(kwargs["profile"]["collection_declaration"], indent=2) + "\n"
        )
    with pytest.raises(FileExistsError):
        host.collect_host(**kwargs)
