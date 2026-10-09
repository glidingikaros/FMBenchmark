from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path

import pytest

from fmb.collection import analysis, paper_collection, paper_host
from fmb.core.errors import FmbInputError
from fmb.preparation import native
import fmb.profiles


@pytest.fixture
def collection_boundary(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence.vmdk"
    evidence.write_bytes(b"small public test evidence")
    output = tmp_path / "analysis"
    parsers = tmp_path / "windows-parsers"
    profile = fmb.profiles.resolve_paper_profile()
    guard = {"opened": set(), "denied": []}
    monkeypatch.setattr(native, "truth_blind_reads", lambda path: nullcontext(guard))
    monkeypatch.setattr(fmb.profiles, "resolve_paper_profile", lambda: profile)
    monkeypatch.setattr(paper_host, "acquire_evidence_image_run_lock", lambda **kw: nullcontext())
    monkeypatch.setattr(paper_host, "default_current_root", lambda: tmp_path / "current")
    monkeypatch.setattr(paper_host, "preflight", lambda **kw: {"status": "passed"})
    monkeypatch.setattr(paper_host, "sha256_file", lambda path: "b" * 64)
    monkeypatch.setattr(paper_host, "validate_host_collector_bundle", lambda **kw: {"status": "passed"})
    monkeypatch.setattr(paper_host, "required_artifact_globs", lambda *a: [])
    monkeypatch.setattr(paper_host, "import_tool_bundle", lambda args: {"evidence_index": {"test": True}})
    monkeypatch.setattr(paper_host, "write_import_outputs", lambda *a: (tmp_path / "index.json", None))

    def setup(boundary, primary=None):
        def collected(*args, **kwargs):
            if primary is not None:
                raise primary
            return {"test": True}

        if boundary == "truth_guard":
            module = native
            receipt = output.with_name("analysis-truth-guard.json")
            monkeypatch.setattr(paper_collection, "collect", collected)
            def invoke():
                return native.collect_native(evidence=evidence, output=output, windows_parsers=parsers)
        elif boundary == "timing":
            module = paper_collection
            receipt = output.with_name("analysis-timing.json")
            monkeypatch.setattr(analysis, "collect_evidence_index", collected)
            def invoke():
                return paper_collection.collect(
                    Namespace(evidence=evidence, output=output, windows_parsers=parsers, host_toolchain_root=None),
                    profile=profile,
                )
        else:
            module = paper_host
            receipt = output / "collection.json"
            monkeypatch.setattr(paper_host, "run_host_collector_extraction", collected)
            def invoke():
                return paper_host.collect_host(
                    profile=profile, evidence=evidence, output=output, run_id="test",
                    windows_parsers=parsers, expected_sha256="b" * 64,
                    bounded_content_subject_limit=1, bounded_i30_directory_paths=None,
                )
        original_write = module.write_json
        write_failure = OSError("destination disappeared")
        writes = []

        def write(path, record):
            if Path(path) == receipt:
                writes.append(dict(record))
                if len(writes) == 2:
                    raise write_failure
            return original_write(path, record)

        monkeypatch.setattr(module, "write_json", write)
        return Namespace(invoke=invoke, receipt=receipt, writes=writes, write_failure=write_failure)

    return Namespace(setup=setup, guard=guard)


@pytest.mark.parametrize("boundary", ["truth_guard", "timing", "host"])
@pytest.mark.parametrize("error_type", [RuntimeError, OSError, KeyboardInterrupt])
def test_final_record_failure_preserves_initiating_error_and_notes(collection_boundary, boundary, error_type):
    primary = error_type("initiating extraction failure")
    primary.add_note("owned VM cleanup state is uncertain")
    case = collection_boundary.setup(boundary, primary)
    with pytest.raises(error_type) as caught:
        case.invoke()
    assert caught.value is primary
    assert primary.__notes__[0] == "owned VM cleanup state is uncertain"
    assert str(case.receipt) in primary.__notes__[1]
    assert "OSError: destination disappeared" in primary.__notes__[1]
    assert case.writes[1]["status"] == "failed"
    assert case.writes[1]["error_type"] == error_type.__name__


@pytest.mark.parametrize("boundary", ["truth_guard", "timing", "host"])
def test_final_record_failure_after_success_is_still_failure(collection_boundary, boundary):
    case = collection_boundary.setup(boundary)
    with pytest.raises(OSError) as caught:
        case.invoke()
    assert caught.value is case.write_failure
    assert case.writes[1]["status"] == "completed"


def test_image_that_changes_during_collection_is_refused(collection_boundary, monkeypatch):
    case = collection_boundary.setup("host")
    digests = iter(["b" * 64, "c" * 64])
    monkeypatch.setattr(paper_host, "sha256_file", lambda path: next(digests, "c" * 64))
    with pytest.raises(FmbInputError, match="changed during collection"):
        case.invoke()
    assert case.writes[1]["status"] == "failed"


def test_suppressed_private_read_is_not_masked_by_final_record_failure(collection_boundary):
    collection_boundary.guard["denied"].append("private-generation.json")
    case = collection_boundary.setup("truth_guard")
    with pytest.raises(ValueError, match="collector attempted a private read") as caught:
        case.invoke()
    assert case.writes[1]["error_type"] == "SuppressedPrivateRead"
    assert "OSError: destination disappeared" in caught.value.__notes__[0]


