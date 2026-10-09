from __future__ import annotations

import json
from pathlib import Path

import pytest

from fmb.index.adapters.logfile import (
    _logfile_bound_updates,
    _logfile_parse_complete,
)
from fmb.index.scanners.logfile_runtime import logfile_runtime_availability, run_logfile_driver

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "logfile"

pytestmark = pytest.mark.skipif(
    not logfile_runtime_availability().get("available"),
    reason="the locked dfir_ntfs environment is not installed on this machine",
)


def _document(tmp_path: Path, name: str, **kwargs: object) -> dict[str, object]:
    source = FIXTURES / name
    logfile = tmp_path / "$LogFile"
    logfile.write_bytes(source.read_bytes())
    return run_logfile_driver(logfile, output_path=tmp_path / f"{name}.json", timeout_seconds=60, **kwargs)


def test_an_update_of_an_earlier_incarnation_is_not_bound(tmp_path: Path) -> None:
    document = _document(tmp_path, "lifecycle.logfile.bin")

    assert document["parse"]["page_coverage_complete"] is True
    assert document["parse"]["lifecycle_record_count"] >= 1
    updates, diagnostics = _logfile_bound_updates(document, raw_mft_path=FIXTURES / "current.mft.bin", mft_context=None)

    assert updates == []
    assert diagnostics["unbound_reasons"].get("entry_reinitialised_after_update") == 1


def test_a_failed_record_page_withholds_every_witness(tmp_path: Path) -> None:
    document = _document(tmp_path, "corrupt-lifecycle.logfile.bin")

    assert document["parse"]["record_page_failure_count"] >= 1
    assert document["parse"]["page_coverage_complete"] is False
    assert _logfile_parse_complete(document) is False
    updates, diagnostics = _logfile_bound_updates(document, raw_mft_path=FIXTURES / "current.mft.bin", mft_context=None)

    assert updates == []
    assert diagnostics["witnesses_withheld"] == "page_coverage_incomplete"


def test_a_record_cap_withholds_witnesses_but_keeps_lifecycle_records(tmp_path: Path) -> None:
    document = _document(tmp_path, "lifecycle.logfile.bin", max_records=1)

    assert document["parse"]["records_truncated"] is True
    assert document["parse"]["lifecycle_record_count"] >= 1
    updates, diagnostics = _logfile_bound_updates(document, raw_mft_path=FIXTURES / "current.mft.bin", mft_context=None)

    assert updates == []
    assert diagnostics["witnesses_withheld"] == "records_truncated"


def test_a_completion_from_another_client_never_commits_the_update(tmp_path: Path) -> None:
    document = _document(tmp_path, "client-collision.logfile.bin")

    assert document["parse"]["client_count"] == 2
    assert document["parse"]["multi_client"] is True
    si_updates = [row for row in document["records"] if row["redo_operation_name"] == "UpdateResidentValue"]
    assert si_updates and all(row["transaction_forgotten_lsn"] is None for row in si_updates)
    updates, diagnostics = _logfile_bound_updates(document, raw_mft_path=FIXTURES / "current.mft.bin", mft_context=None)

    assert updates == []
    assert diagnostics["witnesses_withheld"] == "multi_client_unsupported"
    json.dumps(document)
