from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path

import pytest

from fmb.analysis.catalog import techniques_for_question
from fmb.analysis.deterministic import _prefetch
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.index.adapters.execution import pecmd_prefetch_parser_run


def _parse(tmp_path: Path, paths: list[str], *, active: bool = False):
    source = tmp_path / "pecmd.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ExecutableName", "FilesLoaded", "RunCount", "LastRun"])
        writer.writerow(["RUNNER.EXE", "|".join(paths), 2, "2026-01-01 12:00:00"])
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    return pecmd_prefetch_parser_run(
        csv_path=source,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={
            "row_count": 2,
            "mft_volume_id": "volume:test",
            "indexed_volumes": {"c", "d"},
            "active_full_paths": {r"present\runner.exe"} if active else set(),
            "active_basenames": {"runner.exe"} if active else set(),
            "path_absence_check_supported": True,
        },
    )


def _input(run, *, scope=None):
    run["coverage_scope"] = scope or {"kind": "prefetch"}
    return build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "public-prefetch-fixture",
            "parser_runs": [
                run,
                {
                    "parser_kind": "ntfs_mft",
                    "status": "consumed",
                    "coverage_status": "complete",
                    "observations": [],
                },
            ],
        },
        techniques_for_question("Q-EXEC-01")[0],
    )


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("other", [r"C:\Present\RUNNER.EXE", r"D:\Missing\RUNNER.EXE"])
def test_same_basename_paths_never_certify_the_first_executable(
    tmp_path: Path, reverse: bool, active: bool, other: str,
) -> None:
    paths = [r"C:\Missing\RUNNER.EXE", other]
    run = _parse(tmp_path, paths[::-1] if reverse else paths, active=active)
    row = run["observations"][0]
    assert row["subject_ref"] == "RUNNER.EXE"
    assert row["fields"]["executable_path"] == ""
    assert row["fields"]["mft_active_presence_check_supported"] is False
    assert row["fields"]["mft_active_presence_status"] == "active_mft_absence_undecidable"
    assert row["fields"]["files_loaded"] == "|".join(paths[::-1] if reverse else paths)
    result = analyze_input(_input(run))
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "prefetch_executable_identity_ambiguous"


@pytest.mark.parametrize("active", [False, True])
def test_one_path_with_case_and_prefix_variants_is_still_resolved(
    tmp_path: Path, active: bool,
) -> None:
    run = _parse(
        tmp_path,
        [r"C:\Present\RUNNER.EXE", "c:/present/runner.exe", r"\\?\C:\PRESENT\RUNNER.EXE"],
        active=active,
    )
    row = run["observations"][0]
    assert row["subject_ref"] == r"C:\Present\RUNNER.EXE"
    assert row["fields"]["executable_identity_basis"] == "referenced_executable_path"
    assert analyze_input(_input(run)).assessments[0].outcome == (
        "not_supported" if active else "supported"
    )


@pytest.mark.parametrize(
    "policy", [{"application_prefetch_enabled": False}, {"sysmain_disabled": True}],
)
@pytest.mark.parametrize("active", [False, True])
def test_retained_prefetch_is_not_invalidated_by_current_disabled_policy(
    tmp_path: Path, policy: dict, active: bool,
) -> None:
    run = _parse(tmp_path, [r"C:\Present\RUNNER.EXE"], active=active)
    result = analyze_input(_input(run, scope={"kind": "prefetch", **policy}))
    assert result.assessments[0].outcome == ("not_supported" if active else "supported")
    assert result.assessments[0].reason_code != "prefetch_disabled"


@pytest.mark.parametrize(
    "policy", [{"application_prefetch_enabled": False}, {"sysmain_disabled": True}],
)
def test_disabled_policy_still_limits_absence_and_does_not_rescue_bad_records(
    tmp_path: Path, policy: dict,
) -> None:
    run = _parse(tmp_path, [r"C:\Present\RUNNER.EXE"])
    value = _input(run, scope={"kind": "prefetch", **policy})
    no_record_subject = replace(value.candidate_roster.subjects[0], observation_ids=())
    missing = _prefetch(value, no_record_subject)
    assert (missing.outcome, missing.reason_code) == ("indeterminate", "prefetch_disabled")
    run["observations"][0]["fields"]["run_count"] = 0
    result = analyze_input(_input(run, scope={"kind": "prefetch", **policy}))
    assert result.assessments[0].outcome == "indeterminate"
    assert result.assessments[0].reason_code == "prefetch_record_contract_unavailable"
