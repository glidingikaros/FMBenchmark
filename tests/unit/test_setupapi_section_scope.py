from __future__ import annotations

from pathlib import Path

import pytest

from fmb.analysis.catalog import techniques_for_question
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.index.adapters.registry import setupapi_parser_run


def _section(day: int, *, device: str = "OTHER", legacy: bool = False) -> str:
    stamp = f"2026/01/{day:02d} 00:00:00.000"
    header = f">>> [Device Install - USBSTOR\\DISK&VEN_PUBLIC\\{device}]\n"
    if legacy:
        return (header + f">>> {stamp}: Section start\n"
                f"<<< [{stamp}: Section end]\n<<< [Exit Status(0x00000000)]\n")
    return (header + f">>> Section start {stamp}\n"
            f"<<< Section end {stamp}\n<<< [Exit status: SUCCESS]\n")


def _run(tmp_path: Path, text: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "setupapi.dev.log"
    source.write_text(text, encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    return setupapi_parser_run(
        log_path=source, normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )


def _assess(run):
    instance = r"USBSTOR\DISK&VEN_PUBLIC\TARGET"
    index = {
        "schema_version": "evidence_index.v1", "run_id": "public-setupapi-scope",
        "parser_runs": [*(run if isinstance(run, list) else [run]), {
            "parser_kind": "windows_usbstor", "status": "consumed",
            "coverage_status": "complete", "observations": [{
                "observation_id": "obs:registry", "artifact_family": "windows.registry.usbstor",
                "observation_type": "usb_device_seen", "subject_ref": instance,
                "source_record_ref": "public-registry:row=1",
                "fields": {"device_instance_id": instance, "serial_number": "TARGET",
                           "control_set": "ControlSet001", "first_install": "2026-01-02 12:00:00"},
            }],
        }],
    }
    return analyze_input(build_analysis_input(index, techniques_for_question("Q-MEDIA-01")[0])).assessments[0]


@pytest.mark.parametrize("legacy", [False, True])
def test_complete_sections_support_only_a_retained_envelope(tmp_path: Path, legacy: bool) -> None:
    run = _run(tmp_path, _section(1, legacy=legacy) + _section(4, legacy=legacy))
    assert run["coverage_status"] == "complete"
    scope = run["coverage_scope"]
    assert scope["window_complete"] is True
    assert scope["window_basis"] == "parse_complete_retained_sections"
    assert scope["complete_section_count"] == 2
    assert _assess(run).outcome == "supported"


@pytest.mark.parametrize("defect", [
    "missing_end", "missing_exit", "end_before_start", "duplicate_start", "duplicate_end",
    "duplicate_exit", "invalid_end_time", "footer_out_of_order", "unframed_start",
    "nonusb_incomplete_tail", "backward_start_order", "within_section_clock_reversal",
])
def test_incomplete_or_reversed_sections_never_certify_missing_identity(
    tmp_path: Path, defect: str,
) -> None:
    text = _section(1) + _section(4)
    if defect == "missing_end":
        text = "\n".join(line for line in text.splitlines() if not line.startswith("<<< Section end"))
    elif defect == "missing_exit":
        text = "\n".join(line for line in text.splitlines() if not line.startswith("<<< [Exit"))
    elif defect == "end_before_start":
        text = text.replace(
            ">>> Section start 2026/01/01 00:00:00.000\n<<< Section end 2026/01/01 00:00:00.000",
            "<<< Section end 2026/01/01 00:00:00.000\n>>> Section start 2026/01/01 00:00:00.000",
        )
    elif defect in {"duplicate_start", "duplicate_end", "duplicate_exit"}:
        prefix = {"duplicate_start": ">>> Section start", "duplicate_end": "<<< Section end",
                  "duplicate_exit": "<<< [Exit"}[defect]
        text = "\n".join(line + ("\n" + line if line.startswith(prefix) else "") for line in text.splitlines())
    elif defect == "invalid_end_time":
        text = text.replace("<<< Section end 2026/01/04 00:00:00.000", "<<< Section end invalid")
    elif defect == "footer_out_of_order":
        text = text.replace("<<< Section end 2026/01/04 00:00:00.000\n<<< [Exit status: SUCCESS]",
                            "<<< [Exit status: SUCCESS]\n<<< Section end 2026/01/04 00:00:00.000")
    elif defect == "unframed_start":
        text = ">>> Section start 2026/01/01 00:00:00.000\n" + text
    elif defect == "nonusb_incomplete_tail":
        text += ">>> [Device Install - PCI\\VEN_PUBLIC]\n>>> Section start 2026/01/05 00:00:00.000\n"
    elif defect == "backward_start_order":
        text = _section(4) + _section(1)
    elif defect == "within_section_clock_reversal":
        text = text.replace("<<< Section end 2026/01/04", "<<< Section end 2026/01/03")
    run = _run(tmp_path, text)
    assert len(run["observations"]) == 2
    assert run["coverage_status"] == "complete"
    assert run["coverage_scope"]["window_complete"] is False
    assert _assess(run).outcome == "indeterminate"


@pytest.mark.parametrize("closed", [False, True])
def test_retained_exact_identity_is_available_even_if_envelope_is_incomplete(
    tmp_path: Path, closed: bool,
) -> None:
    text = _section(4, device="TARGET") + _section(1)
    if not closed:
        text = "\n".join(line for line in text.splitlines() if not line.startswith("<<<"))
    run = _run(tmp_path, text)
    assert run["coverage_scope"]["window_complete"] is False
    decision = _assess(run)
    assert decision.outcome == "not_supported"
    assert decision.reason_code == "consistent_device_identity_observed"


@pytest.mark.parametrize("reverse", [False, True])
def test_untimed_incomplete_retained_file_cannot_disappear_during_scope_merge(
    tmp_path: Path, reverse: bool,
) -> None:
    complete = _run(tmp_path / "complete", _section(1) + _section(4))
    incomplete = _run(tmp_path / "incomplete", ">>> [Device Install - PCI\\VEN_PUBLIC]\n")
    assert incomplete["coverage_scope"]["window_complete"] is False
    assert incomplete["coverage_scope"]["first_section_timestamp"] is None
    runs = [complete, incomplete]
    decision = _assess(runs[::-1] if reverse else runs)
    assert decision.outcome == "indeterminate"
    assert decision.reason_code == "setupapi_coverage_unavailable"
