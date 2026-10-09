from __future__ import annotations

from pathlib import Path
from typing import Any

MFTECMD_USN_OUTPUT_GLOB = "modules/FileSystem/*MFTECmd_$J_Output.csv"
MFTECMD_USN_ROW_CHECK_ID = "mftecmd_usn_parser_output_rows"


def csv_contains_data_row(path: Path) -> bool:
    try:
        with path.open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as handle:
            seen_header = False
            for line in handle:
                if not line.strip():
                    continue
                if not seen_header:
                    seen_header = True
                    continue
                return True
    except OSError:
        return False
    return False


def relative_output_paths(output_root: Path, paths: list[Path]) -> list[str]:
    return [path.relative_to(output_root).as_posix() for path in paths]


def summarize_mftecmd_usn_csvs(output_root: Path) -> dict[str, Any]:
    usn_outputs = sorted(output_root.glob(MFTECMD_USN_OUTPUT_GLOB))
    data_outputs = [path for path in usn_outputs if csv_contains_data_row(path)]
    return {
        "parser_outputs": relative_output_paths(output_root, usn_outputs),
        "parser_output_count": len(usn_outputs),
        "parser_outputs_with_data_rows": len(data_outputs),
        "parser_outputs_with_data_rows_paths": relative_output_paths(
            output_root, data_outputs
        ),
        "record_level_evidence_present": bool(data_outputs),
    }


def mftecmd_usn_row_check(mftecmd_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "check_id": MFTECMD_USN_ROW_CHECK_ID,
        "parser_outputs": mftecmd_summary["parser_outputs"],
        "parser_output_count": mftecmd_summary["parser_output_count"],
        "parser_outputs_with_data_rows": mftecmd_summary[
            "parser_outputs_with_data_rows"
        ],
    }


def build_mftecmd_usn_row_validation_checks(
    output_root: Path,
    *,
    requested_modules: list[str] | None = None,
) -> list[dict[str, Any]]:
    mftecmd_summary = summarize_mftecmd_usn_csvs(output_root)
    check = mftecmd_usn_row_check(mftecmd_summary)
    if mftecmd_summary["parser_output_count"] == 0:
        if "MFTECmd_$J" not in (requested_modules or []):
            return []
        return [
            {
                **check,
                "status": "warn",
                "message": (
                    "MFTECmd_$J did not emit CSV output; no raw-artifact substitute "
                    "is used for record-level USN validation."
                ),
            }
        ]
    if mftecmd_summary["record_level_evidence_present"]:
        return [{**check, "status": "pass"}]
    return [
        {
            **check,
            "status": "warn",
            "message": (
                "MFTECmd_$J emitted CSV output, but all observed files are header-only. "
                "Treat USN detections from this run as unsupported unless another parser "
                "surface provides record-level evidence."
            ),
        }
    ]
