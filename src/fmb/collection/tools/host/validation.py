from __future__ import annotations

from fmb.collection.tools.host.vmware import KapeApplianceError

import json
from pathlib import Path
from typing import Any

DEFAULT_REQUIRED_GLOBS_BY_MODULE = {
    "MFTECmd": ["modules/FileSystem/*MFTECmd*$MFT*Output.csv"],
    "MFTECmd_$MFT": ["modules/FileSystem/*MFTECmd_$MFT_Output.csv"],
    "MFTECmd_$MFT_FileListing": [
        "modules/FileSystem/*MFTECmd_$MFT_Output.csv",
        "modules/FileSystem/*MFTECmd_$MFT_Output_FileListing.csv",
    ],
    "MFTECmd_$J": [],
    "NTFSLogTracker_$LogFile": ["modules/FileSystem/*NTFSLogTracker*Output*.csv"],
    "EvtxECmd": ["modules/EventLogs/*EvtxECmd*Output.csv"],
    "PECmd": ["modules/ProgramExecution/*PECmd*Output*.csv"],
    "AppCompatCacheParser": ["modules/ProgramExecution/*AppCompatCache*.csv"],
    "AmcacheParser": ["modules/ProgramExecution/*Amcache*.csv"],
    "RECmd_AllBatchFiles": ["modules/Registry/*.csv"],
    "RECmd_Kroll": ["modules/Registry/*.csv"],
    "RECmd_RECmd_Batch_MC": ["modules/Registry/*.csv"],
    "RECmd_UserActivity": ["modules/Registry/*.csv"],
    "RECmd_BasicSystemInfo": ["modules/Registry/*.csv"],
    "JLECmd": ["modules/FileFolderAccess/*AutomaticDestinations.csv"],
    "LECmd": ["modules/FileFolderAccess/*LECmd*Output.csv"],
    "SBECmd": ["modules/FileFolderAccess/*.csv"],
}
DEFAULT_REQUIRED_GLOBS_BY_TARGET = {
    "$MFT": ["targets/*/$MFT"],
    "FileSystem": ["targets/*/$MFT"],
    "$J": ["targets/*/$Extend/$J"],
    "$LogFile": ["targets/*/$LogFile"],
    "EventLogs": ["targets/*/Windows/System32/winevt/Logs/*.evtx"],
    "FMBBoundedUserBMP": ["targets/*/Users/*/**/*.bmp"],
    "FMBSetupApiLogs": ["targets/*/Windows/inf/setupapi.dev.log"],
}


def required_artifact_globs(
    targets: list[str], modules: list[str], explicit: list[str]
) -> list[str]:
    globs = list(explicit)
    for target in targets:
        globs.extend(DEFAULT_REQUIRED_GLOBS_BY_TARGET.get(target, []))
    for module in modules:
        globs.extend(DEFAULT_REQUIRED_GLOBS_BY_MODULE.get(module, []))
    return list(dict.fromkeys(globs))


KAPE_METADATA_MARKER_GLOBS = (
    "targets/*/$MFT",
    "targets/*/$Extend/$J",
    "targets/*/$LogFile",
)
APPLIANCE_METADATA_MARKERS = (
    "FMB-Appliance",
    "run_kape_appliance.ps1",
    "install_kape.ps1",
    "kape_install_manifest",
)


def file_contains_any_marker(
    path: Path, markers: list[bytes], *, chunk_size: int = 1024 * 1024
) -> str | None:
    overlap_size = max(len(marker) for marker in markers) - 1
    previous = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            window = previous + chunk
            for marker in markers:
                if marker in window:
                    return marker.decode("utf-16le" if b"\x00" in marker else "utf-8")
            previous = window[-overlap_size:] if overlap_size else b""
    return None


def assert_no_appliance_metadata_contamination(
    output_root: Path,
    *,
    checks: list[dict[str, Any]],
) -> None:
    markers = [
        marker.encode(encoding)
        for marker in APPLIANCE_METADATA_MARKERS
        for encoding in ("utf-8", "utf-16le")
    ]
    appliance_marker_issues = [
        {
            "issue_id": "appliance_metadata_cross_contamination",
            "artifact": metadata_path.relative_to(output_root).as_posix(),
            "marker": found,
        }
        for pattern in KAPE_METADATA_MARKER_GLOBS
        for metadata_path in sorted(output_root.glob(any_case(pattern)))
        if metadata_path.is_file() and (found := file_contains_any_marker(metadata_path, markers))
    ]
    if appliance_marker_issues:
        raise KapeApplianceError(
            "KAPE metadata appears to come from the appliance, not evidence: "
            + json.dumps(appliance_marker_issues, sort_keys=True)
        )
    checks.append(
        {"check_id": "kape_metadata_not_appliance_contaminated", "status": "pass"}
    )


def any_case(pattern: str) -> str:
    return "".join(f"[{char.lower()}{char.upper()}]" if char.isalpha() else char for char in pattern)


def assert_required_kape_artifacts(
    output_root: Path,
    required_artifact_globs: list[str] | None,
    *,
    checks: list[dict[str, Any]],
) -> None:
    for pattern in required_artifact_globs or []:
        matches = list(output_root.glob(any_case(pattern)))
        if not matches:
            raise KapeApplianceError(
                f"required KAPE artifact pattern missing: {pattern}"
            )
        checks.append({"check_id": f"artifact_glob:{pattern}", "status": "pass"})
