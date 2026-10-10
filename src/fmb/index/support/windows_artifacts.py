from __future__ import annotations

import csv
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Literal

from fmb.core.coercion import parse_truncated_int

CandidatePurpose = Literal["timestomp", "usn_delete", "prefetch", "registry_mru"]
SUPPORTED_CANDIDATE_PURPOSES = {
    "timestomp",
    "usn_delete",
    "prefetch",
    "registry_mru",
}

MFT_TIMESTAMP_PAIRS = (
    ("created", "Created0x10", "Created0x30"),
    ("modified", "LastModified0x10", "LastModified0x30"),
    ("metadata_changed", "LastRecordChange0x10", "LastRecordChange0x30"),
    ("accessed", "LastAccess0x10", "LastAccess0x30"),
    ("created", "SI Created", "FN Created"),
    ("modified", "SI Modified", "FN Modified"),
    ("metadata_changed", "SI MFT Changed", "FN MFT Changed"),
    ("accessed", "SI Accessed", "FN Accessed"),
)

USER_DOCUMENT_SUFFIXES = {".txt", ".doc", ".docx", ".pdf", ".xlsx", ".csv"}
SYSTEM_SUFFIXES = {".manifest", ".mui", ".cat", ".mum", ".dll", ".sys", ".nls"}
EXECUTION_SUFFIXES = {".exe", ".pf"}
REGISTRY_DOCUMENT_SUFFIXES = {".txt", ".doc", ".docx", ".pdf", ".xlsx"}
REGISTRY_NOISE_SUFFIXES = {".lnk", ".exe", ".dll"}

SYSTEM_NAME_TOKENS = ("microsoft-windows", "winsxs", "system32")
EVIDENCE_NAME_TOKENS = ("evidence", "confidential", "secret", "stolen", "plans")
TYPICAL_TOOL_NOISE_TOKENS = (
    "watson",
    "wer.",
    "client_manifest",
    "thirdpartynotices",
    "notice.txt",
    "testfile.txt",
)
COMMON_PREFETCH_EXECUTABLE_TOKENS = (
    "svchost",
    "dllhost",
    "rundll32",
    "am_base",
    "am_delta",
    "powershell",
    "wsmprovhost",
    "conhost",
    "csc",
    "cvtres",
    "onedrive",
    "msteams",
    "microsoftedge",
    "runtimebroker",
    "filecoauth",
)


def sanitize_csv_row(row: Mapping[object, object]) -> dict[str, str]:
    return {
        str(key): "" if value is None else str(value)
        for key, value in row.items()
        if key is not None
    }


def kape_relative_path(path: str) -> str | None:
    parts = path.replace("\\", "/").split("/")
    roots = [index for index, part in enumerate(parts) if part.casefold() == "kape-output"]
    return "/".join(parts[roots[-1] + 1:]).casefold() if roots else None


def stream_csv_rows(path: Path) -> Iterator[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield sanitize_csv_row(row)


def first_nonempty(*values: str | None) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def safe_path_component(value: str) -> str:
    safe_chars = {"-", "_"}
    return "".join(
        char if char.isalnum() or char in safe_chars else "_" for char in value
    )


def row_value(row: dict[str, str], *keys: str) -> str | None:
    return _folded_row_value(folded_row(row), *keys)


def _folded_row_value(folded: Mapping[str, str], *keys: str) -> str | None:
    for key in keys:
        value = folded.get(key.casefold())
        if value:
            return value
    return None


def folded_row(row: dict[str, str]) -> dict[str, str]:
    return {key.casefold(): value for key, value in row.items()}


def contains_any_token(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def windows_path_is_rooted(value: str) -> bool:
    normalized = value.strip().replace("/", "\\")
    return normalized.startswith("\\\\") or (
        len(normalized) >= 3 and normalized[1:3] == ":\\"
    )


def join_windows_path(parent: str, name: str) -> str:
    parent = parent.strip().replace("/", "\\")
    name = name.strip().replace("/", "\\")
    if not name:
        return parent
    if windows_path_is_rooted(name):
        return name
    if not parent or parent == ".":
        return f".\\{name}" if name else parent
    normalized_parent = parent.rstrip("\\")
    return f"{normalized_parent}\\{name}"


_TIMESTAMP_RE = re.compile(
    r"^\s*(?P<date>\d{4}-\d{2}-\d{2})[ T]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,7}))?"
    r"(?P<offset>Z|[+-]\d{2}:\d{2})?\s*$"
)

_TICKS_PER_SECOND = 10_000_000
_TICKS_PER_DAY = 86_400 * _TICKS_PER_SECOND


@dataclass(frozen=True)
class ForensicTimestamp:

    ticks_100ns: int
    basis: Literal["naive", "utc"]
    year: int


def parse_csv_timestamp(value: str | None) -> ForensicTimestamp | None:
    if not isinstance(value, str):
        return None
    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return None
    try:
        moment = datetime.strptime(
            f"{match.group('date')} {match.group('time')}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None
    fraction = match.group("fraction") or ""
    fraction_ticks = int(fraction.ljust(7, "0")) if fraction else 0
    ticks = (
        (moment.toordinal() * 86_400 + moment.hour * 3_600 + moment.minute * 60)
        * _TICKS_PER_SECOND
        + moment.second * _TICKS_PER_SECOND
        + fraction_ticks
    )
    offset = match.group("offset")
    normalized_year = moment.year
    if offset and offset != "Z":
        hours = int(offset[1:3])
        minutes = int(offset[4:6])
        if hours > 23 or minutes > 59:
            return None
        signed_seconds = hours * 3_600 + minutes * 60
        if offset[0] == "-":
            signed_seconds = -signed_seconds
        ticks -= signed_seconds * _TICKS_PER_SECOND
        try:
            normalized_year = datetime.fromordinal(ticks // _TICKS_PER_DAY).year
        except ValueError:
            return None
    return ForensicTimestamp(
        ticks_100ns=ticks,
        basis="utc" if offset is not None else "naive",
        year=normalized_year,
    )


def timestamp_semantically_equal(left: str | None, right: str | None) -> bool:
    left_time = parse_csv_timestamp(left)
    right_time = parse_csv_timestamp(right)
    return left_time is not None and left_time == right_time


def windows_suffix(value: str | None) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    return PureWindowsPath(value.replace("/", "\\")).suffix.casefold()


def user_path_score(text: str) -> int:
    folded = text.replace("/", "\\").casefold()
    score = 0
    if "\\users\\" in folded:
        score += 55
    if "\\desktop" in folded:
        score += 35
    if "\\appdata\\local\\temp" in folded:
        score += 45
    if "\\windows\\winsxs" in folded:
        score -= 70
    elif "\\windows\\" in folded:
        score -= 35
    if "\\program files" in folded:
        score -= 20
    return score


def row_recency_score(row: dict[str, str], *keys: str) -> int:
    years = []
    for key in keys:
        parsed = parse_csv_timestamp(row.get(key))
        if parsed is not None:
            years.append(parsed.year)
    if not years:
        return 0
    newest = max(years)
    if newest >= 2026:
        return 90
    if newest >= 2025:
        return 75
    if newest >= 2024:
        return 45
    if newest >= 2023:
        return 15
    return -20


def _base_candidate_score(name: str, folded: str, suffix: str) -> int:
    score = user_path_score(name)
    if "~" in name:
        score -= 20
    if suffix in SYSTEM_SUFFIXES:
        score -= 60
    if contains_any_token(folded, SYSTEM_NAME_TOKENS):
        score -= 55
    return score


def _timestomp_candidate_score(folded: str, suffix: str) -> int:
    score = 0
    if suffix in USER_DOCUMENT_SUFFIXES:
        score += 70
    elif suffix in EXECUTION_SUFFIXES:
        score += 10
    if contains_any_token(folded, EVIDENCE_NAME_TOKENS):
        score += 25
    if contains_any_token(folded, TYPICAL_TOOL_NOISE_TOKENS):
        score -= 35
    return score


def _prefetch_candidate_score(name: str, folded: str, suffix: str) -> int:
    score = 0
    if suffix == ".exe":
        score += 45
    if "_" in name:
        score += 20
    if contains_any_token(folded, COMMON_PREFETCH_EXECUTABLE_TOKENS):
        score -= 45
    return score


def _registry_mru_candidate_score(suffix: str) -> int:
    if suffix == "":
        return 45
    if suffix in REGISTRY_DOCUMENT_SUFFIXES:
        return 20
    if suffix in REGISTRY_NOISE_SUFFIXES:
        return -30
    return 0


def _purpose_candidate_score(
    name: str,
    folded: str,
    suffix: str,
    purpose: CandidatePurpose,
) -> int:
    if purpose in {"timestomp", "usn_delete"}:
        return _timestomp_candidate_score(folded, suffix)
    if purpose == "prefetch":
        return _prefetch_candidate_score(name, folded, suffix)
    if purpose == "registry_mru":
        return _registry_mru_candidate_score(suffix)
    raise ValueError(f"unsupported candidate scoring purpose: {purpose}")


def score_candidate_name(name: str, *, purpose: CandidatePurpose) -> int:
    if purpose not in SUPPORTED_CANDIDATE_PURPOSES:
        raise ValueError(f"unsupported candidate scoring purpose: {purpose}")
    folded = name.casefold()
    if not folded or folded in {".", ".."}:
        return -200
    suffix = windows_suffix(name)
    score = _base_candidate_score(name, folded, suffix)
    score += _purpose_candidate_score(name, folded, suffix, purpose)
    if "_" in name or " " in name:
        score += 12
    return score


def mft_path(row: dict[str, str]) -> str:
    folded = folded_row(row)
    full_path = first_nonempty(
        _folded_row_value(folded, "FullPath", "Full Path", "FilePath", "Path")
    )
    if full_path:
        return full_path
    parent = first_nonempty(
        _folded_row_value(folded, "ParentPath", "Parent Path", "Directory")
    )
    name = first_nonempty(
        _folded_row_value(folded, "FileName"),
        _folded_row_value(folded, "Name"),
        _folded_row_value(folded, "File Name"),
    )
    if parent or name:
        return join_windows_path(parent, name)
    return "<unknown>"


def _mft_timestamp_pair_values(
    folded: Mapping[str, str],
) -> Iterator[tuple[str, str | None, str | None]]:
    for field, si_key, fn_key in MFT_TIMESTAMP_PAIRS:
        yield (
            field,
            _folded_row_value(folded, si_key),
            _folded_row_value(folded, fn_key),
        )


def mft_timestamp_mismatches(row: dict[str, str]) -> list[dict[str, str]]:
    mismatches = []
    folded = folded_row(row)
    for field, si_value, fn_value in _mft_timestamp_pair_values(folded):
        if (
            not si_value
            or not fn_value
            or timestamp_semantically_equal(si_value, fn_value)
        ):
            continue
        mismatches.append(
            {
                "field": field,
                "standard_information": si_value,
                "file_name": fn_value,
            }
        )
    return mismatches


def max_timestamp_mismatch_gap_days(mismatches: list[dict[str, str]]) -> int:
    max_days = 0
    for mismatch in mismatches:
        si_value = parse_csv_timestamp(mismatch.get("standard_information"))
        fn_value = parse_csv_timestamp(mismatch.get("file_name"))
        if si_value is None or fn_value is None or si_value.basis != fn_value.basis:
            continue
        elapsed_ticks = abs(si_value.ticks_100ns - fn_value.ticks_100ns)
        max_days = max(max_days, elapsed_ticks // _TICKS_PER_DAY)
    return max_days


PATH_SUBJECT_HEADERS = (
    "Path",
    "FullPath",
    "FilePath",
    "TargetPath",
    "LocalPath",
    "NetworkPath",
    "TargetName",
    "TargetIDAbsolutePath",
    "LowerCaseLongPath",
    "ApplicationPath",
    "BinaryPath",
    "CommonPath",
    "LnkName",
    "RelativePath",
    "ValueData",
    "Value",
    "Name",
    "ProgramName",
    "FileName",
    "File Name",
    "EntryName",
)


def parse_int(value: str | None) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return parse_truncated_int(value)


def parse_bool(value: str | None, *, default: bool = False) -> bool:
    if not isinstance(value, str) or not value.strip():
        return default
    return value.strip().casefold() in {"true", "1", "yes", "y"}


def parse_explicit_bool(value: str | None) -> bool | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().casefold()
    if normalized in {"true", "1", "yes", "y"}:
        return True
    if normalized in {"false", "0", "no", "n"}:
        return False
    return None


def csv_files_with_tokens(
    root: Path,
    *,
    include_any: tuple[str, ...],
    include_all: tuple[str, ...] = (),
    exclude_any: tuple[str, ...] = (),
) -> list[Path]:
    candidates = []
    include_any_folded = tuple(token.casefold() for token in include_any)
    include_all_folded = tuple(token.casefold() for token in include_all)
    exclude_any_folded = tuple(token.casefold() for token in exclude_any)
    for path in sorted(root.rglob("*.csv")):
        folded = path.relative_to(root).as_posix().replace("\\", "/").casefold()
        if include_any_folded and not any(
            token in folded for token in include_any_folded
        ):
            continue
        if include_all_folded and not all(
            token in folded for token in include_all_folded
        ):
            continue
        if exclude_any_folded and any(token in folded for token in exclude_any_folded):
            continue
        candidates.append(path)
    return candidates


def row_first(row: dict[str, str], *keys: str) -> str:
    folded = folded_row(row)
    return first_nonempty(*(_folded_row_value(folded, key) for key in keys))


def native_row_fields(
    row: dict[str, str], aliases: dict[str, tuple[str, ...]]
) -> dict[str, str]:
    columns = {key.casefold(): value for key, value in row.items()}
    fields = {}
    for name, source_names in aliases.items():
        for source_name in source_names:
            value = columns.get(source_name.casefold())
            if isinstance(value, str) and value.strip():
                fields[name] = value
                break
    return fields


def canonical_mftecmd_timestamp(value: str | None) -> str:

    if not isinstance(value, str):
        return ""
    parsed = parse_csv_timestamp(value)
    if parsed is None or parsed.basis == "utc":
        return value
    return value.strip().replace(" ", "T", 1) + "Z"


def csv_header_names(csv_path: Path) -> set[str]:
    try:
        with csv_path.open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as handle:
            fieldnames = csv.DictReader(handle).fieldnames or []
    except (OSError, csv.Error):
        return set()
    return {str(item).strip().casefold() for item in fieldnames if item is not None}


def csv_has_required_headers(
    csv_path: Path,
    *required_groups: tuple[str, ...],
) -> bool:

    headers = csv_header_names(csv_path)
    return bool(headers) and all(
        any(alias.casefold() in headers for alias in group) for group in required_groups
    )
