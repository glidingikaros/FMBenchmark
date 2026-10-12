from __future__ import annotations

import json
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

RECEIPT_NAME = "logfile-retention-receipt.json"
SCHEMA_VERSION = "generation_logfile_retention_receipt.v1"
# Why a target is not retained; only no_candidate_update after a complete parse is a wrap (the log lost the change).
NOT_RETAINED = {
    "parse_coverage_unverified": "dfir_ntfs could not parse the whole exported $LogFile",
    "target_not_in_image": "a file whose timestamps were changed is not in the exported image",
    "transition_not_committed": "a timestamp change is in the $LogFile but its transaction was not committed",
    "transition_mismatch": "the $LogFile records another timestamp change than the intended one",
    "no_targets": "there was no timestamp change to check",
}


def _same_instant(left: str | None, right: str | None) -> bool:
    from fmb.index.support.windows_artifacts import parse_csv_timestamp

    a, b = parse_csv_timestamp(left), parse_csv_timestamp(right)
    return bool(a is not None and b is not None and a.basis == b.basis == "utc"
                and a.ticks_100ns == b.ticks_100ns)


def _backdated_by_minute(before: str | None, after: str | None) -> bool:
    from fmb.index.support.windows_artifacts import parse_csv_timestamp

    old, new = parse_csv_timestamp(before), parse_csv_timestamp(after)
    return bool(old is not None and new is not None and old.basis == new.basis == "utc"
                and old.ticks_100ns - new.ticks_100ns >= 60 * 10_000_000)


def _resolve_entry(index: Any, path: str) -> int | None:
    parts = PureWindowsPath(path).parts
    if len(parts) < 2:
        return None
    directories = index.resolve_directories(list(parts[1:-1]))
    if len(directories) != 1:
        return None
    wanted = parts[-1].casefold()
    matches = [entry for name, entry in index.iter_links(directories[0]) if name.casefold() == wanted]
    return matches[0] if len(matches) == 1 else None


def _matches_complete_transition(update: dict, expected: dict) -> bool:
    old, new = expected.get("old", {}), expected.get("new", {})
    if (not old or set(old) != set(new) or not set(old) <= {"created", "modified", "record_changed"}
            or not set(old) <= set(update.get("covered_fields") or [])
            or update.get("transaction_forgotten_lsn") is None or update.get("transaction_rolled_back")):
        return False
    return all(_same_instant((update.get("old") or {}).get(field), old[field])
               and _same_instant((update.get("new") or {}).get(field), new[field])
               and _backdated_by_minute(old[field], new[field]) for field in old)


def check_logfile_retention(
    image_path: Path,
    *,
    targets: list[dict[str, Any]],
    output_dir: Path,
    require: bool,
    timeline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from fmb.collection.tools.host.ntfs_index import VolumeIndex
    from fmb.index.adapters.logfile import _logfile_bound_updates
    from fmb.index.scanners.logfile_runtime import (
        LogFileRuntimeError,
        logfile_runtime_availability,
        run_logfile_driver,
    )

    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "image": image_path.name,
        "required": bool(require),
        "status": "unchecked",
        "targets": [],
    }
    if timeline is not None:
        receipt["scenario_timeline"] = timeline

    def unchecked(status, reason, message, cause=None):
        receipt.update(status=status, reason=reason)
        _write(output_dir, receipt)
        if require and cause is None:
            raise ValueError(message)
        if require:
            raise ValueError(message) from cause
        return receipt

    availability = logfile_runtime_availability()
    if not availability.get("available"):
        return unchecked("runtime_unavailable", availability.get("reason"),
                         "the $LogFile retention check requires the locked dfir_ntfs environment")
    with tempfile.TemporaryDirectory(prefix="fmb-logfile-retention-") as temp:
        work = Path(temp)
        mft_path = work / "$MFT"
        logfile_path = work / "$LogFile"
        try:
            index = VolumeIndex(image_path)
            with mft_path.open("wb") as sink:
                index.copy_stream(0, "", sink.write)
            with logfile_path.open("wb") as sink:
                index.copy_stream(2, "", sink.write)
        except (OSError, ValueError) as error:
            return unchecked("image_unreadable", str(error),
                             "the $LogFile retention check could not read the exported image", error)
        try:
            document = run_logfile_driver(logfile_path, output_path=work / "records.json")
        except LogFileRuntimeError as error:
            return unchecked("driver_failed", str(error),
                             "the $LogFile retention check could not parse the exported log", error)
        parse = document.get("parse") or {}
        usn = document.get("embedded_usn") or {}
        receipt["log"] = {
            "lsn_first": parse.get("lsn_first"),
            "lsn_last": parse.get("lsn_last"),
            "record_count": parse.get("record_count"),
            "page_coverage_complete": parse.get("page_coverage_complete"),
            "embedded_usn_record_count": usn.get("record_count"),
            "embedded_usn_first_timestamp_filetime": usn.get("first_timestamp_filetime"),
            "embedded_usn_last_timestamp_filetime": usn.get("last_timestamp_filetime"),
        }
        complete = (
            parse.get("page_coverage_complete") is True
            and parse.get("records_truncated") is False
            and parse.get("multi_client") is False
            and type(parse.get("parse_error_count")) is int and parse["parse_error_count"] == 0
            and isinstance(document.get("lifecycle_records"), list)
        )
        if complete:
            updates, diagnostics = _logfile_bound_updates(document, raw_mft_path=mft_path, mft_context=None)
        else:
            updates, diagnostics = [], {"bound_count": 0, "witnesses_withheld": "parse_coverage_unverified"}
        receipt["binding"] = diagnostics
        by_entry: dict[int, list[dict[str, Any]]] = {}
        for update in updates:
            by_entry.setdefault(int(update["mft_entry"]), []).append(update)
        all_retained = True
        for target in targets:
            entry = _resolve_entry(index, str(target["path"]))
            row: dict[str, Any] = {
                "path": target["path"],
                "mft_entry": entry,
                "assigned_timestamp": target.get("assigned_timestamp"),
                "original_creation_utc": target.get("original_creation_utc"),
                **({"original_modified_utc": target["original_modified_utc"]}
                   if "original_modified_utc" in target else {}),
                "retained": False,
                "transition_lsn": None,
                "committed": None,
                "candidate_update_count": 0,
                **({"expected_transition": target["expected_transition"]}
                   if "expected_transition" in target else {}),
            }
            if entry is not None:
                candidates = [
                    update
                    for update in by_entry.get(entry, [])
                    if (set(target["expected_transition"]["old"]) if "expected_transition" in target
                        else {"modified"} if target.get("modified_only") is True else {"created", "modified"})
                    <= set(update.get("covered_fields") or [])
                ]
                row["candidate_update_count"] = len(candidates)
                for update in candidates:
                    new_values, old_values = update.get("new") or {}, update.get("old") or {}
                    committed = update.get("transaction_forgotten_lsn") is not None and not update.get(
                        "transaction_rolled_back"
                    )
                    if "expected_transition" in target:
                        if _matches_complete_transition(update, target["expected_transition"]):
                            row.update(retained=True, transition_lsn=update.get("lsn"), committed=True)
                            break
                        continue
                    if target.get("modified_only") is True:
                        witnessed = (
                            _same_instant(new_values.get("modified"), target.get("assigned_timestamp"))
                            and _backdated_by_minute(old_values.get("modified"), new_values.get("modified"))
                        )
                    else:
                        witnessed = (
                            _same_instant(new_values.get("created"), target.get("assigned_timestamp"))
                            and _same_instant(new_values.get("modified"), target.get("assigned_timestamp"))
                            and _same_instant(old_values.get("created"), target.get("original_creation_utc"))
                            and ("original_modified_utc" not in target
                                 or _same_instant(old_values.get("modified"), target["original_modified_utc"]))
                            and _backdated_by_minute(old_values.get("created"), new_values.get("created"))
                            and _backdated_by_minute(old_values.get("modified"), new_values.get("modified"))
                        )
                    if witnessed:
                        row.update(retained=bool(committed), transition_lsn=update.get("lsn"), committed=committed)
                        if committed:
                            break
            if not row["retained"]:
                row["not_retained_reason"] = _not_retained(complete, entry, row)
            all_retained = all_retained and bool(row["retained"])
            receipt["targets"].append(row)
        receipt["status"] = "retained" if all_retained and targets else "not_retained"
        if receipt["status"] != "retained":
            reasons = [row["not_retained_reason"] for row in receipt["targets"] if not row["retained"]]
            receipt["not_retained_reason"] = next((reason for reason in reasons if reason != "no_candidate_update"),
                                                  "no_candidate_update" if reasons else "no_targets")
    _write(output_dir, receipt)
    if require and receipt["status"] != "retained":
        reason = receipt["not_retained_reason"]
        if reason == "no_candidate_update":
            raise ValueError(
                "the intended timestamp transitions are not retained in the exported $LogFile; "
                "the attempt is a failure record (see logfile-retention-receipt.json)"
            )
        raise ValueError(f"{NOT_RETAINED[reason]}, so the $LogFile check counts the intended timestamp changes as "
                         f"not retained ({reason}); the attempt is a failure record (see logfile-retention-receipt.json)")
    return receipt


def _not_retained(complete: bool, entry: int | None, row: dict[str, Any]) -> str:
    if not complete:
        return "parse_coverage_unverified"
    if entry is None:
        return "target_not_in_image"
    if not row["candidate_update_count"]:
        return "no_candidate_update"
    return "transition_not_committed" if row["committed"] is False else "transition_mismatch"


def _write(output_dir: Path, receipt: dict[str, Any]) -> None:
    target = output_dir / RECEIPT_NAME
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
