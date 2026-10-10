from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from fmb.analysis.inputs import ntfs_scope_and_reference_from_identity
from fmb.core.hashing import sha256_file
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    mft_row_full_path,
)
from fmb.index.support.windows_artifacts import parse_explicit_bool, row_value, stream_csv_rows
from fmb.index.support.windows_identity import (
    ntfs_reference_from_row,
    windows_compare_path_parts,
)

POOL_QUESTIONS = frozenset({"BQ-DELETE-01", "BQ-EXEC-01", "BQ-SHELLBAG-01", "BQ-DIRECTORY-01"})
_ENTRY_BUCKET_SIZE = 128


def pool_volume_ids(pool: dict) -> set[str]:
    ids = {pool["mft_volume_id"]}
    for proof in pool.get("native_volume_observations", []) or []:
        match = re.match(r"source:([0-9a-f]{16}):", str(proof.get("native_volume_mft_source_ref") or ""))
        if match:
            ids.add("mft-source:" + match.group(1))
    return ids


def _pool_covers(pool: dict, volume: str, entry: int) -> bool:
    return (volume in pool_volume_ids(pool) and pool["reference_complete"]
            and any(v["first"] <= entry <= v["last"] for v in pool["entry_intervals"]))


def referenced_identity(record: dict):
    fields = record.get("fields", {})
    if record.get("record_type") != "directory_index_entry":
        return None
    entry, sequence, volume = fields.get("file_reference_entry"), fields.get("file_reference_sequence"), fields.get("mft_volume_id")
    if type(entry) is not int or type(sequence) is not int or not isinstance(volume, str) or not volume:
        return None
    return volume, (entry, sequence)


def validate_pool(pool: dict) -> None:
    required = {"mft_volume_id", "source_record_ref", "source_sha256", "reference_complete", "path_complete",
                "volume_aliases", "native_volume_observations", "entry_intervals", "path_prefixes", "records"}
    if not isinstance(pool, dict) or set(pool) - {"drive_letter_binding"} != required:
        raise ValueError("unregistered MFT comparison pool")
    if (not isinstance(pool["mft_volume_id"], str) or not pool["mft_volume_id"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(pool["source_sha256"]))
            or not isinstance(pool["source_record_ref"], str) or not pool["source_record_ref"]
            or type(pool["reference_complete"]) is not bool or type(pool["path_complete"]) is not bool):
        raise ValueError("MFT pool identity/completeness unavailable")
    for key in ("volume_aliases", "path_prefixes"):
        if not isinstance(pool[key], list) or any(not isinstance(v, str) or not v for v in pool[key]):
            raise ValueError("invalid MFT pool scope")
    if "drive_letter_binding" in pool:
        from fmb.index.adapters.volume_binding import drive_letters_from_proof
        bound = drive_letters_from_proof(pool["drive_letter_binding"])
        if not bound <= set(pool["volume_aliases"]):
            raise ValueError("native drive letters are absent from pool aliases")
    if not isinstance(pool["native_volume_observations"], list):
        raise ValueError("native volume observations must be explicit")
    for proof in pool["native_volume_observations"]:
        if (not isinstance(proof, dict) or set(proof) != {
            "native_volume_token", "native_volume_creation_filetime", "native_volume_serial_number",
            "native_volume_boot_source_ref", "native_volume_mft_source_ref", "native_volume_manifest_sha256"}
            or type(proof["native_volume_creation_filetime"]) is not int):
            raise ValueError("unregistered native volume observations")
        token = f"volume{{{proof['native_volume_creation_filetime']:016x}-{str(proof['native_volume_serial_number'])[-8:].lower()}}}"
        if token != proof["native_volume_token"] or token not in pool["volume_aliases"]:
            raise ValueError("native volume token contradicts retained volume observations")
    if any(v.startswith("volume{") and v not in {p["native_volume_token"] for p in pool["native_volume_observations"]}
           for v in pool["volume_aliases"]):
        raise ValueError("native volume alias lacks its underlying observations")
    if not isinstance(pool["entry_intervals"], list):
        raise ValueError("invalid MFT entry intervals")
    for interval in pool["entry_intervals"]:
        if (not isinstance(interval, dict) or set(interval) != {"first", "last"}
                or any(type(v) is not int for v in interval.values())
                or not 0 <= interval["first"] <= interval["last"] < 1 << 48):
            raise ValueError("invalid MFT entry interval")
    if not isinstance(pool["records"], list):
        raise ValueError("MFT records must be complete explicit rows")
    for row in pool["records"]:
        if (not isinstance(row, dict) or set(row) != {"entry", "sequence", "in_use", "path", "source_record_ref"}
                or type(row["entry"]) is not int or not 0 <= row["entry"] < 1 << 48
                or type(row["sequence"]) is not int or not 0 <= row["sequence"] < 1 << 16
                or type(row["in_use"]) is not bool
                or not isinstance(row["path"], str) or not isinstance(row["source_record_ref"], str)):
            raise ValueError("invalid native MFT row")


def build_comparison_pool(*, csv_path: Path, kape_root: Path, cards: list[dict],
                          native_manifest_path: Path, raw_mft_path: Path,
                          drive_binding_path: Path | None = None, locate=Path) -> dict:
    context = build_mft_presence_context(kape_root)
    if context.get("source_paths") != [str(csv_path)] or not context.get("mft_volume_id"):
        raise ValueError("comparison requires the unique collected MFT source")
    from fmb.index.adapters.volume_binding import bind_native_volume
    context = bind_native_volume(context, native_manifest_path, raw_mft_path)
    drive_proof = None
    if drive_binding_path:
        from fmb.index.adapters.volume_binding import load_drive_binding, drive_letters_from_proof
        drive_proof = load_drive_binding(drive_binding_path, locate=locate)
        context["indexed_volumes"] |= drive_letters_from_proof(drive_proof)
    intervals, prefixes = set(), set()
    volume_ids = pool_volume_ids({"mft_volume_id": context["mft_volume_id"],
                                  "native_volume_observations": list(context.get("native_volume_bindings", {}).values())})
    for card in cards:
        identity = ntfs_scope_and_reference_from_identity(card["identity"])
        if identity and identity[0] in volume_ids:
            start = identity[1][0] // _ENTRY_BUCKET_SIZE * _ENTRY_BUCKET_SIZE
            intervals.add((start, start + _ENTRY_BUCKET_SIZE - 1))
        for record in card["evidence_records"]:
            referenced = referenced_identity(record)
            if referenced and referenced[0] in volume_ids:
                start = referenced[1][0] // _ENTRY_BUCKET_SIZE * _ENTRY_BUCKET_SIZE
                intervals.add((start, start + _ENTRY_BUCKET_SIZE - 1))
            volume, path = windows_compare_path_parts(record["subject_ref"])
            if volume in set(context["indexed_volumes"]) and "\\" in path:
                prefixes.add(path.rsplit("\\", 1)[0] + "\\")
    digest = sha256_file(csv_path)
    rows = []
    reference_complete = context["reference_absence_check_supported"]
    path_complete = context["path_absence_check_supported"]
    for number, row in enumerate(stream_csv_rows(csv_path), 1):
        identity = ntfs_reference_from_row(row, entry_keys=("EntryNumber", "Entry Number"), sequence_keys=("SequenceNumber", "Sequence Number"))
        path = mft_row_full_path(row)
        normalized = windows_compare_path_parts(path)[1]
        state = parse_explicit_bool(row_value(row, "InUse", "In Use"))
        if identity is None or state is None:
            continue
        if any(first <= identity[0] <= last for first, last in intervals) or any(normalized.startswith(p) for p in prefixes):
            rows.append({"entry": identity[0], "sequence": identity[1], "in_use": state, "path": path,
                         "source_record_ref": f"source:{digest[:16]}:row={number}"})
    result = {"mft_volume_id": context["mft_volume_id"], "source_record_ref": f"source:{digest[:16]}:declared-scan",
              "source_sha256": digest, "reference_complete": reference_complete, "path_complete": path_complete,
              "volume_aliases": sorted(context["indexed_volumes"]),
              "native_volume_observations": list(context.get("native_volume_bindings", {}).values()),
              "entry_intervals": [{"first": a, "last": b} for a, b in sorted(intervals)],
              "path_prefixes": sorted(prefixes), "records": rows}
    if drive_proof:
        result["drive_letter_binding"] = drive_proof
    return result


def with_comparison_pool(bundle, pool: dict):
    from fmb.analysis.factual_contract import FACTUAL_EVIDENCE_VERSION
    from fmb.analysis.shared_evidence import EvidenceBundle

    validate_pool(pool)
    value = bundle.payload
    if value["schema_version"] != FACTUAL_EVIDENCE_VERSION or bundle.question_id not in POOL_QUESTIONS:
        raise ValueError("comparison condition is restricted to the factual absence questions")
    value["current_mft_pools"] = [deepcopy(pool)]
    for card in value["candidate_roster"]:
        identity = ntfs_scope_and_reference_from_identity(card["identity"])
        referenced = [r for r in (referenced_identity(rec) for rec in card["evidence_records"]) if r]
        if referenced:
            complete = all(_pool_covers(pool, r[0], r[1][0]) for r in referenced)
        elif identity:
            complete = _pool_covers(pool, identity[0], identity[1][0])
        else:
            volume, suffix = windows_compare_path_parts(card["identity"].get("canonical_name") or card["display_name"])
            complete = (pool["path_complete"] and volume in pool["volume_aliases"]
                        and any(suffix.startswith(prefix) for prefix in pool["path_prefixes"]))
        for coverage in card["coverage"]:
            if coverage["artifact_family"] == "ntfs.mft":
                coverage["collection_status"] = "complete" if complete else "partial"
        for record in card["evidence_records"]:
            record["fields"].pop("active_mft_lookup", None)
    for coverage in value["coverage"]:
        if coverage["artifact_family"] == "ntfs.mft":
            states = [c["collection_status"] for card in value["candidate_roster"]
                      for c in card["coverage"] if c["artifact_family"] == "ntfs.mft"]
            coverage["status"] = "complete" if states and all(s == "complete" for s in states) else "partial"
    return EvidenceBundle.from_payload(value)


def comparison_fields(payload: dict, card: dict, record: dict) -> dict:
    unresolved = {"mft_active_presence_status": "active_mft_absence_undecidable",
                  "mft_active_presence_check_supported": False, "mft_active_presence_basis": "incomplete_mft_comparison_scope"}
    pools = payload.get("current_mft_pools", [])
    identity = referenced_identity(record) or ntfs_scope_and_reference_from_identity(card["identity"])
    native_volume, path = windows_compare_path_parts(record["subject_ref"])
    volume = record["fields"].get("mft_volume_id")
    if volume is None and identity:
        volume = identity[0]
    candidates = [p for p in pools if volume in pool_volume_ids(p)] if volume else [p for p in pools if native_volume in p["volume_aliases"]]
    if len(candidates) != 1:
        return unresolved
    pool = candidates[0]
    volume = volume or pool["mft_volume_id"]
    if native_volume is not None and native_volume not in pool["volume_aliases"]:
        return unresolved
    if identity:
        entry, sequence = identity[1]
        if not _pool_covers(pool, identity[0], entry):
            return unresolved
        states = {(r["sequence"], r["in_use"]) for r in pool["records"] if r["entry"] == entry}
        if len(states) > 1:
            return unresolved
        present = (sequence, True) in states
        state = next(iter(states)) if states else None
        basis = ("file_reference_in_use" if present
                 else "file_reference_entry_absent" if state is None
                 else "file_reference_record_free" if state[0] == sequence
                 else "file_reference_entry_reused" if state[1] else "file_reference_entry_freed")
    else:
        if (not pool["path_complete"] or native_volume is None
                or not any(path.startswith(p) for p in pool["path_prefixes"])):
            return unresolved
        present = any(r["in_use"] and windows_compare_path_parts(r["path"])[0] in [None, *pool["volume_aliases"]]
                      and windows_compare_path_parts(r["path"])[1] == path for r in pool["records"])
        basis = "path_comparison"
    return {"mft_active_presence_status": "active_mft_present" if present else "active_mft_absent",
            "mft_active_presence_check_supported": True, "mft_active_presence_basis": basis,
            "mft_active_reference_match": bool(identity and present),
            "mft_active_path_match": bool(not identity and present), "mft_volume_id": volume}


def comparison_evidence_refs(payload: dict, card: dict, record: dict) -> list[str]:
    fields = comparison_fields(payload, card, record)
    if not fields["mft_active_presence_check_supported"]:
        return []
    pool = next(p for p in payload["current_mft_pools"] if fields["mft_volume_id"] in pool_volume_ids(p))
    identity = referenced_identity(record) or ntfs_scope_and_reference_from_identity(card["identity"])
    path = windows_compare_path_parts(record["subject_ref"])[1]
    rows = [r for r in pool["records"] if (r["entry"] == identity[1][0] if identity else
        windows_compare_path_parts(r["path"])[0] in [None, *pool["volume_aliases"]]
        and windows_compare_path_parts(r["path"])[1] == path)]
    refs = [pool["source_record_ref"], *(r["source_record_ref"] for r in rows)]
    for proof in pool["native_volume_observations"]:
        refs.extend((proof["native_volume_boot_source_ref"], proof["native_volume_mft_source_ref"]))
    if pool.get("drive_letter_binding"):
        refs.append(pool["drive_letter_binding"]["gpt_partition_source_ref"])
        refs.extend(r["source_record_ref"] for r in pool["drive_letter_binding"]["mounted_device_values"])
    return sorted(set(refs))
