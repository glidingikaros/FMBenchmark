from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import re
import hashlib
from fmb.core.hashing import sha256_file
from fmb.core.paper_contract import LISTING_QUESTIONS, PAPER_VIEWS, PRESENTATION_NOTES, STREAM_HEAD_BYTES
from fmb.core.paper_protocol import paper_protocol
from fmb.core.sealed_records import canonical_json, read_json


_PROTOCOL = paper_protocol()
SPLIT_QUESTIONS = tuple(_PROTOCOL["split_questions"])

REF = re.compile(r"^r\d{5,}$")

LEVEL = _PROTOCOL["presentation"]

OPTIONS_TEMPLATE = {
    "notes": list(PRESENTATION_NOTES),
    "notes_where_present": True,
    "views": list(PAPER_VIEWS),
    "legible_ids": True,
    "plain_finding_names": "v2",
    "stated_reasons": True,
}


def _walk(value, function):
    if isinstance(value, dict):
        return {k: _walk(v, function) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, function) for v in value]
    return function(value)


def expand_refs(case: dict) -> dict:
    refs = case["source_reference_map"]
    return _walk(
        {k: v for k, v in case.items() if k != "source_reference_map"},
        lambda s: refs.get(s, s) if isinstance(s, str) else s,
    )


def _collect_refs(case: dict) -> set:
    from fmb.analysis.factual_contract import source_references

    found = set()
    for card in case["candidate_roster"]:
        found.update(source_references(card))

    def collect(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key.endswith("source_ref") or key.endswith("source_record_ref"):
                    if isinstance(value, str) and value:
                        found.add(value)
                elif key.endswith("source_refs") and isinstance(value, list):
                    found.update(v for v in value if isinstance(v, str) and v)
                collect(value)
        elif isinstance(item, list):
            for value in item:
                collect(value)

    collect(case["candidate_roster"])
    return found


def compact_refs(case: dict) -> dict:
    mapping = {f"r{n:05d}": ref for n, ref in enumerate(sorted(_collect_refs(case)), 1)}
    inverse = {ref: key for key, ref in mapping.items()}
    out = _walk(case, lambda s: inverse.get(s, s) if isinstance(s, str) else s)
    out["source_reference_map"] = mapping
    return out


def _used_refs(value, found: set) -> None:
    if isinstance(value, dict):
        for v in value.values():
            _used_refs(v, found)
    elif isinstance(value, list):
        for v in value:
            _used_refs(v, found)
    elif isinstance(value, str) and REF.match(value):
        found.add(value)


def one_card_case(case: dict, index: int) -> dict:
    out = deepcopy(case)
    out["candidate_roster"] = [out["candidate_roster"][index]]
    refs: set = set()
    _used_refs({k: v for k, v in out.items() if k != "source_reference_map"}, refs)
    if isinstance(out.get("source_reference_map"), dict):
        out["source_reference_map"] = {
            k: v for k, v in out["source_reference_map"].items() if k in refs
        }
    return out


def _usn(record):
    return record["fields"]["update_sequence_number"]


def u_usn_complete_stream(case):
    for card in case["candidate_roster"]:
        rs = card["evidence_records"]
        a = [
            r
            for r in rs
            if r["record_type"] == "usn_record" and "record_offset" not in r["fields"]
        ]
        b = [
            r
            for r in rs
            if r["record_type"] == "usn_record" and "record_offset" in r["fields"]
        ]
        if a and b and {_usn(r) for r in a} <= {_usn(r) for r in b}:
            card["evidence_records"] = [r for r in rs if r not in a]


def u_usn_dedupe_by_usn(case):
    for card in case["candidate_roster"]:
        seen, keep = set(), []
        rs = card["evidence_records"]
        for r in sorted(rs, key=lambda r: "record_offset" in r["fields"]):
            if r["record_type"] == "usn_record":
                if _usn(r) in seen:
                    continue
                seen.add(_usn(r))
            keep.append(r)
        card["evidence_records"] = [r for r in rs if r in keep]


def u_time_null_rows(case):
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            if r["record_type"] == "logfile_si_update":
                r["fields"]["timestamp_updates"] = [
                    u
                    for u in r["fields"]["timestamp_updates"]
                    if u.get("after_utc") is not None or u.get("before_utc") is not None
                ]


def u_delete_uniform_labels(case):
    for card in case["candidate_roster"]:
        oid = card.get("identity", {}).get("object_id")
        if oid:
            card["display_name"] += f" [object {':'.join(oid.split(':')[-2:])}]"


def u_exec_drop_files_loaded(case):
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            r["fields"].pop("files_loaded", None)


def u_log_sorted(case):
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            t = r["fields"].get("retained_event_records")
            if isinstance(t, dict) and "rows" in t:
                i = t["columns"].index("event_record_id")
                t["rows"].sort(key=lambda row: row[i])


PRESENTATION = {
    "BQ-TIME-01": [u_usn_complete_stream, u_usn_dedupe_by_usn, u_time_null_rows],
    "BQ-DELETE-01": [
        u_usn_complete_stream,
        u_usn_dedupe_by_usn,
        u_delete_uniform_labels,
    ],
    "BQ-SHELLBAG-01": [],
    "BQ-DIRECTORY-01": [],
    "BQ-STREAM-01": [],
    "BQ-USB-01": [],
    "BQ-FILE-01": [],
    "BQ-EXEC-01": [u_exec_drop_files_loaded],
    "BQ-LOG-01": [u_log_sorted],
}


def collection_sources(analysis: Path) -> dict:
    from fmb.index.adapters.mft import mftecmd_mft_context_csv_files
    from fmb.preparation.native import collected_kape_root

    index = read_json(analysis / "evidence_index.json")
    kape_root = collected_kape_root(analysis, {"parser_runs": [r for r in index["parser_runs"]
                                                            if r["parser_kind"] == "ntfs_mft"]})
    csvs = mftecmd_mft_context_csv_files(kape_root)
    if len(csvs) != 1:
        raise ValueError("the I-series build requires one complete current MFT listing")
    return {
        "mft_csv": Path(csvs[0]),
        "stream_bytes": analysis / "factual-supplement" / "native-ntfs",
    }


def listing_prefixes(cases: dict) -> tuple[set, set]:
    from fmb.analysis.inputs import ntfs_scope_and_reference_from_identity
    from fmb.index.support.windows_identity import windows_compare_path_parts

    prefixes, digests = set(), set()
    for qid in LISTING_QUESTIONS:
        if qid not in cases:
            continue
        for card in cases[qid]["candidate_roster"]:
            for pool in card.get("current_mft_pools") or []:
                digests.add(pool["source_sha256"])
            if ntfs_scope_and_reference_from_identity(card["identity"]):
                continue
            for record in card["evidence_records"]:
                _volume, path = windows_compare_path_parts(record["subject_ref"])
                if path and "\\" in path:
                    prefixes.add(path.rsplit("\\", 1)[0] + "\\")
    return prefixes, digests


def scan_listing(csv: Path, prefixes: set, digests: set) -> dict:
    from fmb.index.adapters.mft import mft_row_full_path
    from fmb.index.support.windows_identity import ntfs_reference_from_row, windows_compare_path_parts
    from fmb.index.support.windows_artifacts import parse_explicit_bool
    from fmb.index.support.windows_artifacts import row_value, stream_csv_rows

    digest = sha256_file(csv)
    if digests != {digest}:
        raise ValueError(
            "the listing on disk is not the source of the comparison pools"
        )
    rows, scanned, skipped = [], 0, 0
    for number, row in enumerate(stream_csv_rows(csv), 1):
        scanned += 1
        identity = ntfs_reference_from_row(
            row,
            entry_keys=("EntryNumber", "Entry Number"),
            sequence_keys=("SequenceNumber", "Sequence Number"),
        )
        state = parse_explicit_bool(row_value(row, "InUse", "In Use"))
        if identity is None or state is None:
            skipped += 1
            continue
        path = mft_row_full_path(row)
        normalized = windows_compare_path_parts(path)[1]
        under = sorted(p for p in prefixes if normalized.startswith(p))
        if under:
            rows.append(
                {
                    "entry": identity[0],
                    "sequence": identity[1],
                    "in_use": state,
                    "path": path,
                    "row": number,
                    "under": under,
                }
            )
    return {
        "csv_sha256": digest,
        "scanned_rows": scanned,
        "rows_without_identity_or_state": skipped,
        "prefixes": sorted(prefixes),
        "rows": rows,
    }


def denaive(case: dict, scan: dict, log: list) -> dict:
    from fmb.index.support.windows_identity import windows_compare_path_parts

    qid = case["question"]["question_id"]
    value = expand_refs(case)
    for card in value["candidate_roster"]:
        name = card["display_name"].split("\\")[-1]
        if "object_id" in card["identity"]:
            if qid == "BQ-DELETE-01":
                before = len(card["evidence_records"])
                card["evidence_records"] = [
                    r
                    for r in card["evidence_records"]
                    if r["record_type"] != "mft_record"
                ]
                if len(card["evidence_records"]) != before:
                    log.append(
                        {
                            "question": qid,
                            "card": name,
                            "step": "D1 own current MFT record not on the card",
                            "records_removed": before - len(card["evidence_records"]),
                        }
                    )
            continue
        paths = {
            windows_compare_path_parts(r["subject_ref"])[1]
            for r in card["evidence_records"]
        }
        if len(paths) != 1 or len(card["current_mft_pools"]) != 1:
            raise ValueError(
                f"{qid} {name}: not a single-path subject with one comparison pool"
            )
        path = paths.pop()
        prefix = path.rsplit("\\", 1)[0] + "\\"
        pool = card["current_mft_pools"][0]
        if (
            pool["path_prefixes"] != [path]
            or pool["entry_intervals"]
            or scan["csv_sha256"] != pool["source_sha256"]
        ):
            raise ValueError(
                f"{qid} {name}: the pool is not an exact-path query on the scanned listing"
            )
        listing = [
            {
                "entry": r["entry"],
                "sequence": r["sequence"],
                "in_use": r["in_use"],
                "path": r["path"],
                "source_record_ref": f"source:{scan['csv_sha256'][:16]}:row={r['row']}",
                "volume_relative_path": windows_compare_path_parts(r["path"])[1],
            }
            for r in sorted(
                (r for r in scan["rows"] if prefix in r["under"]),
                key=lambda r: r["row"],
            )
        ]
        if not {canonical_json(r) for r in pool["records"]} <= {
            canonical_json(r) for r in listing
        }:
            raise ValueError(
                f"{qid} {name}: the scanned listing does not contain the rows of the exact-path query"
            )
        log.append(
            {
                "question": qid,
                "card": name,
                "step": "D2 parent-folder listing",
                "rows_before": len(pool["records"]),
                "rows_after": len(listing),
            }
        )
        pool["path_prefixes"] = [prefix]
        pool["records"] = listing
    return compact_refs(value)


def stream_heads(case: dict, directory: Path) -> dict:
    heads = {}
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            f = r["fields"]
            if (
                r["record_type"] != "named_stream_native_content"
                or f.get("content_complete") is not True
            ):
                continue
            data = (
                directory
                / f"ads-{f['mft_entry']}-{f['sequence_number']}-{f['attribute_id']}.bin"
            ).read_bytes()
            if (
                hashlib.sha256(data).hexdigest() != f["content_sha256"]
                or len(data) != f["stream_size"]
            ):
                raise ValueError(
                    "retained stream bytes disagree with the card: "
                    + card["display_name"]
                )
            heads[f["content_sha256"]] = {
                "size": len(data),
                "head_hex": data[:STREAM_HEAD_BYTES].hex(),
                "complete": len(data) <= STREAM_HEAD_BYTES,
            }
    return heads


def volume_ids(case: dict) -> dict | None:
    pairs = set()
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            field = r["fields"].get("mft_volume_id")
            bound = (r.get("normalized_subject_path") or {}).get("mft_volume_id")
            if field and bound and field != bound:
                pairs.add((field, bound))
    if not pairs:
        return None
    if len(pairs) != 1:
        raise ValueError(
            "directory records name more than one pair of volume spellings"
        )
    original, canonical = pairs.pop()
    return {"canonical": canonical, "original": original}
