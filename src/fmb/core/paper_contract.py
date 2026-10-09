from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from fmb.core.paper_protocol import paper_protocol
from fmb.core.schemas import validate_response_schema
from fmb.core.sealed_records import canonical_json
from fmb.core.case_contract import (
    SCOPES as L0_SCOPES,
    response_schema as base_response_schema,
    validate_response as validate_status_lists,
)

_PLAIN_FINDING_NAMES = {
    "historical file-object absence": "historically referenced file object, now absent",
    "historical directory-path absence": "historically referenced directory path, now absent",
    "historical executable-path absence": "historically referenced executable path, now absent",
    "missing-directory browsing history": "historically browsed directory path, now absent",
}

_WINDOWS_ZONES = {"Pacific Standard Time": "America/Los_Angeles"}

_FLAG_RENAMES = {"identity_conflict": "source_identity_conflict"}

_GAP_OLD, _GAP_NEW = ("coverage_interval_gap_count", "time_coverage_gap_count")

_BASIS_OLD, _BASIS_NEW = ("plugin_naive_clock", "parser_value_without_zone")

LISTING_QUESTIONS = ("BQ-DELETE-01", "BQ-SHELLBAG-01", "BQ-EXEC-01")

_LISTING_COLUMNS = (
    "entry",
    "sequence",
    "in_use",
    "path",
    "volume_relative_path",
    "source_record_ref",
)

_LOCAL_ROWS_NOTE = "Current MFT comparison rows and their search scope are beside the corresponding historical observations. Row selection uses identities and paths, not assessment outcomes."

_LOCAL_ROWS_NOTE_TABLES = "Current MFT comparison rows and their search scope are in current_mft_listings, one table per search scope; each card names its tables in current_mft_listing_refs. Row selection uses identities and paths, not assessment outcomes."

_LOG_RETENTION_SENTENCE = "retained Security log interval only; records overwritten or cleared before the first retained record are unknown"

_SETUPAPI_RETENTION_SENTENCE = "timestamp envelope of parsed retained sections only; rotation, disabled logging and omitted sections are not ruled out, and installs outside the retained envelope are not observable"

_LOG_RETENTION_SCOPE_VALUE = "retained_interval_only_prior_overwrite_history_unknown"

_LOG_SCOPE_SCALARS = ("first_record_id", "last_record_id", "record_count")

_USB_DERIVED_FIELDS = (
    "referenced_entry_mft_active",
    "same_reference_mft_active",
    "same_reference_mft_paths",
)

STREAM_HEAD_BYTES = paper_protocol()["stream_head_bytes"]


def _slug(text: str) -> str:
    import re

    return re.sub("[^A-Za-z0-9._-]+", "-", text).strip("-")[:60]


def legible_id_map(case_l0: dict) -> dict[str, str]:
    result = {}
    for index, card in enumerate(case_l0["candidate_roster"], 1):
        name = _slug(card["display_name"].rsplit("\\", 1)[-1] or card["display_name"])
        for target in card["assessment_targets"]:
            phenomenon_slug = _slug(target["phenomenon"])
            result[target["finding_id"]] = (
                f"finding-{index:02d}-{name}-{phenomenon_slug}"
            )
    if len(set(result.values())) != len(result):
        seen = {}
        for hash_id, legible in list(result.items()):
            seen.setdefault(legible, []).append(hash_id)
        for legible, ids in seen.items():
            if len(ids) > 1:
                for hash_id in ids:
                    result[hash_id] = legible + "-" + hash_id.split(":")[1][:6]
    return result


def _rename_phenomena(case: dict, apply: bool) -> None:
    table = _PLAIN_FINDING_NAMES if apply else {v: k for k, v in _PLAIN_FINDING_NAMES.items()}
    for card in case["candidate_roster"]:
        for target in card["assessment_targets"]:
            target["phenomenon"] = table.get(target["phenomenon"], target["phenomenon"])


def _apply_legible_ids(case: dict) -> None:
    mapping = legible_id_map(case)
    for card in case["candidate_roster"]:
        for target in card["assessment_targets"]:
            target["finding_id"] = mapping[target["finding_id"]]
    case["presentation"]["finding_identifiers"] = (
        "Finding identifiers are labels formed from the card position, the display name and the phenomenon; they carry no information beyond the card."
    )


def _strip_legible_ids(case: dict) -> None:
    from fmb.analysis.factual_contract import component_ids
    from fmb.core.case_contract import PHENOMENA, finding_id

    note = case["presentation"].pop("finding_identifiers", None)
    if not note:
        raise ValueError("legible identifier note missing")
    qid = case["question"]["question_id"]
    for card in case["candidate_roster"]:
        components = component_ids(card, qid)
        if len(components) != len(card["assessment_targets"]):
            raise ValueError("target count differs from the applicable components")
        for component, target in zip(components, card["assessment_targets"]):
            if PHENOMENA[component] != target["phenomenon"]:
                raise ValueError(
                    "target phenomenon does not match the applicable component order"
                )
            target["finding_id"] = finding_id(card["subject_id"], component)


def _all_scopes(case: dict):
    for holder in [case] + list(case["candidate_roster"]):
        for entry in holder.get("coverage", []) or []:
            if isinstance(entry.get("scope"), dict):
                yield entry["scope"]


def _volume_pair(case: dict, options: dict | None):
    return ((options or {}).get("volume_ids") or {}).get(
        case["question"]["question_id"]
    )


def _toggle_boilerplate(holders, key: str, value: str, apply: bool, *, differs: str, present: str) -> None:
    for holder in holders:
        if apply:
            if holder.get(key) != value:
                raise ValueError(differs)
            del holder[key]
        else:
            if key in holder:
                raise ValueError(present)
            holder[key] = value


def _single_volume_id(case: dict, options: dict | None, apply: bool) -> None:
    pair = _volume_pair(case, options)
    if pair:
        src, dst = (
            (pair["original"], pair["canonical"])
            if apply
            else (pair["canonical"], pair["original"])
        )
        for card in case["candidate_roster"]:
            oid = card.get("identity", {}).get("object_id")
            if oid and src in oid:
                card["identity"]["object_id"] = oid.replace(src, dst)
            for r in card["evidence_records"]:
                if r["fields"].get("mft_volume_id") == src:
                    if (
                        apply
                        and (r.get("normalized_subject_path") or {}).get(
                            "mft_volume_id"
                        )
                        != dst
                    ):
                        raise ValueError(
                            "the preparation does not bind this record to the canonical volume"
                        )
                    r["fields"]["mft_volume_id"] = dst


def _neutral_flag_names(case: dict, options: dict | None, apply: bool) -> None:
    for scope in _all_scopes(case):
        for old, new in _FLAG_RENAMES.items():
            a, b = (old, new) if apply else (new, old)
            if a in scope:
                scope[b] = scope.pop(a)
        if scope.get("kind") != "security_event_log":
            a, b = (_GAP_OLD, _GAP_NEW) if apply else (_GAP_NEW, _GAP_OLD)
            if a in scope:
                scope[b] = scope.pop(a)
    a, b = (_BASIS_OLD, _BASIS_NEW) if apply else (_BASIS_NEW, _BASIS_OLD)
    for card in case["candidate_roster"]:
        for r in card["evidence_records"]:
            if r["fields"].get("timestamp_basis") == a:
                r["fields"]["timestamp_basis"] = b


def _setupapi_utc(case: dict, options: dict | None, apply: bool) -> None:
    import datetime
    import zoneinfo

    for card in case["candidate_roster"]:
        zone = next(
            (
                e["scope"].get("guest_time_zone")
                for e in card.get("coverage", []) or []
                if isinstance(e.get("scope"), dict)
                and e["scope"].get("kind") == "setupapi_log"
            ),
            None,
        )
        for r in card["evidence_records"]:
            f = r["fields"]
            if r["record_type"] != "setupapi_usb_event":
                continue
            if not apply:
                f.pop("event_timestamp_utc", None)
            elif f.get("timestamp_basis") == "local_clock" and zone:
                local = datetime.datetime.fromisoformat(
                    f["event_timestamp"]
                ).replace(tzinfo=zoneinfo.ZoneInfo(_WINDOWS_ZONES[zone]))
                f["event_timestamp_utc"] = (
                    local.astimezone(datetime.timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S.%f"
                    )
                    + "Z"
                )


def _shared_listing_tables(case: dict, options: dict | None, apply: bool) -> None:
    if case["question"]["question_id"] not in LISTING_QUESTIONS:
        return
    notes = case["preparation_notes"]
    if apply:
        listings, index = ([], {})
        for card in case["candidate_roster"]:
            refs = []
            for pool in card.pop("current_mft_pools", []):
                if any(
                    (set(row) != set(_LISTING_COLUMNS) for row in pool["records"])
                ):
                    raise ValueError(
                        "a pool row has unregistered fields; shared_listing_tables does not apply"
                    )
                key = canonical_json(pool)
                if key not in index:
                    index[key] = f"L{len(listings) + 1}"
                    listings.append(
                        {
                            "listing_id": index[key],
                            **{k: v for k, v in pool.items() if k != "records"},
                            "records": {
                                "columns": list(_LISTING_COLUMNS),
                                "rows": [
                                    [row[c] for c in _LISTING_COLUMNS]
                                    for row in pool["records"]
                                ],
                            },
                        }
                    )
                refs.append(index[key])
            card["current_mft_listing_refs"] = refs
        case["current_mft_listings"] = listings
        if notes.get("local_mft_records") != _LOCAL_ROWS_NOTE:
            raise ValueError("unexpected production note on local MFT records")
        notes["local_mft_records"] = _LOCAL_ROWS_NOTE_TABLES
    else:
        listings = {
            entry["listing_id"]: entry for entry in case.pop("current_mft_listings")
        }
        for card in case["candidate_roster"]:
            pools = []
            for ref in card.pop("current_mft_listing_refs"):
                pool = deepcopy(listings[ref])
                del pool["listing_id"]
                table = pool["records"]
                if table["columns"] != list(_LISTING_COLUMNS):
                    raise ValueError("listing columns altered")
                pool["records"] = [
                    dict(zip(table["columns"], row)) for row in table["rows"]
                ]
                pools.append(pool)
            card["current_mft_pools"] = pools
        if notes.get("local_mft_records") != _LOCAL_ROWS_NOTE_TABLES:
            raise ValueError("listing note missing or altered")
        notes["local_mft_records"] = _LOCAL_ROWS_NOTE


def _log_no_retention_sentence(case: dict, options: dict | None, apply: bool) -> None:
    _toggle_boilerplate(
        _log_scopes(case), "retention_basis", _LOG_RETENTION_SENTENCE, apply,
        differs="the retention sentence differs from the registered boilerplate; log_no_retention_sentence does not apply",
        present="retention sentence present in a sent log scope",
    )


def _setupapi_no_retention_sentence(case: dict, options: dict | None, apply: bool) -> None:
    _toggle_boilerplate(
        (scope for scope in _all_scopes(case) if scope.get("kind") == "setupapi_log"),
        "retention_basis", _SETUPAPI_RETENTION_SENTENCE, apply,
        differs="the setup-log retention sentence differs from the registered boilerplate; setupapi_no_retention_sentence does not apply",
        present="retention sentence present in a sent setup-log scope",
    )


def _log_no_retention_scope_value(case: dict, options: dict | None, apply: bool) -> None:
    _toggle_boilerplate(
        (r["fields"] for card in case["candidate_roster"] for r in card["evidence_records"]
         if r["record_type"] == "retained_security_event_inventory"),
        "retention_scope", _LOG_RETENTION_SCOPE_VALUE, apply,
        differs="the retention_scope value differs from the registered boilerplate; log_no_retention_scope_value does not apply",
        present="retention_scope present in a sent log record",
    )


def _no_scope(case: dict, options: dict | None, apply: bool) -> None:
    qid = case["question"]["question_id"]
    production = L0_SCOPES.get(qid)
    if production is None:
        return
    if apply:
        if case["question"].get("scope") != production:
            raise ValueError("scope differs from the production scope for " + qid)
        del case["question"]["scope"]
    else:
        if "scope" in case["question"]:
            raise ValueError(
                "a scope statement is present under the no_scope view for " + qid
            )
        case["question"]["scope"] = production


_CASE_VIEWS = {
    "single_volume_id": _single_volume_id,
    "neutral_flag_names": _neutral_flag_names,
    "setupapi_utc": _setupapi_utc,
    "shared_listing_tables": _shared_listing_tables,
    "log_no_retention_sentence": _log_no_retention_sentence,
    "setupapi_no_retention_sentence": _setupapi_no_retention_sentence,
    "log_no_retention_scope_value": _log_no_retention_scope_value,
    "no_scope": _no_scope,
}


def _case_view(case: dict, name: str, options: dict | None, apply: bool) -> bool:
    view = _CASE_VIEWS.get(name)
    if view is None:
        return False
    view(case, options, apply)
    return True


def _log_scopes(case: dict):
    return (scope for scope in _all_scopes(case) if scope.get("kind") == "security_event_log")


def _usb_derived(fields: dict) -> dict:
    reference = fields["link_file_reference_number"]
    entry, sequence = (reference & (1 << 48) - 1, reference >> 48)
    rows = [r for r in fields["companion_directory_rows"] if r["entry"] == entry]
    if (
        len(rows) != 1
        or fields.get("referenced_entry_mft_entry") != entry
        or fields.get("referenced_entry_mft_sequence") != rows[0]["sequence"]
    ):
        raise ValueError(
            "the referenced entry is not listed exactly once in the companion directory rows"
        )
    row = rows[0]
    exact = row["sequence"] == sequence
    return {
        "referenced_entry_mft_active": row["in_use"],
        "same_reference_mft_active": row["in_use"] if exact else None,
        "same_reference_mft_paths": [row["path"]] if exact else [],
    }


def _stream_parser_fields(head: bytes, size: int) -> dict:
    from fmb.analysis.evidence_projection import _FORMAT_ENTRY_FIELDS
    from fmb.index.adapters.stream_content import executable_content_fields
    from fmb.index.scanners.zip_content import zip_content_fields

    if len(head) != min(size, STREAM_HEAD_BYTES):
        raise ValueError("the carried stream bytes do not match the stream size")
    if len(head) < size and head[:2] == b"PK":
        raise ValueError("an archive longer than the carried bytes is not derivable")
    data = head + bytes(size - len(head))
    derived = {**executable_content_fields(data), **zip_content_fields(data)}
    out = {
        k: v
        for k, v in derived.items()
        if (k == "dos_signature_hex" or k.startswith(("pe_", "zip_")))
        and k not in ("pe_structure_status", "zip_structure_status")
    }
    for key, names in _FORMAT_ENTRY_FIELDS.items():
        if key in out:
            out[key] = [
                {k: v for k, v in item.items() if k in names} for item in out[key]
            ]
    return out


def _view_apply(case: dict, name: str, options: dict | None = None) -> None:
    if _case_view(case, name, options, True):
        return
    if name == "log_no_scalars_v2":
        for scope in _log_scopes(case):
            for k in _LOG_SCOPE_SCALARS:
                del scope[k]
            scope["time_coverage_gap_count"] = scope.pop("coverage_interval_gap_count")
    for card in case["candidate_roster"]:
        rs = card["evidence_records"]
        if name == "stream_bytes_only":
            heads = None
            for r in rs:
                f = r["fields"]
                if (
                    r["record_type"] != "named_stream_native_content"
                    or f.get("content_complete") is not True
                ):
                    continue
                if heads is None:
                    heads = _stream_heads(options)
                kept = heads[f["content_sha256"]]
                if kept["size"] != f["stream_size"]:
                    raise ValueError(
                        "the retained stream bytes do not belong to this record"
                    )
                prepared = {
                    k: v
                    for k, v in f.items()
                    if k == "dos_signature_hex" or k.startswith(("pe_", "zip_"))
                }
                if (
                    _stream_parser_fields(
                        bytes.fromhex(kept["head_hex"]), f["stream_size"]
                    )
                    != prepared
                ):
                    raise ValueError(
                        "the parser fields are not derivable from the carried bytes; stream_bytes_only does not apply"
                    )
                for k in prepared:
                    del f[k]
                f["content_first_bytes_hex"] = kept["head_hex"]
        elif name == "usb_rows_only":
            for r in rs:
                f = r["fields"]
                if r["record_type"] != "native_usb_reference_history":
                    continue
                if _usb_derived(f) != {k: f[k] for k in _USB_DERIVED_FIELDS}:
                    raise ValueError(
                        "the USB lookup fields are not derivable from the directory rows; usb_rows_only does not apply"
                    )
                for k in _USB_DERIVED_FIELDS:
                    del f[k]
        elif name == "log_no_scalars_v2":
            for r in rs:
                f = r["fields"]
                if isinstance(f.get("retained_event_records"), dict):
                    for k in (
                        "first_event_record_id",
                        "last_event_record_id",
                        "record_count",
                    ):
                        del f[k]
        elif name == "dir_declutter":
            scans = [r for r in rs if r["record_type"] == "directory_index_scan"]
            if len(scans) != 1:
                continue
            scan = scans[0]["fields"]
            for r in rs:
                f = r["fields"]
                if r["record_type"] != "directory_index_entry":
                    continue
                same = (
                    f["mft_entry"] == scan["mft_entry"]
                    and f["sequence_number"] == scan["sequence_number"]
                    and (f["parent_reference_entry"] == scan["mft_entry"])
                    and (f["parent_reference_sequence"] == scan["sequence_number"])
                    and (f["directory_path"] == scan["directory_path"])
                    and (f["mft_volume_id"] == scan["mft_volume_id"])
                    and (
                        f["entry_path"] == f["directory_path"] + "\\" + f["entry_name"]
                    )
                )
                if not same:
                    raise ValueError(
                        "a residue entry differs from its scan record; dir_declutter does not apply"
                    )
                for k in (
                    "mft_entry",
                    "sequence_number",
                    "parent_reference_entry",
                    "parent_reference_sequence",
                    "directory_path",
                    "mft_volume_id",
                    "entry_path",
                ):
                    del f[k]
                f["entry"] = f.pop("file_reference_entry")
                f["sequence"] = f.pop("file_reference_sequence")
            for pool in card.get("current_mft_pools", []) or []:
                for row in pool["records"]:
                    if (
                        row["volume_relative_path"]
                        != row["path"].lstrip(".").lstrip("\\").lower()
                    ):
                        raise ValueError(
                            "a pool path has no single spelling; dir_declutter does not apply"
                        )
                    del row["volume_relative_path"]
        elif name == "one_entry_per_identity":
            keep, byid = ([], {})
            for r in rs:
                f = r["fields"]
                if r["record_type"] != "directory_index_entry":
                    keep.append(r)
                    continue
                k = (
                    f["file_reference_entry"],
                    f["file_reference_sequence"],
                    f.get("i30_entry_state"),
                    f.get("residue_surface"),
                )
                if (
                    k in byid
                    and "~" in f["entry_name"]
                    and ("entry_short_name" not in byid[k]["fields"])
                ):
                    byid[k]["fields"]["entry_short_name"] = f["entry_name"]
                    byid[k]["fields"]["entry_short_name_source_record_ref"] = r[
                        "source_record_ref"
                    ]
                else:
                    byid.setdefault(k, r)
                    keep.append(r)
            card["evidence_records"] = keep


def _view_strip(case: dict, name: str, options: dict | None = None) -> None:
    if _case_view(case, name, options, False):
        return
    if name == "log_no_scalars_v2":
        ids = []
        for card in case["candidate_roster"]:
            for r in card["evidence_records"]:
                table = r["fields"].get("retained_event_records")
                if isinstance(table, dict):
                    i = table["columns"].index("event_record_id")
                    ids += [row[i] for row in table["rows"]]
        for scope in _log_scopes(case):
            if "record_count" not in scope:
                (
                    scope["first_record_id"],
                    scope["last_record_id"],
                    scope["record_count"],
                ) = (min(ids), max(ids), len(ids))
                scope["coverage_interval_gap_count"] = scope.pop(
                    "time_coverage_gap_count"
                )
    for card in case["candidate_roster"]:
        rs = card["evidence_records"]
        if name == "stream_bytes_only":
            for r in rs:
                f = r["fields"]
                if "content_first_bytes_hex" in f:
                    f.update(
                        _stream_parser_fields(
                            bytes.fromhex(f.pop("content_first_bytes_hex")),
                            f["stream_size"],
                        )
                    )
        elif name == "usb_rows_only":
            for r in rs:
                f = r["fields"]
                if (
                    r["record_type"] == "native_usb_reference_history"
                    and "referenced_entry_mft_active" not in f
                ):
                    f.update(_usb_derived(f))
        elif name == "log_no_scalars_v2":
            for r in rs:
                f = r["fields"]
                table = f.get("retained_event_records")
                if isinstance(table, dict) and "first_event_record_id" not in f:
                    i = table["columns"].index("event_record_id")
                    ids = [row[i] for row in table["rows"]]
                    (
                        f["first_event_record_id"],
                        f["last_event_record_id"],
                        f["record_count"],
                    ) = (min(ids), max(ids), len(ids))
        elif name == "dir_declutter":
            scans = [r for r in rs if r["record_type"] == "directory_index_scan"]
            if len(scans) != 1:
                continue
            scan = scans[0]["fields"]
            for r in rs:
                f = r["fields"]
                if r["record_type"] == "directory_index_entry" and "mft_entry" not in f:
                    f["file_reference_entry"] = f.pop("entry")
                    f["file_reference_sequence"] = f.pop("sequence")
                    f["mft_entry"], f["sequence_number"] = (
                        scan["mft_entry"],
                        scan["sequence_number"],
                    )
                    f["parent_reference_entry"], f["parent_reference_sequence"] = (
                        scan["mft_entry"],
                        scan["sequence_number"],
                    )
                    f["directory_path"], f["mft_volume_id"] = (
                        scan["directory_path"],
                        scan["mft_volume_id"],
                    )
                    f["entry_path"] = f["directory_path"] + "\\" + f["entry_name"]
            for pool in card.get("current_mft_pools", []) or []:
                for row in pool["records"]:
                    if "volume_relative_path" not in row:
                        row["volume_relative_path"] = (
                            row["path"].lstrip(".").lstrip("\\").lower()
                        )
        elif name == "one_entry_per_identity":
            full = []
            for r in rs:
                full.append(r)
                f = r["fields"]
                if "entry_short_name" in f:
                    twin = deepcopy(r)
                    short = f.pop("entry_short_name")
                    ref = f.pop("entry_short_name_source_record_ref")
                    tf = twin["fields"]
                    del tf["entry_short_name"], tf["entry_short_name_source_record_ref"]
                    tf["entry_name"] = short
                    tf["entry_path"] = (
                        tf["entry_path"].rsplit("\\", 1)[0] + "\\" + short
                    )
                    twin["source_record_ref"] = ref
                    full.append(twin)
            card["evidence_records"] = full


def _note_applies(case: dict, name: str, options: dict) -> bool:
    if not options.get("notes_where_present"):
        return True
    cards = case.get("candidate_roster", [])
    types = {
        r.get("record_type") for card in cards for r in card.get("evidence_records", [])
    }
    tables = (
        "shared_listing_tables" in (options.get("views") or [])
        and case.get("question", {}).get("question_id") in LISTING_QUESTIONS
    )
    if name == "pool_semantics":
        return any((card.get("current_mft_pools") for card in cards)) and (not tables)
    if name == "listing_semantics":
        return any((card.get("current_mft_pools") for card in cards)) and tables
    if name == "index_scan_counts":
        return "directory_index_scan" in types
    if name == "stream_content_bytes":
        return "named_stream_native_content" in types
    return True


PRESENTATION_NOTES = {
    "listing_semantics": (
        "current_mft_listings",
        "Each table in current_mft_listings lists every current MFT record whose "
        "volume-relative path starts with a listed path prefix (path_complete: "
        "true) or whose entry number lies in a listed entry interval, in every "
        "generation and allocation state, one record per row under the named "
        "columns; a card names the tables that belong to its subject in "
        "current_mft_listing_refs; a table without rows means that this search of "
        "the complete current MFT returned no record.",
    ),
    "pool_semantics": (
        "current_mft_pools",
        "Each current MFT pool lists every current MFT record whose volume-relative "
        "path starts with a listed path prefix (path_complete: true) or whose entry "
        "number lies in a listed entry interval, in every generation and allocation "
        "state; an empty records list means that this search of the complete current "
        "MFT returned no record.",
    ),
    "index_scan_counts": (
        "directory_index_scan_counts",
        "The entry counts of a directory_index_scan record count the entries the "
        "scan parsed on each surface, active entries included; only residue entries "
        "are listed as directory_index_entry records.",
    ),
    "stream_content_bytes": (
        "named_stream_content_bytes",
        "For a named stream whose content_complete is true the preparation read "
        "the complete bytes of the stream; content_first_bytes_hex holds the "
        "leading bytes as hexadecimal text: the whole stream when stream_size is "
        "at most 1024 bytes, otherwise its first 1024 bytes.",
    ),
}

PAPER_VIEWS = (
    "stream_bytes_only",
    "usb_rows_only",
    "one_entry_per_identity",
    "log_no_scalars_v2",
    "dir_declutter",
    "single_volume_id",
    "setupapi_utc",
    "neutral_flag_names",
    "no_scope",
    "log_no_retention_sentence",
    "log_no_retention_scope_value",
    "setupapi_no_retention_sentence",
    "shared_listing_tables",
)
REASONS_DESCRIPTION = "For every finding_id, one sentence naming the supplied records or coverage statements on which the status rests."


def validate_options(options: dict | None) -> dict:
    options = deepcopy(options or {})
    allowed = {
        "notes",
        "notes_where_present",
        "views",
        "legible_ids",
        "plain_finding_names",
        "stated_reasons",
        "stream_heads_path",
        "volume_ids",
    }
    if set(options) - allowed:
        raise ValueError(
            "options outside the paper protocol: "
            + ", ".join(sorted(set(options) - allowed))
        )
    for key, names in (("views", PAPER_VIEWS), ("notes", PRESENTATION_NOTES)):
        values = options.get(key, [])
        if (
            not isinstance(values, list)
            or len(values) != len(set(values))
            or set(values) - set(names)
        ):
            raise ValueError("invalid paper " + key)
    for key in ("notes_where_present", "legible_ids", "stated_reasons"):
        if key in options and type(options[key]) is not bool:
            raise ValueError(key + " must be boolean")
    if options.get("plain_finding_names") not in (None, "v2"):
        raise ValueError("the paper uses plain_finding_names v2")
    return options


def bind_options(options: dict | None, build: Path | None) -> dict:
    from fmb.core.sealed_records import contained_path

    options = validate_options(options)
    value = options.get("stream_heads_path")
    if value and build is not None and not Path(value).is_absolute():
        options["stream_heads_path"] = str(contained_path(build, value))
    return options


def _stream_heads(options: dict | None) -> dict:
    path = Path((options or {}).get("stream_heads_path", ""))
    if not path.is_absolute():
        raise ValueError(
            "new paper preparation needs an explicit absolute stream-head file"
        )
    from fmb.core.sealed_records import read_json

    return read_json(path)


def encode(case: dict, options: dict | None = None) -> dict:
    options = validate_options(options)
    value = deepcopy(case)
    for name in options.get("notes", []):
        if _note_applies(value, name, options):
            key, text = PRESENTATION_NOTES[name]
            notes = value.setdefault("preparation_notes", {})
            if key in notes:
                raise ValueError("presentation note already present: " + key)
            notes[key] = text
    for name in options.get("views", []):
        _view_apply(value, name, options)
    if options.get("plain_finding_names"):
        _rename_phenomena(value, True)
    if options.get("legible_ids"):
        _apply_legible_ids(value)
    return value


def decode_case(case: dict, options: dict | None = None) -> dict:
    options = validate_options(options)
    value = deepcopy(case)
    if options.get("plain_finding_names"):
        _rename_phenomena(value, False)
    if options.get("legible_ids"):
        _strip_legible_ids(value)
    for name in reversed(options.get("views", [])):
        _view_strip(value, name, options)
    for name in options.get("notes", []):
        if _note_applies(value, name, options):
            key, text = PRESENTATION_NOTES[name]
            if value.get("preparation_notes", {}).get(key) != text:
                raise ValueError("presentation note missing or altered: " + key)
            del value["preparation_notes"][key]
    return value


def response_schema(sent_case: dict, *, stated_reasons: bool = True) -> dict:
    schema = base_response_schema(sent_case)
    if stated_reasons:
        ids = sorted(
            t["finding_id"]
            for c in sent_case["candidate_roster"]
            for t in c["assessment_targets"]
        )
        schema["properties"]["reasons"] = {
            "type": "object",
            "properties": {fid: {"type": "string"} for fid in ids},
            "required": ids,
            "additionalProperties": False,
            "description": REASONS_DESCRIPTION,
        }
        schema["required"] = ["supported_findings", "insufficient_findings", "reasons"]
    return schema


def _named_case(case: dict, options: dict) -> dict:
    named = deepcopy(case)
    if options.get("plain_finding_names"):
        _rename_phenomena(named, True)
    return named


def finding_display_ids(case: dict, options: dict | None = None) -> dict[str, str]:
    options = validate_options(options)
    if options.get("legible_ids"):
        return legible_id_map(_named_case(case, options))
    return {
        target["finding_id"]: target["finding_id"]
        for card in case["candidate_roster"]
        for target in card["assessment_targets"]
    }


def to_two_list(
    case: dict,
    response: dict,
    options: dict | None = None,
    *,
    sent_schema: dict | None = None,
) -> dict:
    options = validate_options(options)
    named = _named_case(case, options)
    mapping = finding_display_ids(case, options)
    for card in named["candidate_roster"]:
        for target in card["assessment_targets"]:
            target["finding_id"] = mapping[target["finding_id"]]
    schema = response_schema(named, stated_reasons=options.get("stated_reasons", True))
    if sent_schema is not None:
        validate_response_schema(response, sent_schema)
    validate_response_schema(response, schema)
    inverse = {display: original for original, display in mapping.items()}
    normalized = {
        key: [inverse[fid] for fid in response[key]]
        for key in ("supported_findings", "insufficient_findings")
    }
    validate_status_lists(case, normalized)
    return {key: sorted(values) for key, values in normalized.items()}
