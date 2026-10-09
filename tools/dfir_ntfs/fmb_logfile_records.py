#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time

from dfir_ntfs import LogFile

SCHEMA_VERSION = "fmb_logfile_records.v2"
DRIVER_VERSION = "2"
DEFAULT_OPS = (
    "UpdateResidentValue",
    "InitializeFileRecordSegment",
    "DeallocateFileRecordSegment",
)
LIFECYCLE_OPS = {"InitializeFileRecordSegment", "DeallocateFileRecordSegment"}
USN_JOURNAL_ATTRIBUTE = "$J"
NAME_BY_CODE = dict(LogFile.NTFSOperations)
CODE_BY_NAME = {name: code for code, name in NAME_BY_CODE.items()}
PAGE_SIGNATURES = {b"RCRD": "record", b"CHKD": "checkdisk", b"RSTR": "restart"}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def usn_v2_summary(buf: bytes) -> dict | None:
    if len(buf) < 60:
        return None
    length, major, _minor = struct.unpack_from("<LHH", buf, 0)
    if major != 2 or length < 60 or length > len(buf):
        return None
    file_ref, parent_ref, usn, timestamp, reason = struct.unpack_from("<QQQQL", buf, 8)
    return {
        "record_length": int(length),
        "file_reference_number": int(file_ref),
        "parent_file_reference_number": int(parent_ref),
        "usn": int(usn),
        "timestamp_filetime": int(timestamp),
        "reason": int(reason),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit selected NTFS $LogFile client records as JSON.")
    parser.add_argument("--logfile", required=True, help="raw $LogFile copy")
    parser.add_argument("--output", required=True, help="JSON document to write")
    parser.add_argument(
        "--ops",
        default=",".join(DEFAULT_OPS),
        help="comma-separated NTFS operation names selecting the records to emit",
    )
    parser.add_argument(
        "--usn-pages",
        action="store_true",
        help="also emit the USN journal page writes logged through $LogFile",
    )
    parser.add_argument("--max-records", type=int, default=500_000)
    parser.add_argument(
        "--no-recovery",
        action="store_true",
        help="do not apply the tail/fast log pages before parsing",
    )
    return parser.parse_args(argv)


def restart_area_document(item: LogFile.NTFSRestartArea) -> dict:
    document = {"lsn": int(item.lsn)}
    for key, getter in (
        ("major_version", item.get_major_version),
        ("minor_version", item.get_minor_version),
        ("start_of_checkpoint_lsn", item.get_start_of_checkpoint_lsn),
        ("open_attribute_table_lsn", item.get_open_attribute_table_lsn),
        ("attribute_names_lsn", item.get_attribute_names_lsn),
        ("dirty_page_table_lsn", item.get_dirty_page_table_lsn),
        ("transaction_table_lsn", item.get_transaction_table_lsn),
        ("usn_journal_restart_offset", item.get_usn_journal_restart_offset),
        ("last_lsn", item.get_last_lsn),
        ("bytes_per_cluster", item.get_bytes_per_cluster),
        ("usn_journal_reference", item.get_usn_journal_reference),
        ("usn_base", item.get_usn_base),
        ("oldest_lsn", item.get_oldest_lsn),
    ):
        try:
            value = getter()
        except (LogFile.LogFileException, struct.error, IndexError):
            value = None
        document[key] = int(value) if isinstance(value, int) else value
    return document


def record_document(item: LogFile.NTFSLogRecord, redo: int, undo: int, *, with_data: bool = True) -> dict:
    try:
        lcns = [int(value) for value in item.get_lcns_for_page()]
    except LogFile.ClientException:
        lcns = None
    try:
        mft_target = item.calculate_mft_target_number()
    except LogFile.ClientException:
        mft_target = None
    try:
        offset_in_target = item.calculate_offset_in_target()
    except LogFile.ClientException:
        offset_in_target = None
    nonresident = None
    if mft_target is None:
        try:
            target = item.calculate_mft_target_reference_and_name()
        except LogFile.ClientException:
            target = None
        if target is not None:
            reference, name = target
            nonresident = {
                "file_reference": int(reference),
                "file_reference_entry": int(reference) & 0x0000FFFFFFFFFFFF,
                "file_reference_sequence": int(reference) >> 48,
                "attribute_name": name,
            }
    document = {
        "lsn": int(item.lsn),
        "client_id": None,
        "transaction_id": int(item.transaction_id),
        "redo_operation": int(redo),
        "redo_operation_name": NAME_BY_CODE.get(redo, f"0x{redo:02x}"),
        "undo_operation": int(undo),
        "undo_operation_name": NAME_BY_CODE.get(undo, f"0x{undo:02x}"),
        "target_attribute": int(item.get_target_attribute()),
        "target_block_size": int(item.get_target_block_size()),
        "target_vcn": int(item.get_target_vcn()),
        "cluster_block_offset": int(item.get_cluster_block_offset()),
        "record_offset": int(item.get_record_offset()),
        "attribute_offset": int(item.get_attribute_offset()),
        "mft_target_number": int(mft_target) if mft_target is not None else None,
        "offset_in_target": int(offset_in_target) if offset_in_target is not None else None,
        "nonresident_target": nonresident,
        "lcns": lcns,
        "transaction_forgotten_lsn": None,
        "transaction_rolled_back": False,
    }
    if with_data:
        redo_data = item.get_redo_data()
        undo_data = item.get_undo_data()
        document.update(
            {
                "redo_length": len(redo_data),
                "undo_length": len(undo_data),
                "redo_hex": redo_data.hex(),
                "undo_hex": undo_data.hex(),
            }
        )
    return document


def page_coverage(parser: LogFile.LogFileParser) -> dict:
    page_size = int(parser.log_page_size)
    file_object = parser.file_object
    file_object.seek(0, 2)
    total = file_object.tell() // page_size
    counts = {
        "page_size": page_size,
        "page_count": int(total),
        "restart_page_count": 0,
        "record_page_count": 0,
        "record_page_failure_count": 0,
        "checkdisk_page_count": 0,
        "unused_page_count": 0,
        "unknown_page_count": 0,
        "first_failed_record_pages": [],
    }
    filler = {b"\xff" * page_size, b"\x00" * page_size}
    for number in range(total):
        file_object.seek(number * page_size)
        buf = file_object.read(page_size)
        if len(buf) != page_size:
            counts["unknown_page_count"] += 1
            continue
        signature = PAGE_SIGNATURES.get(buf[:4])
        if signature == "restart":
            counts["restart_page_count"] += 1
            continue
        if signature == "checkdisk":
            counts["checkdisk_page_count"] += 1
            continue
        if signature == "record":
            try:
                LogFile.LogRecordPage(buf, number, parser.log_page_data_offset)
            except (LogFile.LogFileException, NotImplementedError):
                counts["record_page_failure_count"] += 1
                if len(counts["first_failed_record_pages"]) < 16:
                    counts["first_failed_record_pages"].append(number)
            else:
                counts["record_page_count"] += 1
            continue
        if buf in filler:
            counts["unused_page_count"] += 1
            continue
        counts["unknown_page_count"] += 1
    counts["page_coverage_complete"] = (
        counts["record_page_failure_count"] == 0 and counts["unknown_page_count"] == 0
    )
    return counts


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    selected_names = [name for name in args.ops.split(",") if name.strip()]
    unknown = sorted(set(selected_names) - set(CODE_BY_NAME))
    if unknown:
        print("unknown NTFS operation name(s): " + ", ".join(unknown), file=sys.stderr)
        return 2
    selected = {CODE_BY_NAME[name] for name in selected_names}
    started = time.time()
    size_bytes = os.path.getsize(args.logfile)
    logfile_sha256 = sha256_file(args.logfile)

    records: list[dict] = []
    lifecycle_records: list[dict] = []
    restart_areas: list[dict] = []
    operation_counts: dict[str, int] = {}
    ledger: list[tuple[int, int, int, int]] = []
    usn_window: dict = {
        "record_count": 0,
        "first_usn": None,
        "first_timestamp_filetime": None,
        "last_usn": None,
        "last_timestamp_filetime": None,
        "min_timestamp_filetime": None,
        "max_timestamp_filetime": None,
        "journal_file_reference": None,
    }
    counters = {
        "record_count": 0,
        "restart_area_count": 0,
        "parse_error_count": 0,
        "emitted_record_count": 0,
        "lifecycle_record_count": 0,
        "records_truncated": False,
        "forgotten_transaction_count": 0,
        "rolled_back_transaction_count": 0,
    }
    lsn_first = None
    lsn_last = None

    with open(args.logfile, "rb") as handle:
        parser = LogFile.LogFileParser(handle)
        log_version = list(parser.log_version)
        log_page_size = int(parser.log_page_size)
        for item in parser.parse_ntfs_records(recover_log_data=not args.no_recovery):
            if isinstance(item, LogFile.NTFSRestartArea):
                counters["restart_area_count"] += 1
                restart_areas.append(restart_area_document(item))
                continue
            if not isinstance(item, LogFile.NTFSLogRecord):
                continue
            counters["record_count"] += 1
            lsn = int(item.lsn)
            if lsn_first is None or lsn < lsn_first:
                lsn_first = lsn
            if lsn_last is None or lsn > lsn_last:
                lsn_last = lsn
            try:
                redo = item.get_redo_operation()
                undo = item.get_undo_operation()
            except LogFile.ClientException:
                counters["parse_error_count"] += 1
                continue
            key = f"{NAME_BY_CODE.get(redo, hex(redo))}/{NAME_BY_CODE.get(undo, hex(undo))}"
            operation_counts[key] = operation_counts.get(key, 0) + 1
            txid = int(item.transaction_id)
            ledger.append((lsn, txid, int(redo), int(undo)))
            emit = redo in selected or undo in selected
            usn_page = False
            if redo == LogFile.UpdateNonresidentValue or undo == LogFile.UpdateNonresidentValue:
                try:
                    target = item.calculate_mft_target_reference_and_name()
                except LogFile.ClientException:
                    target = None
                if target is not None and target[1] == USN_JOURNAL_ATTRIBUTE:
                    usn_page = True
                    summary = usn_v2_summary(item.get_redo_data())
                    if summary is not None:
                        usn_window["record_count"] += 1
                        usn_window["journal_file_reference"] = int(target[0])
                        if usn_window["first_usn"] is None:
                            usn_window["first_usn"] = summary["usn"]
                            usn_window["first_timestamp_filetime"] = summary["timestamp_filetime"]
                        usn_window["last_usn"] = summary["usn"]
                        usn_window["last_timestamp_filetime"] = summary["timestamp_filetime"]
                        stamp = summary["timestamp_filetime"]
                        if usn_window["min_timestamp_filetime"] is None or stamp < usn_window["min_timestamp_filetime"]:
                            usn_window["min_timestamp_filetime"] = stamp
                        if usn_window["max_timestamp_filetime"] is None or stamp > usn_window["max_timestamp_filetime"]:
                            usn_window["max_timestamp_filetime"] = stamp
                    if args.usn_pages:
                        emit = True
            if NAME_BY_CODE.get(redo) in LIFECYCLE_OPS or NAME_BY_CODE.get(undo) in LIFECYCLE_OPS:
                try:
                    lifecycle_records.append(record_document(item, redo, undo, with_data=False))
                    counters["lifecycle_record_count"] += 1
                except (LogFile.ClientException, struct.error):
                    counters["parse_error_count"] += 1
            if not emit:
                continue
            if len(records) >= args.max_records:
                counters["records_truncated"] = True
                continue
            try:
                document = record_document(item, redo, undo)
            except (LogFile.ClientException, struct.error):
                counters["parse_error_count"] += 1
                continue
            if usn_page:
                document["usn_record"] = usn_v2_summary(item.get_redo_data())
            records.append(document)
            counters["emitted_record_count"] += 1
        client_by_lsn: dict[int, int] = {}
        for client_id, lsns in getattr(parser, "lsns_sorted", {}).items():
            for lsn in lsns:
                client_by_lsn[int(lsn)] = int(client_id)
        pages = page_coverage(parser)

    client_record_counts: dict[str, int] = {}
    for lsn, _txid, _redo, _undo in ledger:
        client = client_by_lsn.get(lsn)
        client_record_counts[str(client)] = client_record_counts.get(str(client), 0) + 1
    emitted_by_lsn: dict[int, list[dict]] = {}
    for document in records:
        emitted_by_lsn.setdefault(document["lsn"], []).append(document)
    for document in lifecycle_records:
        emitted_by_lsn.setdefault(document["lsn"], []).append(document)
    pending: dict[tuple[int | None, int], dict] = {}
    for lsn, txid, redo, undo in sorted(ledger):
        client = client_by_lsn.get(lsn)
        for document in emitted_by_lsn.get(lsn, []):
            document["client_id"] = client
        key = (client, txid)
        if redo == LogFile.ForgetTransaction:
            state = pending.pop(key, None)
            counters["forgotten_transaction_count"] += 1
            if state is not None:
                if state["rolled_back"]:
                    counters["rolled_back_transaction_count"] += 1
                for member_lsn in state["lsns"]:
                    for document in emitted_by_lsn.get(member_lsn, []):
                        document["transaction_forgotten_lsn"] = lsn
                        document["transaction_rolled_back"] = state["rolled_back"]
            continue
        state = pending.setdefault(key, {"lsns": [], "rolled_back": False})
        if undo == LogFile.CompensationLogRecord:
            state["rolled_back"] = True
        if lsn in emitted_by_lsn:
            state["lsns"].append(lsn)

    document = {
        "schema_version": SCHEMA_VERSION,
        "driver": {"name": "fmb_logfile_records", "version": DRIVER_VERSION, "license": "GPL-3.0-or-later"},
        "tool": {
            "name": "dfir_ntfs",
            "module_file": os.path.abspath(LogFile.__file__),
            "python": sys.version.split()[0],
        },
        "logfile": {"path": os.path.abspath(args.logfile), "size_bytes": size_bytes, "sha256": logfile_sha256},
        "selection": {
            "operations": selected_names,
            "usn_pages": bool(args.usn_pages),
            "max_records": int(args.max_records),
            "recover_log_data": not args.no_recovery,
        },
        "parse": {
            "log_version": log_version,
            "log_page_size": log_page_size,
            "lsn_first": lsn_first,
            "lsn_last": lsn_last,
            **counters,
            "open_transaction_count": len(pending),
            "client_count": len(client_record_counts),
            "client_record_counts": client_record_counts,
            "multi_client": len(client_record_counts) > 1,
            **pages,
            "duration_seconds": round(time.time() - started, 3),
        },
        "operation_counts": dict(sorted(operation_counts.items())),
        "embedded_usn": usn_window,
        "restart_areas": restart_areas,
        "lifecycle_records": lifecycle_records,
        "records": records,
    }
    tmp = args.output + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"))
    os.replace(tmp, args.output)
    summary = {k: document["parse"][k] for k in ("record_count", "emitted_record_count", "lifecycle_record_count", "parse_error_count", "record_page_failure_count", "client_count", "duration_seconds")}
    summary["embedded_usn_record_count"] = usn_window["record_count"]
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
