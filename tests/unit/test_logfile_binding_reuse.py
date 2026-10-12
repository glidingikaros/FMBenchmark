from __future__ import annotations

import json
import os
import random
import struct
from pathlib import Path

import pytest
from test_logfile_adapter import VOLUME, driver_document, mft_context
from test_logfile_scanner import FILETIME_2010, FILETIME_2026_A, FILETIME_2026_B, file_record_bytes

from fmb.index.adapters import logfile as logfile_adapters
from fmb.index.scanners.logfile import si_update_variants_from_records, si_updates_from_records
from fmb.pipeline import reads

REFERENCES = {(entry, 3) for entry in range(10, 16)} | {(17, 1)}
TIMES = (FILETIME_2010, FILETIME_2026_A, FILETIME_2026_B)


def mft_bytes(*, times: tuple[int, ...] = TIMES) -> bytes:
    table = bytearray(1024 * 18)
    table[2 * 1024 : 3 * 1024] = b"FILE" + bytes(1020)
    for entry in range(10, 18):
        table[entry * 1024 : (entry + 1) * 1024] = file_record_bytes(
            entry=entry, sequence=3 if entry < 16 else 1, lsn=5000 if entry != 13 else 50,
            in_use=entry != 14, file_name=f"file{entry}.txt",
            si_times=tuple(times[(entry + field) % len(times)] for field in range(4)),
        )
    # Entry 16's first attribute is no longer a standard information attribute.
    struct.pack_into("<I", table, 16 * 1024 + 56, 0x40)
    return bytes(table)


def log_records(seed: int = 7, count: int = 600) -> list[dict[str, object]]:
    # Whole and partial timestamp updates, with and without an undo the fragments come from,
    # and every reason an update stays unbound.
    rng = random.Random(seed)
    records: list[dict[str, object]] = []
    for lsn in range(100, 100 + 7 * count, 7):
        entry = rng.choice([2, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18])
        if entry == 15 and rng.random() < 0.2:
            name = rng.choice(["InitializeFileRecordSegment", "DeallocateFileRecordSegment"])
            records.append({"lsn": lsn, "transaction_id": lsn, "redo_operation_name": name,
                            "undo_operation_name": "Noop", "mft_target_number": entry, "offset_in_target": 0,
                            "target_block_size": 2, "redo_hex": "", "undo_hex": "",
                            "transaction_forgotten_lsn": lsn + 1, "transaction_rolled_back": False})
            continue
        size = rng.choice([2, 4, 7, 8, 16, 32])
        redo, undo = rng.randbytes(size).hex(), rng.randbytes(size).hex()
        records.append({
            "lsn": lsn, "transaction_id": lsn, "redo_operation_name": "UpdateResidentValue",
            "undo_operation_name": rng.choice(["UpdateResidentValue", "Noop"]), "mft_target_number": entry,
            "offset_in_target": 80 + rng.choice([0, 1, 3, 8, 9, 16, 30, 40]), "target_block_size": 2,
            "redo_hex": redo if rng.random() > 0.02 else "zz", "undo_hex": undo,
            "transaction_forgotten_lsn": rng.choice([lsn + 3, None]), "transaction_rolled_back": rng.random() < 0.2,
        })
    rng.shuffle(records)
    return records


def lifecycle_of(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [record for record in records if record["redo_operation_name"] != "UpdateResidentValue"]


def context(**sequences: tuple[int, bool]) -> dict[str, object]:
    found = mft_context()
    found["entry_sequences"] = {entry: (3, True) for entry in range(10, 16)} | {17: (2, True)}
    found["entry_sequences"].update({int(entry): value for entry, value in sequences.items()})
    return found


@pytest.mark.parametrize("lifecycle", [True, False])
def test_one_pass_gives_each_variant_exactly_as_its_own_binding(tmp_path: Path, lifecycle: bool) -> None:
    mft = tmp_path / "$MFT"
    mft.write_bytes(mft_bytes())
    records = log_records()
    arguments = {"mft_path": mft, "mft_entry_sequences": context()["entry_sequences"],
                 "lifecycle_records": lifecycle_of(records) if lifecycle else None}

    variants = si_update_variants_from_records(records, **arguments)

    for flag in (False, True):
        alone = si_updates_from_records(records, include_timestamp_fragments=flag, **arguments)
        assert json.dumps(variants[flag]) == json.dumps(alone)
    (plain, plain_diagnostics), (fragments, fragment_diagnostics) = variants[False], variants[True]
    assert len(plain) < len(fragments) and any("si_timestamp_fragments" in item for item in fragments)
    assert plain_diagnostics["si_update_count"] < fragment_diagnostics["si_update_count"]
    assert set(fragment_diagnostics["unbound_reasons"]) == {
        "entry_reinitialised_after_update", "mft_context_sequence_disagrees", "record_lsn_precedes_update",
        "record_not_in_use", "record_unreadable", "si_value_offset_unresolved", "update_bytes_malformed",
    }


@pytest.fixture
def collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    # Other tests in the same worker may have bound these records to this $MFT already.
    monkeypatch.setattr(logfile_adapters, "_BOUND_SI_UPDATES", {})
    folder = tmp_path / "kape-output" / "targets" / "F"
    folder.mkdir(parents=True)
    logfile = folder / "$LogFile"
    logfile.write_bytes(b"\xff" * 64)
    mft = folder / "$MFT"
    mft.write_bytes(mft_bytes())
    records = log_records()
    state = {"logfile": logfile, "mft": mft, "records": records, "binds": 0}

    def document(path: Path, *, normalized_output_dir: Path, operations=None) -> dict[str, object]:
        # Each run reads its own copy of the driver's document, as it does from the driver's file.
        made = driver_document(state["records"], logfile=path)
        made["lifecycle_records"] = lifecycle_of(state["records"])
        return json.loads(json.dumps(made))

    def bind(*args, **kwargs):
        state["binds"] += 1
        return si_update_variants_from_records(*args, **kwargs)

    monkeypatch.setattr(logfile_adapters, "logfile_runtime_availability", lambda: {
        "available": True, "reason": None, "tool_identity": {"name": "dfir_ntfs", "version": "1.1.20"}})
    monkeypatch.setattr(logfile_adapters, "_logfile_driver_document", document)
    monkeypatch.setattr(logfile_adapters, "si_update_variants_from_records", bind)
    return state


def reference_run(collection: dict[str, object], output: Path, *, fragments: bool = False,
                  found: dict[str, object] | None = None) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    return logfile_adapters.raw_logfile_reference_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"], normalized_output_dir=output,
        collector_run={"collector": "kape"}, references=REFERENCES, filesystem_scope_id=VOLUME,
        mft_context=found or context(), include_timestamp_fragments=fragments,
    )


def masked(text: str, output: Path) -> str:
    # The run's folder as written, and as JSON writes it (with a Windows path's backslashes escaped).
    return text.replace(json.dumps(str(output))[1:-1], "<output>").replace(str(output), "<output>")


def analysis_runs(collection: dict[str, object], output: Path) -> str:
    # The scope run, the analysis's reference run and the factual supplement's, as S2 makes them.
    (output / "scope").mkdir(parents=True)
    runs = [
        logfile_adapters.raw_logfile_parser_run(
            logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
            normalized_output_dir=output / "scope", collector_run={"collector": "kape"}, mft_context=context(),
        ),
        reference_run(collection, output / "analysis"),
        reference_run(collection, output / "factual", fragments=True),
    ]
    written = {
        str(path.relative_to(output)): masked(path.read_text(encoding="utf-8"), output)
        for path in sorted(output.rglob("*")) if path.is_file()
    }
    return masked(json.dumps([runs, written]), output)


class Forgetful(dict):
    # A cache that never finds anything: every run binds its records itself.
    def get(self, key, default=None):
        return default


def test_a_run_binds_its_records_once_and_writes_what_binding_each_time_writes(collection, tmp_path, monkeypatch):
    kept = analysis_runs(collection, tmp_path / "kept")
    assert collection["binds"] == 1

    monkeypatch.setattr(logfile_adapters, "_BOUND_SI_UPDATES", Forgetful())
    bound_each_time = analysis_runs(collection, tmp_path / "bound")

    assert collection["binds"] == 4
    assert kept == bound_each_time
    assert '"si_timestamp_fragments"' in kept and '"normalized_record_count": 0' not in kept


def test_a_binding_is_reused_only_for_the_same_records_mft_and_sequences(collection, tmp_path):
    first = reference_run(collection, tmp_path / "first")
    collection["mft"].write_bytes(mft_bytes(times=(FILETIME_2026_A, FILETIME_2010, FILETIME_2026_B)))
    os.utime(collection["mft"], ns=(0, 0))
    other_mft = reference_run(collection, tmp_path / "mft")
    collection["records"] = log_records(seed=8)
    other_records = reference_run(collection, tmp_path / "records")
    other_sequences = reference_run(collection, tmp_path / "sequences", found=context(**{"11": (4, True)}))

    assert collection["binds"] == 4 and len(logfile_adapters._BOUND_SI_UPDATES) == 1
    fields = [[item["fields"] for item in run["observations"]]
              for run in (first, other_mft, other_records, other_sequences)]
    assert all(fields[index] != fields[index + 1] for index in range(3))


def test_callers_cannot_change_the_kept_binding(collection):
    document = logfile_adapters._logfile_driver_document(collection["logfile"], normalized_output_dir=Path())

    def bound() -> tuple[list[dict[str, object]], dict[str, object]]:
        return logfile_adapters._logfile_bound_updates(
            json.loads(json.dumps(document)), raw_mft_path=collection["mft"], mft_context=context(),
            include_timestamp_fragments=True, references=REFERENCES)

    updates, diagnostics = bound()
    expected = json.dumps([updates, diagnostics])
    updates[0]["old"]["created"] = "changed by the first caller"
    next(item for item in updates if "si_timestamp_fragments" in item)["si_timestamp_fragments"].clear()
    updates.clear()
    diagnostics["unbound_reasons"]["changed_by_the_first_caller"] = 1

    assert json.dumps(bound()) == expected and collection["binds"] == 1


def test_a_run_that_finds_the_binding_kept_records_the_mft_read(collection, tmp_path, monkeypatch):
    def opened(output: Path) -> set[str]:
        with reads.measured() as files:
            analysis_runs(collection, output)
        # write_json's temporary files have random names.
        return {masked(name, output) for name in files if not name.endswith(".tmp")}

    reference_run(collection, tmp_path / "warm")
    kept = opened(tmp_path / "kept")
    assert collection["binds"] == 1
    monkeypatch.setattr(logfile_adapters, "_BOUND_SI_UPDATES", Forgetful())
    bound_each_time = opened(tmp_path / "bound")

    assert kept == bound_each_time and str(collection["mft"]) in kept


def test_a_generation_binding_keeps_nothing(collection):
    document = logfile_adapters._logfile_driver_document(collection["logfile"], normalized_output_dir=Path())

    updates, _diagnostics = logfile_adapters._logfile_bound_updates(
        document, raw_mft_path=collection["mft"], mft_context=None)

    assert updates and logfile_adapters._BOUND_SI_UPDATES == {} and collection["binds"] == 0
