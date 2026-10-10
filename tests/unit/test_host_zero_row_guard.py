from __future__ import annotations

import hashlib
import shutil
import struct
import sys
from pathlib import Path

import pytest
from test_host_collector import _host_bundle

from fmb.analysis.inputs import _inferred_coverage
from fmb.collection.tools.host import backend as host_backend
from fmb.collection.tools.host.bundle import parser_appliance_request_args
from fmb.collection.tools.host.definitions import ModuleProcessor
from fmb.collection.tools.host.modules import (
    STATUS_COMPLETED,
    STATUS_COMPLETED_EMPTY_OUTPUT,
    csv_data_row_count,
    processor_run_record,
    run_module_processors,
    targets_inventory,
)
from fmb.collection.tools.host.toolchain import HostToolchain
from fmb.core.json_io import write_json
from fmb.core.paths import load_schema_definition_payload
from fmb.core.schemas import _validator
from fmb.index.adapters.parser_output import (
    apply_host_processor_status,
    host_processor_run_for_output,
)
from fmb.index.adapters.usn import mftecmd_usn_parser_run
from fmb.index.contract.evidence_index import unconsumed_run_labels
from fmb.index.kape.sources import scan_kape_output_root

FAKE_TOOL = (
    "import os, pathlib, sys\n"
    "args = sys.argv[1:]\n"
    "dest = pathlib.Path(args[args.index('--csv') + 1])\n"
    "dest.mkdir(parents=True, exist_ok=True)\n"
    "rows = int(os.environ.get('FMB_FAKE_TOOL_ROWS', '0'))\n"
    "lines = ['Name,Value'] + ['row%d,\"two\\nlines\"' % i for i in range(rows)]\n"
    "(dest / 'out.csv').write_text('\\n'.join(lines) + '\\n', encoding='utf-8')\n"
    "print('Command line: ' + ' '.join(args))\n"
)
USN_CSV_HEADER = (
    "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,"
    "ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,"
    "OffsetToData,SourceFile\n"
)
J_OUTPUT = "modules/FileSystem/20260912083107_MFTECmd_$J_Output.csv"


def _toolchain(case: Path) -> HostToolchain:
    script = case / "tool.py"
    script.write_text(FAKE_TOOL, encoding="utf-8")
    root = case / "toolchain"
    tool_dir = root / "Tool"
    tool_dir.mkdir(parents=True)
    target = tool_dir / script.name
    shutil.copyfile(script, target)
    lock = {
        "schema_version": "fmb_host_toolchain_lock.v1",
        "dotnet_sdk": "10.0.107",
        "dotnet_runtime": "10.0.7",
        "tools": [
            {
                "tool": "Tool",
                "executable": "Tool.exe",
                "directory": "Tool",
                "entry_assembly": script.name,
                "entry_assembly_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "version": "1.0",
                "host_runnable": True,
                "source": {"repository": "https://example.invalid/tool", "commit_sha": "0" * 40},
            }
        ],
    }
    lock_path = case / "lock.json"
    write_json(lock_path, lock)
    return HostToolchain(root, lock, lock_path=lock_path)


def _processor(*, file_mask: str | None) -> ModuleProcessor:
    command = (
        "-f %sourceFile% --csv %destinationDirectory%"
        if file_mask
        else "-d %sourceDirectory% --csv %destinationDirectory%"
    )
    return ModuleProcessor(
        requested_module="MFTECmd_$J", module_name="MFTECmd_$J", definition="fixture",
        definition_id="fixture-j", category="FileSystem", export_format="csv",
        file_mask=file_mask, executable="Tool.exe", command_line=command,
    )


def _run(
    tmp_path: Path,
    *,
    name: str,
    processor: ModuleProcessor,
    source_bytes: bytes | None,
    rows: int,
    monkeypatch: pytest.MonkeyPatch,
):
    case = tmp_path / name
    targets_root = case / "kape-output" / "targets"
    (targets_root / "F" / "$Extend").mkdir(parents=True)
    if source_bytes is not None:
        (targets_root / "F" / "$Extend" / "$J").write_bytes(source_bytes)
    monkeypatch.setenv("FMB_FAKE_TOOL_ROWS", str(rows))
    runs = run_module_processors(
        [processor], toolchain=_toolchain(case), dotnet=sys.executable, targets_root=targets_root,
        modules_root=case / "kape-output" / "modules", tool_logs_dir=case / "tool-logs",
    )
    assert len(runs) == 1
    return runs[0]


def test_csv_data_row_count_counts_records_not_lines(tmp_path: Path) -> None:
    path = tmp_path / "out.csv"
    path.write_text("﻿Name,Value\n", encoding="utf-8")
    assert csv_data_row_count(path) == 0
    path.write_text('Name,Value\n\na,"line one\nline two"\nb,2\n', encoding="utf-8")
    assert csv_data_row_count(path) == 2
    path.write_bytes(b"")
    assert csv_data_row_count(path) == 0


def test_non_empty_input_with_header_only_output_is_completed_empty_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processor = _processor(file_mask="$J")
    empty_output = _run(
        tmp_path, name="empty-output", processor=processor, source_bytes=b"\x00\x01" * 2048,
        rows=0, monkeypatch=monkeypatch,
    )
    assert empty_output.status == STATUS_COMPLETED_EMPTY_OUTPUT
    assert empty_output.exit_code == 0
    assert empty_output.outputs == ["modules/FileSystem/out.csv"]
    assert empty_output.data_row_counts == {"modules/FileSystem/out.csv": 0}
    assert (empty_output.input_file_count, empty_output.input_byte_count) == (1, 4096)
    assert "wrote no CSV data row" in str(empty_output.detail)
    record = processor_run_record(empty_output)
    assert record["status"] == STATUS_COMPLETED_EMPTY_OUTPUT
    assert record["data_row_count"] == 0
    assert record["data_row_counts"] == {"modules/FileSystem/out.csv": 0}
    assert record["input_byte_count"] == 4096

    with_rows = _run(
        tmp_path, name="with-rows", processor=processor, source_bytes=b"J" * 4096, rows=2,
        monkeypatch=monkeypatch,
    )
    assert with_rows.status == STATUS_COMPLETED
    assert with_rows.data_row_counts == {"modules/FileSystem/out.csv": 2}
    assert with_rows.data_row_count == 2
    assert with_rows.detail is None

    empty_input = _run(
        tmp_path, name="empty-input", processor=processor, source_bytes=b"", rows=0,
        monkeypatch=monkeypatch,
    )
    assert empty_input.status == STATUS_COMPLETED
    assert (empty_input.input_file_count, empty_input.input_byte_count) == (1, 0)
    assert empty_input.data_row_count == 0


def test_directory_processor_guard_uses_the_collected_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processor = _processor(file_mask=None)
    collected = _run(
        tmp_path, name="dir-empty-output", processor=processor, source_bytes=b"J" * 512, rows=0,
        monkeypatch=monkeypatch,
    )
    assert collected.status == STATUS_COMPLETED_EMPTY_OUTPUT
    assert (collected.input_file_count, collected.input_byte_count) == (1, 512)
    assert collected.source_file is None

    nothing_collected = _run(
        tmp_path, name="dir-no-input", processor=processor, source_bytes=None, rows=0,
        monkeypatch=monkeypatch,
    )
    assert nothing_collected.status == STATUS_COMPLETED
    assert (nothing_collected.input_file_count, nothing_collected.input_byte_count) == (0, 0)

    targets = tmp_path / "inventory" / "targets"
    (targets / "F").mkdir(parents=True)
    (targets / "2026-09-12T08_30_36_CopyLog.csv").write_text("CopiedTimestamp\n", encoding="utf-8")
    (targets / "F" / "$MFT").write_bytes(b"FILE0" * 2)
    assert targets_inventory(targets) == (1, 10)
    assert targets_inventory(tmp_path / "absent") == (0, 0)


def test_bundle_validation_warns_on_empty_output_and_keeps_failures_fatal(tmp_path: Path) -> None:
    validate = host_backend.validate_host_collector_bundle
    request_args = parser_appliance_request_args("run", [])
    appliance = {"mode": "run", "status": "not_requested", "modules": []}
    outputs = {"modules/FileFolderAccess/vagrant_NTUSER.csv": "BagPath,Value\n"}
    empty_run = {
        "module": "MFTECmd_$J", "tool": "MFTECmd", "status": STATUS_COMPLETED_EMPTY_OUTPUT,
        "exit_code": 0, "outputs": [J_OUTPUT], "input_file_count": 1,
        "input_byte_count": 39150520, "data_row_count": 0, "data_row_counts": {J_OUTPUT: 0},
        "detail": "MFTECmd exited 0 on 1 non-empty input file(s) but wrote no CSV data row",
    }

    warned = _host_bundle(
        tmp_path / "warn", request_args=request_args, appliance=appliance,
        module_runs=[empty_run, {"module": "SBECmd", "status": "deferred"}], extra_outputs=outputs,
    )
    verdict = validate(**warned["validate"])
    assert verdict["status"] == "passed"
    checks = {check["check_id"]: check for check in verdict["checks"]}
    assert checks["host_processor_exit_codes"]["status"] == "pass"
    assert checks["host_processor_empty_outputs"]["status"] == "warn"
    assert checks["host_processor_empty_outputs"]["modules"] == ["MFTECmd_$J"]
    assert checks["host_processor_empty_outputs"]["outputs"] == [J_OUTPUT]
    assert "certify no coverage" in checks["host_processor_empty_outputs"]["message"]
    assert verdict["host_collector_metadata"]["module_runs"][0]["data_row_counts"] == {J_OUTPUT: 0}

    clean = _host_bundle(
        tmp_path / "clean", request_args=request_args, appliance=appliance,
        module_runs=[{**empty_run, "status": STATUS_COMPLETED, "data_row_count": 236176}],
        extra_outputs=outputs,
    )
    checks = {check["check_id"]: check for check in validate(**clean["validate"])["checks"]}
    assert checks["host_processor_empty_outputs"] == {
        "check_id": "host_processor_empty_outputs", "status": "pass", "modules": [], "outputs": [],
    }

    failed = _host_bundle(
        tmp_path / "failed", request_args=request_args, appliance=appliance,
        module_runs=[{"module": "MFTECmd_$J", "status": "failed", "exit_code": 1}],
        extra_outputs=outputs,
    )
    with pytest.raises(host_backend.HostCollectorError, match="failed processor run"):
        validate(**failed["validate"])


def _host_kape_output(tmp_path: Path, *, status: str) -> tuple[Path, Path, dict]:
    bundle = tmp_path / "bundle-extracted"
    root = bundle / "kape-output"
    extend = root / "targets" / "F" / "$Extend"
    extend.mkdir(parents=True)
    (extend / "$Max").write_bytes(struct.pack("<QQQQ", 32 << 20, 8 << 20, 0x0102030405060708, 0))
    csv_path = root / J_OUTPUT
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text("﻿" + USN_CSV_HEADER, encoding="utf-8")
    write_json(
        bundle / "host_collector_metadata.json",
        {
            "schema_version": "fmb_host_collector_metadata.v1",
            "module_runs": [
                {
                    "module": "MFTECmd_$J", "tool": "MFTECmd", "status": status, "exit_code": 0,
                    "outputs": [J_OUTPUT], "input_file_count": 1, "input_byte_count": 39150520,
                    "data_row_count": 0, "data_row_counts": {J_OUTPUT: 0},
                    "detail": "MFTECmd exited 0 on 1 non-empty input file(s) but wrote no CSV data row",
                }
            ],
        },
    )
    collector_run = {"collector": "kape", "provenance": {}, "output_root": str(root)}
    return root, csv_path, collector_run


def test_header_only_host_output_is_consumed_empty_with_unavailable_coverage(tmp_path: Path) -> None:
    root, csv_path, collector_run = _host_kape_output(tmp_path, status=STATUS_COMPLETED_EMPTY_OUTPUT)
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    run = mftecmd_usn_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized, collector_run=collector_run,
    )
    assert (run["status"], run["coverage_status"], run["observation_count"]) == ("consumed", "complete", 0)
    assert host_processor_run_for_output(collector_run, csv_path)["module"] == "MFTECmd_$J"

    bound = apply_host_processor_status(run, collector_run)
    assert bound["status"] == "consumed_empty"
    assert bound["coverage_status"] == "unavailable"
    assert "coverage_scope" not in bound
    assert bound["observations"] == [] and bound["observation_count"] == 0
    processor = bound["provenance"]["host_processor_run"]
    assert processor["module"] == "MFTECmd_$J"
    assert processor["status"] == STATUS_COMPLETED_EMPTY_OUTPUT
    assert processor["data_row_count"] == 0 and processor["input_byte_count"] == 39150520
    assert unconsumed_run_labels([], [], [bound]) == []
    schema = load_schema_definition_payload("evidence.schema.json", "parserRun")
    assert list(_validator(schema).iter_errors(bound)) == []
    assert _inferred_coverage({"parser_runs": [bound]}) == {"ntfs.usn": "partial"}


def test_completed_host_output_and_appliance_bundles_keep_the_consumed_record(tmp_path: Path) -> None:
    root, csv_path, collector_run = _host_kape_output(tmp_path / "completed", status=STATUS_COMPLETED)
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    run = mftecmd_usn_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized, collector_run=collector_run,
    )
    assert apply_host_processor_status(run, collector_run) is run
    assert (run["status"], run["coverage_status"]) == ("consumed", "complete")
    assert run["coverage_scope"]["kind"] == "usn_journal"
    assert "host_processor_run" not in run["provenance"]

    root, csv_path, collector_run = _host_kape_output(
        tmp_path / "appliance", status=STATUS_COMPLETED_EMPTY_OUTPUT
    )
    (root.parent / "host_collector_metadata.json").unlink()
    run = mftecmd_usn_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized, collector_run=collector_run,
    )
    assert host_processor_run_for_output(collector_run, csv_path) is None
    assert apply_host_processor_status(run, collector_run)["status"] == "consumed"


def test_kape_indexing_applies_the_guard_to_collected_outputs(tmp_path: Path) -> None:
    root, _csv_path, collector_run = _host_kape_output(tmp_path, status=STATUS_COMPLETED_EMPTY_OUTPUT)
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    runs = scan_kape_output_root(
        root=root, collector_run=collector_run, normalized_output_dir=normalized,
    )
    usn_runs = [item for item in runs if item.get("source_module") == "MFTECmd_$J"]
    assert len(usn_runs) == 1
    assert usn_runs[0]["status"] == "consumed_empty"
    assert usn_runs[0]["coverage_status"] == "unavailable"
    assert unconsumed_run_labels([], [], runs) == []
