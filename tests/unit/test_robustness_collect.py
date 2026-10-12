from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest
from test_logfile_adapter import collection, mft_context  # noqa: F401  (collection is a fixture)

from fmb.collection import analysis
from fmb.collection.tools.host import backend as host_backend
from fmb.collection.tools.host import parser_appliance as appliance
from fmb.collection.tools.host.modules import (
    STATUS_COMPLETED,
    STATUS_COMPLETED_EMPTY_OUTPUT,
    ProcessorRun,
    processor_run_record,
)
from fmb.collection.tools.host.validation import (
    KapeApplianceError,
    assert_required_kape_artifacts,
    required_artifact_globs,
)
from fmb.core.json_io import write_json
from fmb.index.adapters import event_log
from fmb.index.adapters import logfile as logfile_adapters
from fmb.index.adapters.execution import pecmd_prefetch_parser_run
from fmb.index.adapters.parser_output import apply_host_processor_status, unavailable_coverage
from fmb.profiles import question_definitions, resolve_paper_profile


def _timed_out_logfile_run(collection, monkeypatch):  # noqa: F811
    def timed_out(path, *, normalized_output_dir, operations=None):
        raise logfile_adapters.LogFileRuntimeError("dfir_ntfs did not finish within 600 seconds")

    monkeypatch.setattr(logfile_adapters, "_logfile_driver_document", timed_out)
    return logfile_adapters.raw_logfile_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        mft_context=mft_context(),
    )


def test_a_timed_out_logfile_parse_certifies_no_coverage_and_says_why(collection, monkeypatch):  # noqa: F811
    run = _timed_out_logfile_run(collection, monkeypatch)

    assert run["coverage_status"] == "unavailable"
    assert run["provenance"]["unavailable_reason"] == (
        "dfir_ntfs_driver_failed: dfir_ntfs did not finish within 600 seconds")
    assert unavailable_coverage(run) == (
        "dfir_ntfs ($LogFile): dfir_ntfs_driver_failed: dfir_ntfs did not finish within 600 seconds")


def test_s2_stops_on_an_unavailable_family_naming_the_tool_and_reason(collection, monkeypatch, tmp_path):  # noqa: F811
    from fmb.pipeline import stages

    run = _timed_out_logfile_run(collection, monkeypatch)
    covering = [{"parser": "mftecmd", "source_module": "MFTECmd", "status": "consumed", "coverage_status": "complete",
                 "coverage_families": [family]} for family in ("ntfs.mft", "ntfs.usn")]
    write_json(tmp_path / "evidence_index.json", {"parser_runs": [run, *covering]})
    g2 = stages.profile_gate(resolve_paper_profile(["BQ-TIME-01"]), question_definitions(["BQ-TIME-01"]))

    with pytest.raises(ValueError) as raised:
        stages.profile_coverage(tmp_path, g2)
    assert str(raised.value) == (
        "S2 collected no usable source for families the profile requires: BQ-TIME-01: ntfs.logfile; "
        "dfir_ntfs ($LogFile): dfir_ntfs_driver_failed: dfir_ntfs did not finish within 600 seconds")

    with pytest.raises(ValueError, match=r"no usable source for ntfs\.logfile, .*dfir_ntfs \(\$LogFile\): "
                                         r"dfir_ntfs_driver_failed: dfir_ntfs did not finish"):
        analysis.refuse_unavailable_families({"parser_runs": [run, *covering]}, {"ntfs.logfile", "ntfs.mft"})
    partial = {**covering[0], "coverage_status": "partial", "coverage_families": ["ntfs.logfile"]}
    analysis.refuse_unavailable_families({"parser_runs": [run, partial]}, {"ntfs.logfile"})
    analysis.refuse_unavailable_families({"parser_runs": [run]}, {"ntfs.mft"})


def _prefetch_root(tmp_path: Path, *, pf_files: int, rows: str) -> tuple[Path, dict]:
    root = tmp_path / "kape-output"
    prefetch = root / "targets" / "C" / "Windows" / "Prefetch"
    prefetch.mkdir(parents=True)
    for index in range(pf_files):
        (prefetch / f"TOOL{index}.EXE-0000000{index}.pf").write_bytes(b"MAM\x04" + b"\x00" * 60)
    csv_path = root / "modules" / "ProgramExecution" / "20260912083107_PECmd_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text("ExecutableName,SourceFile,RunCount\n" + rows, encoding="utf-8")
    return csv_path, {"collector": "kape", "provenance": {}, "output_root": str(root)}


@pytest.mark.parametrize(("pf_files", "rows", "status"), [
    (2, "", "unavailable"),
    (0, "", "complete"),
    (2, "TOOL0.EXE,C:\\Windows\\Prefetch\\TOOL0.EXE-00000000.pf,3\n", "complete"),
])
def test_header_only_pecmd_output_certifies_no_coverage_when_prefetch_files_exist(tmp_path, pf_files, rows, status):
    csv_path, collector_run = _prefetch_root(tmp_path, pf_files=pf_files, rows=rows)
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = pecmd_prefetch_parser_run(csv_path=csv_path, normalized_output_dir=normalized, collector_run=collector_run)

    assert run["coverage_status"] == status
    if status == "unavailable":
        assert "coverage_scope" not in run
        assert unavailable_coverage(run) == "pecmd (PECmd): PECmd wrote no row for the 2 collected Prefetch file(s)"
    else:
        assert run["coverage_scope"]["pf_file_count"] == pf_files
        assert "unavailable_reason" not in run["provenance"]


def _deferred(module: str, category: str) -> ProcessorRun:
    return ProcessorRun(module_name=module, requested_module=module, executable=f"{module}.exe", tool_name=None,
                        category=category, argv=[], command_line=f"{module}.exe", working_directory=None,
                        source_file=None, started_at="", status="deferred", detail="runs in the parser appliance")


def _appliance_receipt(tmp_path: Path, files: dict[str, str]) -> tuple[Path, dict]:
    outputs_zip = tmp_path / "outputs.zip"
    results = [
        {"label": "PECmd", "category": "ProgramExecution", "executable_sha256": "a" * 64, "exit_code": 0,
         "arguments": ["-d", "C:\\in", "--csv", "C:\\out"]},
        {"label": "SBECmd", "category": "FileFolderAccess", "executable_sha256": "b" * 64, "exit_code": 0,
         "arguments": ["-d", "C:\\in", "--csv", "C:\\out"]},
    ]
    with zipfile.ZipFile(outputs_zip, "w") as archive:
        archive.writestr("receipt.json", json.dumps({"schema_version": appliance.RECEIPT_SCHEMA, "results": results}))
        for name, text in files.items():
            archive.writestr(name, text)
    package = {
        "package_sha256": "c" * 64, "input_file_count": 3,
        "commands": [
            {"label": "PECmd", "category": "ProgramExecution", "executable_sha256": "a" * 64,
             "input_file_count": 2, "input_byte_count": 4096},
            {"label": "SBECmd", "category": "FileFolderAccess", "executable_sha256": "b" * 64,
             "input_file_count": 1, "input_byte_count": 262144},
        ],
    }
    return outputs_zip, package


def test_empty_parser_appliance_output_reaches_the_module_runs_and_the_index(tmp_path):
    bundle = tmp_path / "bundle"
    modules_root, tool_logs = bundle / "kape-output" / "modules", bundle / "logs"
    tool_logs.mkdir(parents=True)
    outputs_zip, package = _appliance_receipt(tmp_path, {
        "modules/ProgramExecution/20260912083107_PECmd_Output.csv": "ExecutableName,SourceFile,RunCount\n",
        "modules/FileFolderAccess/vagrant_NTUSER.csv": "AbsolutePath,BagPath,ShellType\nDesktop\\x,1,Directory\n",
    })
    record = appliance._merge_outputs(outputs_zip=outputs_zip, appliance_dir=tmp_path / "appliance",
                                      modules_root=modules_root, tool_logs=tool_logs, package=package)
    assert record["empty_output_modules"] == ["PECmd"]
    runs = [_deferred("PECmd", "ProgramExecution"), _deferred("SBECmd", "FileFolderAccess"),
            _deferred("JLECmd", "FileFolderAccess")]

    host_backend._record_appliance_runs(runs, record, bundle_root=modules_root.parent)

    pecmd, sbecmd, untouched = runs
    assert pecmd.status == STATUS_COMPLETED_EMPTY_OUTPUT and pecmd.exit_code == 0
    assert pecmd.outputs == ["modules/ProgramExecution/20260912083107_PECmd_Output.csv"]
    assert pecmd.console_log_relative_path == "modules/ProgramExecution/PECmd-parser-appliance.console.log"
    assert pecmd.detail.startswith("PECmd exited 0 on 2 non-empty input file(s) totalling 4096 bytes")
    assert (sbecmd.status, sbecmd.data_row_count) == (STATUS_COMPLETED, 1)
    assert untouched.status == "deferred"

    write_json(bundle / "host_collector_metadata.json", {"module_runs": [processor_run_record(run) for run in runs]})
    collector_run = {"collector": "kape", "provenance": {}, "output_root": str(modules_root.parent)}
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    csv_path = modules_root / "ProgramExecution" / "20260912083107_PECmd_Output.csv"
    run = apply_host_processor_status(pecmd_prefetch_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized, collector_run=collector_run), collector_run)
    assert (run["status"], run["coverage_status"]) == ("consumed_empty", "unavailable")
    assert unavailable_coverage(run).startswith("pecmd (PECmd): PECmd exited 0 on 2 non-empty input file(s)")


def test_sbecmd_output_is_required_on_its_own(tmp_path):
    globs = required_artifact_globs(targets=[], modules=["SBECmd"], explicit=[])
    lecmd = tmp_path / "modules" / "FileFolderAccess" / "20260912083107_LECmd_Output.csv"
    lecmd.parent.mkdir(parents=True)
    lecmd.write_text("SourceFile\nx.lnk\n", encoding="utf-8")

    with pytest.raises(KapeApplianceError, match="required KAPE artifact pattern missing: .*_NTUSER.csv"):
        assert_required_kape_artifacts(tmp_path, globs, checks=[])
    (lecmd.parent / "vagrant_UsrClass.csv").write_text("BagPath\n1\n", encoding="utf-8")
    checks: list[dict] = []
    assert_required_kape_artifacts(tmp_path, globs, checks=checks)
    assert [check["status"] for check in checks] == ["pass"]


def _evtx_case(tmp_path: Path) -> tuple[Path, Path, dict]:
    security = tmp_path / "kape-output" / "targets" / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    security.parent.mkdir(parents=True)
    security.write_bytes(b"ElfFile\x00" + b"\x00" * 120)
    csv_path = tmp_path / "kape-output" / "modules" / "EventLogs" / "20260912083107_EvtxECmd_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "EventId,EventRecordId,Channel,SourceFile,TimeCreated\n"
        "4624,1,Security,C:\\Windows\\System32\\winevt\\Logs\\Security.evtx,2026-09-12T08:00:00Z\n",
        encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    return csv_path, normalized, {"collector": "kape", "provenance": {}, "artifacts": [{"path": str(security)}]}


def test_an_unparsable_security_log_records_why_and_an_unreadable_one_fails(tmp_path, monkeypatch):
    csv_path, normalized, collector_run = _evtx_case(tmp_path)

    def dirty(data):
        raise ValueError("the log is dirty (flag 0x1 at offset 120)")

    monkeypatch.setattr(event_log, "retained_record_ids", dirty)
    run = event_log.evtxecmd_parser_run(csv_path=csv_path, normalized_output_dir=normalized,
                                        collector_run=collector_run)
    assert run["coverage_status"] == "partial"
    index = json.loads(Path(run["normalized_output"]["path"]).read_text(encoding="utf-8"))
    assert index["native_record_projection_error"] == (
        "Security.evtx could not be parsed: the log is dirty (flag 0x1 at offset 120)")

    def unreadable(data):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(event_log, "retained_record_ids", unreadable)
    with pytest.raises(PermissionError):
        event_log.evtxecmd_parser_run(csv_path=csv_path, normalized_output_dir=normalized,
                                      collector_run=collector_run)


def test_skipped_reference_scoped_scanners_leave_a_note_saying_why(tmp_path, monkeypatch):
    logfile = tmp_path / "kape-output" / "targets" / "F" / "$LogFile"
    logfile.parent.mkdir(parents=True)
    logfile.write_bytes(b"public synthetic control")
    monkeypatch.setattr(analysis, "build_mft_presence_context", lambda kape_root: {"mft_volume_id": "volume:other"})
    monkeypatch.setattr(analysis, "validate_payload", lambda payload, schema: None)
    index = {
        "parser_runs": [{"parser_kind": "ntfs_logfile", "raw_outputs": [{"path": str(logfile)}]}],
        "collector_runs": [{"collector": "kape"}],
        "candidate_populations": [{
            "question_id": "Q-TIME-01", "technique_id": "timestamp_manipulation", "coverage_status": "complete",
            "subjects": [{"identity": {"object_id": "ntfs:volume:test:42:3"}}],
        }],
    }

    analysis.add_reference_scoped_usn(index, output_dir=tmp_path / "out")

    note = json.loads((tmp_path / "out/execution/02-normalization/reference-scope-skips.json").read_text("utf-8"))
    assert note == {"skipped": [
        {"scanner": "usn", "filesystem_scope_id": "volume:test",
         "reason": "no single raw $J among the parser outputs"},
        {"scanner": "logfile", "filesystem_scope_id": "volume:test",
         "reason": "the collected $MFT is volume volume:other, not the population's volume volume:test"},
    ]}


def test_the_run_lock_names_its_holder_and_dies_with_it(tmp_path):
    import subprocess
    import sys

    from fmb.collection.run import lock as run_lock

    holder = subprocess.Popen(
        [sys.executable, "-c", (
            "import sys, time\n"
            "from pathlib import Path\n"
            "from fmb.collection.run.lock import acquire_evidence_image_run_lock\n"
            "with acquire_evidence_image_run_lock(current_root=Path(sys.argv[1]), requested_run_id='run-held'):\n"
            "    print('held', flush=True)\n"
            "    time.sleep(120)\n"
        ), str(tmp_path)],
        stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(run_lock.ActiveEvidenceImageRunError,
                           match=rf"already active: run-held at .*\(pid {holder.pid} on "):
            with run_lock.acquire_evidence_image_run_lock(current_root=tmp_path, requested_run_id="run-next"):
                pass
    finally:
        holder.kill()
        holder.wait(timeout=30)
        holder.stdout.close()

    lock_path = run_lock.evidence_image_run_lock_path(tmp_path)
    # What a dead run leaves behind: its record, an empty file, or a record naming a reused pid on a renamed host.
    reused = {**run_lock.read_lock_payload(lock_path), "pid": os.getpid(), "host": "renamed-host"}
    for leftover in (lock_path.read_text(encoding="utf-8"), "", json.dumps(reused)):
        lock_path.write_text(leftover, encoding="utf-8")
        with run_lock.acquire_evidence_image_run_lock(current_root=tmp_path, requested_run_id="run-next") as lock:
            assert run_lock.read_lock_payload(lock.lock_path)["requested_run_id"] == "run-next"
