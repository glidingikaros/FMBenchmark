from __future__ import annotations

import argparse
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest
from test_logfile_adapter import collection, mft_context  # noqa: F401  (collection is a fixture)
from test_parser_appliance_work_root import parser_case  # noqa: F401  (a fixture)

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


@pytest.fixture
def identity_case(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from fmb.analysis import population_binding
    from fmb.collection import alignment, factual_challenge, paper_host

    evidence = tmp_path / "evidence.vmdk"
    evidence.write_bytes(b"small public test evidence")
    hashed: list[Path] = []
    case = SimpleNamespace(evidence=evidence, hashed=hashed, during_host=lambda: None, during_factual=lambda: None,
                           digest=lambda: "b" * 64)
    generated = SimpleNamespace(content_subject_limit=None, i30_directory_paths=(), evidence_sha256="b" * 64,
                                population_manifest={"scenarios": {}})
    monkeypatch.setattr(population_binding, "load_generated_population_bundle", lambda *_, **__: generated)
    monkeypatch.setattr(factual_challenge, "load_public_population", lambda _: {"members": []})
    monkeypatch.setattr(paper_host, "sha256_file", lambda path: hashed.append(path) or case.digest())

    def collect_host(**kwargs):
        case.during_host()
        return {"parser_runs": []}

    def add_factual_population(index, **kwargs):
        case.during_factual()
        return index

    monkeypatch.setattr(paper_host, "collect_host", collect_host)
    monkeypatch.setattr(factual_challenge, "add_factual_population", add_factual_population)
    for module, name in [(alignment, "add_native_population_surfaces"),
                         (population_binding, "bind_population_manifest"),
                         (analysis, "add_reference_scoped_usn"), (analysis, "add_reference_scoped_ads")]:
        monkeypatch.setattr(module, name, lambda index, *_, **__: index)
    case.invoke = lambda: analysis.collect_evidence_index(
        evidence, profile=resolve_paper_profile(["BQ-LOG-01"]), output_dir=tmp_path / "analysis", run_id="test",
        windows_parsers=None)
    return case


def test_an_image_changed_by_a_late_collection_step_is_refused(identity_case, monkeypatch):
    from fmb.collection import paper_host
    from fmb.core.errors import FmbInputError

    monkeypatch.setattr(paper_host, "REHASH_AFTER_COLLECTION", False)

    def append():
        with identity_case.evidence.open("ab") as handle:
            handle.write(b"appended during collection")

    identity_case.during_factual = append
    with pytest.raises(FmbInputError, match=r"evidence image changed during collection \(size, "):
        identity_case.invoke()
    assert identity_case.hashed == []


@pytest.mark.parametrize(("rehash", "rewritten", "hashes"), [
    (False, False, 0), (True, False, 1), (True, True, 1),
])
def test_an_image_whose_metadata_can_be_restored_is_hashed_again(identity_case, monkeypatch, rehash, rewritten,
                                                                  hashes):
    from fmb.collection import paper_host
    from fmb.core.errors import FmbInputError

    monkeypatch.setattr(paper_host, "REHASH_AFTER_COLLECTION", rehash)
    # What Windows reports: st_ctime is the creation time, so only the size and the restorable last-write time remain.
    monkeypatch.setattr(paper_host, "file_identity", lambda path: (path.stat().st_size, path.stat().st_mtime_ns))
    evidence = identity_case.evidence

    def rewrite():
        status = evidence.stat()
        evidence.write_bytes(b"SMALL PUBLIC TEST EVIDENCE")
        os.utime(evidence, ns=(status.st_atime_ns, status.st_mtime_ns))
        identity_case.digest = lambda: "c" * 64

    if rewritten:
        identity_case.during_host = rewrite
        with pytest.raises(FmbInputError, match=r"changed during collection \(content\)"):
            identity_case.invoke()
    else:
        assert identity_case.invoke() == {"parser_runs": []}
    assert identity_case.hashed == [evidence] * hashes


@pytest.mark.skipif(os.name == "nt", reason="st_ctime is the creation time on Windows")
@pytest.mark.parametrize("same_bytes", [True, False])
def test_a_change_time_alone_is_settled_by_hashing_again(identity_case, monkeypatch, same_bytes):
    from fmb.collection import paper_host
    from fmb.core.errors import FmbInputError

    monkeypatch.setattr(paper_host, "REHASH_AFTER_COLLECTION", False)

    def chmod():
        identity_case.evidence.chmod(0o444)
        if not same_bytes:
            identity_case.digest = lambda: "c" * 64

    identity_case.during_host = chmod
    if same_bytes:
        assert identity_case.invoke() == {"parser_runs": []}
    else:
        with pytest.raises(FmbInputError, match=r"changed during collection \(content\)"):
            identity_case.invoke()
    assert identity_case.hashed == [identity_case.evidence]


def _qemu_vm(tmp_path, monkeypatch, *, exit_code=None):
    from fmb.generation import backends

    stage = tmp_path / "analysis"
    stage.mkdir()

    class Process:
        returncode = exit_code

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    launched = []

    def popen(command, *, stdout, stderr):
        launched.append(command)
        stdout.write("qemu-system-x86_64: Could not set up host forwarding rule 'tcp:127.0.0.1:5000-:5985'\n")
        stdout.flush()
        return Process()

    def guest_command(qemu, state, **kwargs):
        (state / "serial.log").write_text("serial console\n", encoding="utf-8")
        return ["qemu-system-x86_64"]

    monkeypatch.setattr(backends.QemuBackend, "discover_tools", staticmethod(
        lambda: {"qemu-system": "qemu-system-x86_64", "qemu-img": "qemu-img", "ansible": "ansible"}))
    monkeypatch.setattr(backends.QemuBackend, "base_location", staticmethod(lambda box, version: {}))
    monkeypatch.setattr(backends.QemuBackend, "base_directory", staticmethod(lambda location: tmp_path / "base"))
    monkeypatch.setattr(backends, "prepare_overlay", lambda *args: None)
    monkeypatch.setattr(backends, "qemu_guest_command", guest_command)
    monkeypatch.setattr(backends, "winrm_listening", lambda port: exit_code is None)
    monkeypatch.setattr(backends, "ansible_adhoc", lambda *a, **k: subprocess.CompletedProcess([], 0, "ok", ""))
    monkeypatch.setattr(appliance.subprocess, "Popen", popen)
    monkeypatch.setattr(appliance, "_parser_qemus", lambda: [])
    args = argparse.Namespace(vm_work_root=None, run_id="analysis", windows_parsers="windows-parsers",
                              collection_provider="qemu", windows_box="fmb/windows-11-x64")
    return appliance.ParserVM(args=args, stage_dir=stage), stage / appliance.APPLIANCE_DIR_NAME, launched


def test_a_parser_qemu_that_dies_during_boot_says_how_and_keeps_its_logs(tmp_path, monkeypatch):
    vm, appliance_dir, launched = _qemu_vm(tmp_path, monkeypatch, exit_code=-9)

    with pytest.raises(appliance.ParserApplianceError) as raised:
        vm.boot()
    message = str(raised.value)
    assert "exited during boot with exit code -9 (killed" in message
    assert "Could not set up host forwarding rule" in message
    state = appliance_dir / appliance.QEMU_STATE_DIR
    assert vm.state == state and state.is_dir()
    command = launched[0]
    assert command[command.index("-name") + 1] == f"fmb-parser-{os.getpid()}"
    assert command[command.index("-pidfile") + 1] == str(state / "qemu.pid")

    vm.close()
    assert not state.exists()
    assert (appliance_dir / "parser-vm-serial.log").read_text(encoding="utf-8") == "serial console\n"
    assert "host forwarding" in (appliance_dir / "parser-vm-qemu.log").read_text(encoding="utf-8")


def test_repeatable_qemu_parser_steps_are_retried(tmp_path, monkeypatch):
    from fmb.generation import backends

    vm, _, _ = _qemu_vm(tmp_path, monkeypatch)
    monkeypatch.setattr(appliance, "QEMU_STEP_RETRY_DELAY_SECONDS", 0)
    pings = []
    monkeypatch.setattr(vm, "_answered", lambda: pings.append(True) or True)
    calls: list[str] = []
    failures = {"ansible.windows.win_copy": 1, "ansible.builtin.fetch": 1}

    def adhoc(ansible, port, module, args, *, timeout):
        calls.append(module)
        if failures.get(module):
            failures[module] -= 1
            if module == "ansible.builtin.fetch":
                raise subprocess.TimeoutExpired(["ansible"], timeout)
            return subprocess.CompletedProcess([], 2, "UNREACHABLE! connection reset", "")
        if module == "ansible.builtin.fetch":
            Path(args["dest"]).write_bytes(b"outputs")
        return subprocess.CompletedProcess([], 0, "ok", "")

    monkeypatch.setattr(backends, "ansible_adhoc", adhoc)
    outputs = tmp_path / "outputs.zip"
    completed = vm.run_qemu_parsers(package_path=tmp_path / "inputs.zip", script_path=tmp_path / "run.ps1",
                                    outputs_zip=outputs)
    assert completed.returncode == 0 and outputs.read_bytes() == b"outputs"
    assert calls == ["ansible.windows.win_file", "ansible.windows.win_copy", "ansible.windows.win_copy",
                     "ansible.windows.win_copy", "ansible.windows.win_command", "ansible.builtin.fetch",
                     "ansible.builtin.fetch"]
    assert len(pings) == 2

    calls.clear()
    failures.update({"ansible.windows.win_file": 5})
    with pytest.raises(appliance.ParserApplianceError,
                       match="win_file failed 3 times; last: UNREACHABLE! connection reset"):
        vm.run_qemu_parsers(package_path=tmp_path / "inputs.zip", script_path=tmp_path / "run.ps1",
                            outputs_zip=outputs)
    assert calls == ["ansible.windows.win_file"] * 3

    monkeypatch.setattr(backends, "ansible_adhoc", lambda ansible, port, module, args, *, timeout: (
        calls.append(module), subprocess.CompletedProcess([], 1 if module.endswith("win_command") else 0, "x", ""))[1])
    calls.clear()
    assert vm.run_qemu_parsers(package_path=tmp_path / "inputs.zip", script_path=tmp_path / "run.ps1",
                               outputs_zip=outputs).returncode == 1
    assert calls.count("ansible.windows.win_command") == 1


def _clone_folder(work_root: Path, name: str, owner: dict | None) -> Path:
    folder = work_root / f"fmb-parser-{name}"
    (folder / ".vmrun-appliance").mkdir(parents=True)
    (folder / ".vmrun-appliance" / "box.vmx").write_text("config.version = \"8\"\n", encoding="utf-8")
    if owner is not None:
        write_json(folder / appliance.PARSER_OWNER_FILE, owner)
    return folder


def test_a_new_run_removes_parser_clones_of_gone_runs_and_names_a_running_vm(tmp_path, monkeypatch):
    from fmb.collection.run import lock as run_lock
    from fmb.collection.tools.host import vmware

    monkeypatch.setattr(run_lock, "current_host", lambda: "this-mac")
    monkeypatch.setattr(run_lock, "process_is_running", lambda pid: pid == 111)
    monkeypatch.setattr(vmware, "vmrun_is_running", lambda **kwargs: False)
    work_root = tmp_path / "vm-work"
    gone = _clone_folder(work_root, "gone", {"pid": 222, "host": "this-mac", "run_id": "I1"})
    alive = _clone_folder(work_root, "alive", {"pid": 111, "host": "this-mac"})
    elsewhere = _clone_folder(work_root, "elsewhere", {"pid": 222, "host": "other-mac"})
    unowned = _clone_folder(work_root, "unowned", None)
    listing = "Total running VMs: 1\n/Users/me/vm-work/fmb-parser-alive/.vmrun-appliance/box.vmx\n"
    monkeypatch.setattr(appliance.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, listing, ""))
    monkeypatch.setattr(vmware, "vmrun_executable", lambda: "/Applications/VMware Fusion.app/Contents/Library/vmrun")
    monkeypatch.setattr(vmware, "vmrun_target_for_provider", lambda provider: "fusion")
    args = argparse.Namespace(vm_work_root=work_root, run_id="I2", collection_provider="vmware_desktop",
                              windows_box="fmb/windows-11-arm64")
    logged: list[str] = []
    vm = appliance.ParserVM(args=args, stage_dir=tmp_path / "analysis", progress=logged.append)

    with pytest.raises(appliance.ParserApplianceError) as raised:
        vm.start()
    assert vm._thread is None
    assert str(raised.value) == (
        "another VM is running; the parser appliance needs the single VM slot\n"
        "  running: /Users/me/vm-work/fmb-parser-alive/.vmrun-appliance/box.vmx\n"
        "If it is not in use (for example left by an fmb run that was killed), stop it with: "
        "'/Applications/VMware Fusion.app/Contents/Library/vmrun' -T fusion stop "
        "/Users/me/vm-work/fmb-parser-alive/.vmrun-appliance/box.vmx hard")
    assert not gone.exists() and alive.is_dir() and elsewhere.is_dir() and unowned.is_dir()
    assert logged == [f"parser appliance: removed the parser VM of run I1 (pid 222 is gone): {gone}"]


def test_the_parser_clone_names_its_owner_and_keeps_its_vmware_log(parser_case, monkeypatch):
    from fmb.collection.tools.host import vmware

    owners = []

    def clone(**kwargs):
        vmx = parser_case.clone(**kwargs)
        owners.append(json.loads((kwargs["vm_work_dir"] / appliance.PARSER_OWNER_FILE).read_text(encoding="utf-8")))
        (vmx.parent / "vmware.log").write_text("vmx| Power on\n", encoding="utf-8")
        return vmx

    monkeypatch.setattr(vmware, "clone_vagrant_box_for_vmrun", clone)
    parser_case.run(parser_case.work_root)

    assert owners[0]["pid"] == os.getpid() and owners[0]["run_id"] == "analysis" and owners[0]["host"]
    assert list(parser_case.work_root.iterdir()) == []
    kept = parser_case.stage / appliance.APPLIANCE_DIR_NAME / "parser-vm-vmware.log"
    assert kept.read_text(encoding="utf-8") == "vmx| Power on\n"


def test_a_boot_failure_is_kept_when_the_collection_fails_first(parser_case, monkeypatch):
    from fmb.collection.tools.host import vmware

    def fail(**kwargs):
        raise RuntimeError("worker did not boot")

    monkeypatch.setattr(vmware, "vmrun_start_and_wait", fail)
    args = argparse.Namespace(vm_work_root=parser_case.work_root, run_id="analysis",
                              collection_provider="vmware_desktop", windows_box="fmb/windows-11-arm64")
    vm = appliance.ParserVM(args=args, stage_dir=parser_case.stage).start()
    failure = RuntimeError("host collection failed")
    vm._thread.join()
    vm.discard(failure)
    assert failure.__notes__ == ["The parser VM had also failed to boot: RuntimeError: worker did not boot"]
    assert list(parser_case.work_root.iterdir()) == []


@pytest.mark.skipif(not Path("/proc/self/cmdline").is_file(), reason="needs /proc")
def test_an_orphaned_parser_qemu_is_stopped_and_its_overlay_removed(tmp_path, monkeypatch):
    import signal
    import sys

    from fmb.collection.run import lock as run_lock

    import time

    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "-name", "fmb-parser-999999"])
    try:
        deadline = time.monotonic() + 30
        while sleeper.pid not in (found := dict(appliance._parser_qemus())) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert found[sleeper.pid][-3:-1] == ["-name", "fmb-parser-999999"]
    finally:
        sleeper.kill()
        sleeper.wait(timeout=30)

    states = {}
    for owner in ("222", "111"):
        state = tmp_path / owner / "parser-appliance" / appliance.QEMU_STATE_DIR
        state.mkdir(parents=True)
        (state / "system.qcow2").write_bytes(b"overlay")
        states[owner] = state
    monkeypatch.setattr(appliance, "_parser_qemus", lambda: [
        (4000 + int(owner), ["qemu-system-x86_64", "-name", f"fmb-parser-{owner}",
                             "-pidfile", str(state / "qemu.pid"), ""]) for owner, state in states.items()])
    monkeypatch.setattr(run_lock, "process_is_running", lambda pid: pid == 111)
    killed = []
    monkeypatch.setattr(appliance.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    logged: list[str] = []

    appliance.reap_orphan_parser_qemus(logged.append)

    assert killed == [(4222, signal.SIGKILL)]
    assert not states["222"].exists() and states["111"].is_dir()
    assert logged == ["parser appliance: stopped the parser QEMU (pid 4222) of a gone fmb run (pid 222)"]


def test_the_qemu_monitor_reply_is_read_up_to_the_prompt():
    import socket
    import threading
    import time

    from fmb.generation.backends import QemuBackend

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        connection, _ = server.accept()
        with connection:
            connection.sendall(b"QEMU 8.2.2 monitor - type 'help' for more information\r\n")
            time.sleep(0.2)
            connection.sendall(b"(qemu) ")
            connection.recv(1024)
            connection.sendall(b"drive_add 0 if=none,id=usb8\r\n")
            time.sleep(1.0)
            connection.sendall(b"Could not open '/m8.vmdk': No such file or directory\r\n(qemu) ")
            time.sleep(0.5)

    threading.Thread(target=serve, daemon=True).start()
    backend = QemuBackend(pipeline=None)
    backend.monitor_port = server.getsockname()[1]
    with server:
        reply = backend._monitor("drive_add 0 if=none,id=usb8")
    assert "Could not open" in reply and reply.rstrip().endswith("(qemu)")


def test_parser_outputs_with_long_fields_read_without_collection(tmp_path):
    import subprocess
    import sys

    csv_path = tmp_path / "PECmd_Output.csv"
    csv_path.write_text("ExecutableName,FilesLoaded\nRUNNER.EXE," + "x" * 300_000 + "\n", encoding="utf-8")
    script = ("import sys\nfrom pathlib import Path\nfrom fmb.index.support.windows_artifacts import stream_csv_rows\n"
              "print(len(next(stream_csv_rows(Path(sys.argv[1])))['FilesLoaded']))\n")
    completed = subprocess.run([sys.executable, "-c", script, str(csv_path)], capture_output=True, text=True,
                               env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}, timeout=120)
    assert completed.stdout.strip() == "300000", completed.stderr


@pytest.mark.parametrize("change", ["extra", "missing"])
def test_a_mid_run_seal_failure_names_the_file(tmp_path, change):
    from fmb.core.paper_integrity import source_files, verify_sources

    roots = {"package": tmp_path / "package"}
    module = roots["package"] / "analysis" / "rules.py"
    module.parent.mkdir(parents=True)
    module.write_text("x = 1\n", encoding="utf-8")
    manifest = tmp_path / "lock.json"
    manifest.write_text(json.dumps({"schema_version": "paper_source_manifest.v1", "files": {
        name: __import__("hashlib").sha256(path.read_bytes()).hexdigest()
        for name, path in source_files(roots).items()}}), encoding="utf-8")
    if change == "extra":
        (module.parent / ".DS_Store").write_bytes(b"\0")
        expected = "membership changed: added package/analysis/.DS_Store"
    else:
        module.unlink()
        expected = "membership changed: missing package/analysis/rules.py"
    with pytest.raises(ValueError, match=expected):
        verify_sources(manifest, roots=roots)


def test_a_symlinked_source_is_named(tmp_path):
    from fmb.core.paper_integrity import source_files

    package = tmp_path / "package"
    package.mkdir()
    (package / "rules.py").write_text("x = 1\n", encoding="utf-8")
    try:
        os.symlink(package / "rules.py", package / "alias.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlinked implementation asset: .*alias.py"):
        source_files({"package": package})
