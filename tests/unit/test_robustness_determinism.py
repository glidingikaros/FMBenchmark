from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from fmb.collection.tools.host import backend as host_backend
from fmb.collection.tools.host.definitions import ModuleProcessor
from fmb.collection.tools.host.modules import run_module_processors, strip_run_stamps
from fmb.collection.tools.host.toolchain import HostToolchain
from fmb.core.json_io import write_json

# A stand-in for the EZ tools: it names its outputs and writes its path columns the way MFTECmd and RECmd do.
FAKE_TOOL = r'''
import json, os, random, sys
args = sys.argv[1:]
stamp = os.environ["FAKE_STAMP"]
with open(os.environ["FAKE_CALLS"], "a", encoding="utf-8") as calls:
    calls.write(json.dumps({"cwd": os.getcwd(), "args": args}) + "\n")
dest = args[args.index("--csv") + 1]
os.makedirs(dest, exist_ok=True)
if "-f" in args:
    source = args[args.index("-f") + 1]
    with open(os.path.join(dest, f"{stamp}_MFTECmd_$MFT_Output.csv"), "w", encoding="utf-8", newline="") as out:
        out.write("EntryNumber,SequenceNumber,FileName,SourceFile\r\n")
        out.write(f"41,3,report.txt,{source}\r\n")
elif "--mp" in args:
    # LECmd: Path.GetFullPath(d), and the file times of the copy it reads (here: the time of this run).
    directory = os.path.abspath(args[args.index("-d") + 1])
    moment = f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[8:10]}:{stamp[10:12]}:{stamp[12:]}.0000000"
    with open(os.path.join(dest, f"{stamp}_LECmd_Output.csv"), "w", encoding="utf-8-sig", newline="") as out:
        out.write("SourceFile,SourceCreated,SourceModified,SourceAccessed,LocalPath\r\n")
        for root, _dirs, names in sorted(os.walk(directory)):
            for name in sorted(names):
                if name.endswith(".lnk"):
                    out.write(f"{os.path.join(root, name)},{moment},2024-05-02 09:00:00.0000001,{moment},"
                              "C:\\Users\\u\\report.txt\r\n")
else:
    directory = args[args.index("-d") + 1]
    batch = args[args.index("--bn") + 1]
    assert os.path.isfile(batch), batch
    hives = sorted(os.path.join(root, name) for root, _dirs, names in os.walk(directory) for name in names
                   if name.upper() in {"NTUSER.DAT", "SYSTEM", "SOFTWARE"})
    random.Random(stamp).shuffle(hives)
    rows = []
    for hive in hives:
        plugin = os.path.join(dest, stamp, f"{stamp}_Plugin_{hive.replace(directory, '')}.csv")
        os.makedirs(os.path.dirname(plugin), exist_ok=True)
        with open(plugin, "w", encoding="utf-8") as out:
            out.write("Name,Value\n" + f"{os.path.basename(hive)},1\n")
        rows += [f"{hive},Key{n},Value{n},{plugin}" for n in (1, 2)]
    stem = os.path.splitext(os.path.basename(batch))[0]
    with open(os.path.join(dest, f"{stamp}_RECmd_Batch_{stem}_Output.csv"), "w", encoding="utf-8-sig",
              newline="") as out:
        out.write("HivePath,KeyPath,ValueName,PluginDetailFile\r\n" + "".join(row + "\r\n" for row in rows))
print("Command line: " + " ".join(args))
'''


def _toolchain(root: Path, names: tuple[str, ...] = ("MFTECmd", "RECmd")) -> HostToolchain:
    tools = []
    for name in names:
        tool_dir = root / "toolchain" / name
        (tool_dir / "BatchExamples").mkdir(parents=True)
        (tool_dir / "BatchExamples" / "Kroll_Batch.reb").write_text("batch", encoding="utf-8")
        entry = tool_dir / "tool.py"
        entry.write_text(FAKE_TOOL, encoding="utf-8")
        tools.append({"tool": name, "executable": name + ".exe", "directory": name, "entry_assembly": entry.name,
                      "entry_assembly_sha256": hashlib.sha256(entry.read_bytes()).hexdigest(), "version": "1.0",
                      "host_runnable": True,
                      "source": {"repository": "https://example.invalid/tool", "commit_sha": "0" * 40}})
    lock = {"schema_version": "fmb_host_toolchain_lock.v1", "dotnet_sdk": "10.0.107", "dotnet_runtime": "10.0.7",
            "tools": tools}
    write_json(root / "lock.json", lock)
    return HostToolchain(root / "toolchain", lock, lock_path=root / "lock.json")


def _processor(name: str, category: str, command: str, file_mask: str | None) -> ModuleProcessor:
    return ModuleProcessor(
        requested_module=name, module_name=name, definition="fixture", definition_id=name, category=category,
        export_format="csv", file_mask=file_mask, executable=name.split("_")[0] + ".exe", command_line=command,
    )


PROCESSORS = [
    _processor("MFTECmd_$MFT", "FileSystem", "-f %sourceFile% --csv %destinationDirectory%", "$MFT"),
    _processor("RECmd_Kroll", "Registry",
               "-d %sourceDirectory% --bn BatchExamples\\Kroll_Batch.reb --nl false --csv %destinationDirectory%",
               None),
]


def _collect(folder: Path, stamp: str, monkeypatch, runs: list | None = None) -> Path:
    bundle = folder / "analysis" / "execution" / "01-collection" / "extracted" / "kape-output"
    targets = bundle / "targets" / "C"
    (targets / "Windows" / "System32" / "config").mkdir(parents=True)
    (targets / "Users" / "u").mkdir(parents=True)
    (targets / "$MFT").write_bytes(b"FILE" * 256)
    for hive in ("Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE", "Users/u/NTUSER.DAT"):
        (targets / hive).write_bytes(b"regf")
    monkeypatch.setenv("FAKE_STAMP", stamp)
    monkeypatch.setenv("FAKE_CALLS", str(folder / "calls.jsonl"))
    done = run_module_processors(
        PROCESSORS, toolchain=_toolchain(folder), dotnet=sys.executable, targets_root=bundle / "targets",
        modules_root=bundle / "modules", tool_logs_dir=folder / "tool-logs",
    )
    (runs if runs is not None else []).extend(done)
    return bundle


def _module_outputs(bundle: Path) -> dict[str, bytes]:
    return {path.relative_to(bundle).as_posix(): path.read_bytes()
            for path in sorted((bundle / "modules").rglob("*")) if path.is_file() and path.suffix == ".csv"}


def test_ez_tools_run_in_the_bundle_on_relative_paths(tmp_path: Path, monkeypatch) -> None:
    bundle = _collect(tmp_path / "run", "20261011101500", monkeypatch)
    calls = [json.loads(line) for line in (tmp_path / "run" / "calls.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {Path(call["cwd"]) for call in calls} == {bundle}
    assert calls[0]["args"] == ["-f", "targets/C/$MFT", "--csv", "modules/FileSystem"]
    assert calls[1]["args"][:2] == ["-d", "targets"]
    assert Path(calls[1]["args"][3]) == tmp_path / "run" / "toolchain" / "RECmd" / "BatchExamples" / "Kroll_Batch.reb"
    mft = (bundle / "modules" / "FileSystem" / "MFTECmd_$MFT_Output.csv").read_text(encoding="utf-8")
    assert mft.splitlines()[1] == "41,3,report.txt,targets/C/$MFT"
    console = next((bundle / "modules" / "Registry").glob("RECmd-*.console.log")).read_text(encoding="utf-8")
    assert console.splitlines()[0] == (
        "Command line: -d targets --bn BatchExamples/Kroll_Batch.reb --nl false --csv modules/Registry")


def test_ez_tool_outputs_lose_their_run_time_prefix(tmp_path: Path, monkeypatch) -> None:
    bundle = _collect(tmp_path / "run", "20261011101500", monkeypatch)
    names = sorted(_module_outputs(bundle))
    assert names[0] == "modules/FileSystem/MFTECmd_$MFT_Output.csv"
    assert "modules/Registry/RECmd_Batch_Kroll_Batch_Output.csv" in names
    assert "modules/Registry/Plugins/Plugin__C_Windows_System32_config_SYSTEM.csv" in names
    assert not any("20261011101500" in name for name in names)
    assert not (bundle / "modules" / "Registry" / "20261011101500").exists()


def test_a_name_taken_by_an_earlier_output_gets_a_numbered_name(tmp_path: Path) -> None:
    (tmp_path / "A_Output.csv").write_text("first", encoding="utf-8")
    before = {tmp_path / "A_Output.csv"}
    (tmp_path / "20261011101500_A_Output.csv").write_text("second", encoding="utf-8")
    (tmp_path / "20261011101500").mkdir()
    (tmp_path / "20261011101500" / "20261011101500_Plugin_x.csv").write_text("plugin", encoding="utf-8")
    strip_run_stamps(tmp_path, created_before=before)
    assert sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file()) == [
        "A_Output-2.csv", "A_Output.csv", "Plugins/Plugin_x.csv"]
    assert (tmp_path / "A_Output-2.csv").read_text(encoding="utf-8") == "second"


def test_host_collector_command_lines_name_no_host_folder() -> None:
    target_line, module_line, _argv = host_backend._host_command_lines(
        evidence=Path("/home/someone/fmb/generated/I1/I1.vmdk"),
        targets_root=Path("/home/someone/fmb/results/I1/20261011-101500/kape-output/targets"),
        modules_root=Path("/home/someone/fmb/results/I1/20261011-101500/kape-output/modules"),
        targets="$MFT", modules="MFTECmd",
    )
    assert target_line == "fmb-host-collector targets --evidence I1.vmdk --tdest targets --target $MFT"
    assert module_line == "fmb-host-collector modules --msource targets --mdest modules --module MFTECmd"


def test_parser_appliance_outputs_lose_their_run_time_prefix(tmp_path: Path) -> None:
    from fmb.collection.tools.host import parser_appliance

    package = {"commands": [{"label": "PECmd", "category": "ProgramExecution", "executable_sha256": "e" * 64,
                             "input_file_count": 1, "input_byte_count": 3}],
               "package_sha256": "p" * 64, "input_file_count": 1}
    receipt = {"schema_version": parser_appliance.RECEIPT_SCHEMA, "os": "Windows", "machine": "ARM64",
               "results": [{"label": "PECmd", "executable_sha256": "e" * 64, "exit_code": 0,
                            "category": "ProgramExecution", "arguments": []}]}
    outputs_zip = tmp_path / "outputs.zip"
    with zipfile.ZipFile(outputs_zip, "w") as opened:
        opened.writestr("receipt.json", json.dumps(receipt))
        opened.writestr("modules\\ProgramExecution\\20261011101500_PECmd_Output.csv", "SourceFilename,RunCount\na,1\n")
    (tmp_path / "logs").mkdir()
    record = parser_appliance._merge_outputs(
        outputs_zip=outputs_zip, appliance_dir=tmp_path / "appliance",
        modules_root=tmp_path / "kape-output" / "modules", tool_logs=tmp_path / "logs", package=package,
    )
    assert "modules/ProgramExecution/PECmd_Output.csv" in record["outputs"]


def test_pecmd_rows_carry_the_images_times_not_the_time_it_read_the_file(tmp_path: Path) -> None:
    from fmb.collection.tools.host import parser_appliance

    package = {"commands": [{"label": "PECmd", "category": "ProgramExecution", "executable_sha256": "e" * 64,
                             "input_file_count": 2, "input_byte_count": 6}],
               "package_sha256": "p" * 64, "input_file_count": 2}
    receipt = {"schema_version": parser_appliance.RECEIPT_SCHEMA, "os": "Windows", "machine": "X64",
               "results": [{"label": "PECmd", "executable_sha256": "e" * 64, "exit_code": 0,
                            "category": "ProgramExecution", "arguments": []}]}
    known = "C:\\FMB-Parsers\\work\\targets\\C\\Windows\\prefetch\\A.EXE-1.pf"
    unknown = "C:\\FMB-Parsers\\work\\targets\\C\\Windows\\prefetch\\B.EXE-2.pf"
    outputs_zip = tmp_path / "outputs.zip"
    with zipfile.ZipFile(outputs_zip, "w") as opened:
        opened.writestr("receipt.json", json.dumps(receipt))
        opened.writestr("modules\\ProgramExecution\\20261011101500_PECmd_Output.csv",
                        "\ufeffSourceFilename,SourceCreated,SourceModified,SourceAccessed,RunCount\r\n"
                        f"{known},2024-05-01 08:00:00.1234567,2024-05-02 09:00:00.0000001,2026-10-12 17:11:20.9542681,3\r\n"
                        f"{unknown},2024-05-01 08:00:00.0000000,2024-05-01 08:00:00.0000000,2026-10-12 17:11:21.0000000,1\r\n")
    times = {"targets/C/Windows/prefetch/A.EXE-1.pf": {"created": 133590240001234567, "modified": 133591140000000001,
                                                       "accessed": 133592040000000000}}
    (tmp_path / "logs").mkdir()
    parser_appliance._merge_outputs(
        outputs_zip=outputs_zip, appliance_dir=tmp_path / "appliance", modules_root=tmp_path / "kape-output" / "modules",
        tool_logs=tmp_path / "logs", package=package, source_times=times,
    )
    written = (tmp_path / "kape-output" / "modules" / "ProgramExecution" / "PECmd_Output.csv").read_bytes()
    assert written.startswith(b"\xef\xbb\xbf")
    assert written.decode("utf-8-sig").splitlines()[1:] == [
        f"{known},2024-05-01 08:00:00.1234567,2024-05-02 09:00:00.0000001,2024-05-03 10:00:00.0000000,3",
        f"{unknown},2024-05-01 08:00:00.0000000,2024-05-01 08:00:00.0000000,2026-10-12 17:11:21.0000000,1",
    ]


def test_the_membership_scan_names_its_journal_relative_to_its_record(tmp_path: Path, monkeypatch) -> None:
    from fmb.collection import analysis, factual_challenge

    journal = tmp_path / "kape-output" / "targets" / "C" / "$Extend" / "$J"
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"\0" * 4096)
    monkeypatch.setattr(analysis, "_raw_usn_journal_path", lambda _index: journal)
    monkeypatch.setattr(factual_challenge, "normalize_parser_output", lambda **_: {})
    output = tmp_path / "factual-supplement"
    output.mkdir()
    factual_challenge._membership_usn_run(
        {"collector_runs": [{"collector": "kape"}]},
        {"members": [{"question_id": "BQ-DELETE-01", "path": "C:\\Users\\u\\gone.txt"}]}, output, {"source_paths": []})
    written = json.loads((output / "public-membership-usn.json").read_text(encoding="utf-8"))
    assert written["source"] == "../kape-output/targets/C/$Extend/$J"


def test_readers_accept_tool_paths_relative_to_the_bundle(tmp_path: Path) -> None:
    from fmb.analysis.evidence_projection import _collected_artifact_path
    from fmb.index.adapters.usn import collected_usn_journal_path
    from fmb.index.support.windows_artifacts import kape_relative_path

    journal = tmp_path / "kape-output" / "targets" / "C" / "$Extend" / "$J"
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"\0" * 64)
    run = {"output_root": str(tmp_path / "kape-output")}
    assert collected_usn_journal_path("targets/C/$Extend/$J", run) == journal.resolve()
    assert collected_usn_journal_path("targets\\C\\$Extend\\$J", run) == journal.resolve()
    assert kape_relative_path("targets\\C\\Users\\u\\x.lnk") == kape_relative_path(
        str(tmp_path / "kape-output" / "targets" / "C" / "Users" / "u" / "x.lnk")) == "targets/c/users/u/x.lnk"
    relative = "targets\\C\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    assert _collected_artifact_path(relative) == _collected_artifact_path(
        "C:\\r\\kape-output\\" + relative) == "targets/C/Windows/System32/winevt/Logs/Security.evtx"


def test_recmd_rows_follow_its_hive_masks_and_name_the_renamed_plugin_files(tmp_path: Path, monkeypatch) -> None:
    import csv

    bundle = _collect(tmp_path / "run", "20261011101500", monkeypatch)
    with (bundle / "modules" / "Registry" / "RECmd_Batch_Kroll_Batch_Output.csv").open(
            encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    # RECmd writes the hive path with the host's separator, as the fake tool here does.
    assert [(row["HivePath"].replace("\\", "/"), row["KeyPath"]) for row in rows] == [
        ("targets/C/Users/u/NTUSER.DAT", "Key1"), ("targets/C/Users/u/NTUSER.DAT", "Key2"),
        ("targets/C/Windows/System32/config/SYSTEM", "Key1"), ("targets/C/Windows/System32/config/SYSTEM", "Key2"),
        ("targets/C/Windows/System32/config/SOFTWARE", "Key1"),
        ("targets/C/Windows/System32/config/SOFTWARE", "Key2"),
    ]
    for row in rows:
        assert (bundle / row["PluginDetailFile"]).is_file()
    assert rows[0]["PluginDetailFile"] == "modules/Registry/Plugins/Plugin__C_Users_u_NTUSER.DAT.csv"


SHORTCUT = "targets/C/Users/u/AppData/Roaming/Microsoft/Windows/Recent/report.lnk"
LECMD = _processor("LECmd", "FileFolderAccess", "-d %sourceDirectory% --csv %destinationDirectory% -q --mp", None)


def _lecmd(folder: Path, stamp: str, monkeypatch) -> tuple[Path, list]:
    bundle = folder / "analysis" / "execution" / "01-collection" / "extracted" / "kape-output"
    (bundle / SHORTCUT).parent.mkdir(parents=True)
    (bundle / SHORTCUT).write_bytes(b"L")
    (bundle / "targets" / f"{stamp}_CopyLog.csv").write_text(
        "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,"
        "ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\n"
        f"x,C:\\Users\\u\\report.lnk,{SHORTCUT},1,AA,False,2024-05-01 08:00:00.1234567,"
        "2024-05-02 09:00:00.0000001,2024-05-03 10:00:00,00:00:00\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FAKE_STAMP", stamp)
    monkeypatch.setenv("FAKE_CALLS", str(folder / "calls.jsonl"))
    runs = run_module_processors(
        [LECMD], toolchain=_toolchain(folder, ("LECmd",)), dotnet=sys.executable, targets_root=bundle / "targets",
        modules_root=bundle / "modules", tool_logs_dir=folder / "tool-logs",
    )
    return bundle, runs


def test_lecmd_rows_name_no_run_folder_and_no_extraction_time(tmp_path: Path, monkeypatch) -> None:
    first, first_runs = _lecmd(tmp_path / "a", "20261011101500", monkeypatch)
    second, second_runs = _lecmd(tmp_path / "elsewhere" / "b", "20261012134512", monkeypatch)
    assert _module_outputs(first) == _module_outputs(second)
    assert first_runs[0].rewritten_outputs != second_runs[0].rewritten_outputs
    lecmd = (first / "modules" / "FileFolderAccess" / "LECmd_Output.csv").read_text(encoding="utf-8-sig")
    assert lecmd.splitlines()[1] == (
        f"{SHORTCUT},2024-05-01 08:00:00.1234567,2024-05-02 09:00:00.0000001,2024-05-03 10:00:00.0000000,"
        "C:\\Users\\u\\report.txt")


def test_two_runs_in_two_folders_write_the_same_module_outputs(tmp_path: Path, monkeypatch) -> None:
    first_runs, second_runs = [], []
    first = _collect(tmp_path / "a", "20261011101500", monkeypatch, first_runs)
    second = _collect(tmp_path / "elsewhere" / "b", "20261012134512", monkeypatch, second_runs)
    recmd = [next(run for run in runs if run.tool_name == "RECmd") for runs in (first_runs, second_runs)]
    assert recmd[0].rewritten_outputs != recmd[1].rewritten_outputs
    assert _module_outputs(first) == _module_outputs(second)
    assert [run.outputs for run in first_runs] == [run.outputs for run in second_runs]


def test_event_log_scope_is_named_by_the_log_path_inside_targets() -> None:
    from fmb.index.adapters.event_log import event_log_scope_id

    csv_path = Path("EvtxECmd_Output.csv")
    spellings = [
        "targets/C/Windows/System32/winevt/Logs/Security.evtx",
        "targets\\C\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        "/home/someone/results/I1/20261011-101500/run/analysis/execution/01-collection/extracted/kape-output/"
        "targets/C/Windows/System32/winevt/Logs/Security.evtx",
        "C:\\Users\\someone\\results\\I1\\20261012-090000\\kape-output\\targets\\C\\Windows\\System32\\winevt\\Logs"
        "\\Security.evtx",
    ]
    assert len({event_log_scope_id("Security", spelling, csv_path) for spelling in spellings}) == 1


def _normalized_run(analysis: Path) -> tuple[Path, dict]:
    from fmb.index.adapters.parser_output import write_observation_index

    raw = analysis / "execution" / "01-collection" / "extracted" / "kape-output" / "modules" / "X" / "Tool_Output.csv"
    raw.parent.mkdir(parents=True)
    raw.write_text("a,b\n", encoding="utf-8")
    path = write_observation_index(
        normalized_output_dir=analysis / "execution" / "02-normalization" / "parser-normalized", raw_output=raw,
        file_suffix="tool.observations.json", parser="Tool", parser_kind="tool", observations=[],
    )
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_normalized_outputs_are_named_and_sourced_from_the_collection_folder(tmp_path: Path) -> None:
    first, first_document = _normalized_run(tmp_path / "one" / "analysis")
    second, second_document = _normalized_run(tmp_path / "other" / "place" / "analysis")
    assert first.name == second.name and first_document == second_document
    assert first_document["source"] == "../../01-collection/extracted/kape-output/modules/X/Tool_Output.csv"


def _logfile_run(analysis: Path, monkeypatch) -> tuple[dict, bytes]:
    from fmb.index.adapters import logfile

    logfile_path = analysis / "execution" / "01-collection" / "extracted" / "kape-output" / "targets" / "C" / "$LogFile"
    logfile_path.parent.mkdir(parents=True)
    logfile_path.write_bytes(b"RSTR" * 1024)
    normalized = analysis / "execution" / "02-normalization" / "parser-normalized"
    normalized.mkdir(parents=True)
    output = logfile.normalized_output_path(normalized, logfile_path, logfile.LOGFILE_DRIVER_DOCUMENT_SUFFIX)
    document = {
        "parse": {"record_count": 2, "lsn_first": 10, "lsn_last": 20, "parse_error_count": 0,
                  "duration_seconds": float(len(str(analysis)))},
        "embedded_usn": {}, "logfile": {"size_bytes": 4096, "sha256": "f" * 64}, "operation_counts": {},
        "restart_areas": [],
        "runtime": {"command_line": f"/opt/py /opt/driver.py --logfile {logfile_path} --output {output} --ops x"},
    }
    monkeypatch.setattr(logfile, "_logfile_document", lambda *_args, **_kwargs: (
        document, {"available": True, "tool_identity": {"name": "dfir_ntfs", "version": "1"}}))
    run = logfile.raw_logfile_parser_run(logfile_path=logfile_path, normalized_output_dir=normalized,
                                         collector_run={"collector": "kape"})
    return run, Path(run["normalized_output"]["path"]).read_bytes()


def test_logfile_records_name_no_run_folder_and_no_parse_time(tmp_path: Path, monkeypatch) -> None:
    first, first_scope = _logfile_run(tmp_path / "one" / "analysis", monkeypatch)
    second, second_scope = _logfile_run(tmp_path / "another" / "analysis", monkeypatch)
    assert first_scope == second_scope
    assert first["command_line"] == second["command_line"]
    assert str(tmp_path) not in first["command_line"]


def _native_parsers(tmp_path: Path, monkeypatch, root: Path) -> tuple[list[list[str]], Path]:
    from fmb.collection.tools.host import parser_appliance
    from fmb.core import owned_process

    commands: list[list[str]] = []

    def run(command, **_kwargs):
        commands.append(command)
        (root / "outputs.zip").write_bytes(b"zip")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(parser_appliance, "native_parser_root", lambda: root)
    monkeypatch.setattr(parser_appliance, "_windows_powershell", lambda: ("powershell.exe", {}))
    monkeypatch.setattr(owned_process, "run_owned", run)
    (tmp_path / "inputs.zip").write_bytes(b"in")
    (tmp_path / "run_parsers.ps1").write_text("", encoding="utf-8")
    outputs = tmp_path / "outputs.zip"
    parser_appliance._run_native_windows_parsers(
        package_path=tmp_path / "inputs.zip", script_path=tmp_path / "run_parsers.ps1", outputs_zip=outputs)
    return commands, outputs


def test_native_windows_parsers_run_in_one_fixed_folder(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "FMB-Parsers"
    first, outputs = _native_parsers(tmp_path, monkeypatch, root)
    second, _ = _native_parsers(tmp_path, monkeypatch, root)
    assert first == second and first[0][-2:] == ["-Root", str(root)]
    assert outputs.read_bytes() == b"zip" and not root.exists()


def test_native_windows_parsers_wait_for_another_run_to_leave_the_folder(tmp_path: Path, monkeypatch) -> None:
    from fmb.collection.run.lock import _try_lock
    from fmb.collection.tools.host import parser_appliance

    root = tmp_path / "FMB-Parsers"
    root.mkdir()
    holder = os.open(root / parser_appliance.NATIVE_ROOT_LOCK, os.O_RDWR | os.O_CREAT)
    assert _try_lock(holder)
    monkeypatch.setattr(parser_appliance, "DEFAULT_GUEST_TIMEOUT_SECONDS", 0)
    try:
        with pytest.raises(parser_appliance.ParserApplianceError, match="another fmb run"):
            _native_parsers(tmp_path, monkeypatch, root)
    finally:
        os.close(holder)
    assert _native_parsers(tmp_path, monkeypatch, root)[0]


# One collection as the host tools leave it: their path columns relative to the bundle (targets/...).
COLLECTED = {
    "targets/C/$MFT": b"\0" * 2048,
    "modules/FileSystem/MFTECmd_$MFT_Output.csv": (
        "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,"
        "FileSize,IsDirectory,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30,SourceFile\n"
        "42,3,True,5,5,.\\Users\\alice,report.txt,.txt,10,False,2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,targets/C/$MFT\n").encode(),
    "modules/EventLogs/EvtxECmd_Output.csv": (
        "EventId,EventRecordId,Channel,SourceFile\n"
        "1102,77,Security,targets\\C\\Windows\\System32\\winevt\\Logs\\Security.evtx\n").encode(),
    "modules/Registry/RECmd_Batch_Kroll_Batch_Output.csv": (
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,"
        "Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile\n"
        "targets\\C\\Users\\alice\\NTUSER.DAT,NtUser,TypedPaths,File and folder opening,"
        "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,url1,RegSz,C:\\Users\\alice\\gone,"
        ",,,False,False,2026-10-01 10:00:00,\n").encode(),
    "modules/ProgramExecution/PECmd_Output.csv": (
        "ExecutableName,SourceFilename,RunCount\n"
        "RUNNER.EXE,C:\\FMB-Parsers\\work\\targets\\C\\Windows\\prefetch\\RUNNER.EXE-AAAA1111.pf,1\n").encode(),
    "modules/FileFolderAccess/alice_NTUSER.csv": (
        "AbsolutePath,BagPath,ShellType,Value\nThis PC\\C:\\Users\\alice\\Desktop,1,Directory,1\n").encode(),
}


def _indexed(analysis: Path) -> dict:
    from fmb.core.collection_paths import relative_to_collection
    from fmb.index.kape.sources import scan_kape_output_root

    root = analysis / "execution" / "01-collection" / "extracted" / "kape-output"
    for name, data in COLLECTED.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    normalized = analysis / "execution" / "02-normalization" / "parser-normalized"
    normalized.mkdir(parents=True)
    runs = scan_kape_output_root(root=root, normalized_output_dir=normalized,
                                 collector_run={"collector": "kape", "provenance": {}, "output_root": str(root)})
    return relative_to_collection({"parser_runs": runs}, analysis)


def test_one_collection_indexed_in_two_folders_gives_the_same_index(tmp_path: Path) -> None:
    first = _indexed(tmp_path / "results" / "I1" / "20261011-101500" / "run" / "analysis")
    second = _indexed(tmp_path / "other-home" / "results" / "I1" / "20261012-090000" / "run" / "analysis")
    text = json.dumps(first, sort_keys=True)
    assert text == json.dumps(second, sort_keys=True)
    assert str(tmp_path) not in text
    kinds = {run["parser_kind"]: run for run in first["parser_runs"]}
    assert kinds["windows_shellbag"]["observations"][0]["fields"]["source_file"] == "alice_NTUSER.csv"
    assert kinds["ntfs_mft"]["raw_outputs"][0]["path"] == (
        "execution/01-collection/extracted/kape-output/modules/FileSystem/MFTECmd_$MFT_Output.csv")


def test_a_collection_reads_its_relative_records_and_absolute_sidecars_where_it_is_now(tmp_path: Path) -> None:
    from fmb.core.collection_paths import CollectionPaths, relative_to_collection

    made = tmp_path / "made" / "analysis"
    generation = tmp_path / "generated" / "I1" / "full_scale.vmdk"
    for name in ("execution/x/out.csv", "factual-supplement/norm.json", "native-ntfs/native-ntfs.json"):
        (made / name).parent.mkdir(parents=True, exist_ok=True)
        (made / name).write_text("{}", encoding="utf-8")
    index = {"parser_runs": [{"raw_outputs": [{"path": str(made / "execution/x/out.csv")}, {"path": str(generation)}],
                              "normalized_output": {"path": str(made / "factual-supplement/norm.json")}}],
             "collector_runs": [{"output_root": str(made / "execution")}]}
    portable = relative_to_collection(index, made)
    assert portable["parser_runs"][0]["raw_outputs"] == [{"path": "execution/x/out.csv"}, {"path": str(generation)}]
    assert portable["parser_runs"][0]["normalized_output"] == {"path": "factual-supplement/norm.json"}
    assert portable["collector_runs"] == index["collector_runs"]
    write_json(made / "factual-collection.json", {"evidence": str(generation), "analysis": str(made)})
    assert not CollectionPaths(made, portable).relocated
    moved = tmp_path / "moved" / "analysis"
    moved.parent.mkdir()
    made.rename(moved)
    locate = CollectionPaths(moved, portable)
    assert locate.relocated
    assert locate("execution/x/out.csv") == moved.resolve() / "execution/x/out.csv"
    assert locate(str(made / "native-ntfs/native-ntfs.json")) == moved.resolve() / "native-ntfs/native-ntfs.json"


def _usb_receipt(generated: Path, analysis: Path, monkeypatch) -> Path:
    from fmb.collection import usb_volume

    kape = analysis / "execution" / "01-collection" / "extracted" / "kape-output"
    shortcut = kape / "targets/C/Users/vagrant/AppData/Roaming/Microsoft/Windows/Recent/native.lnk"
    shortcut.parent.mkdir(parents=True)
    shortcut.write_bytes(b"collected shortcut bytes")
    lecmd = kape / "modules" / "FileFolderAccess" / "LECmd_Output.csv"
    lecmd.parent.mkdir(parents=True)
    lecmd.write_text(
        "SourceFile,DriveType,VolumeSerialNumber,LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,"
        "TargetMFTSequenceNumber\n" + shortcut.relative_to(kape).as_posix() + ",\"Removable storage media (Floppy, USB)\","
        "AABBCCDD,U:\\Records\\original.txt,,This PC\\U:\\Records\\original.txt,0x1E,0x7\n", encoding="utf-8")
    monkeypatch.setattr(usb_volume, "extract_companion_streams",
                        lambda *_: {key: key.encode() for key in ("boot", "mft", "journal", "journal_max")})
    return usb_volume.collect_usb_volume(generation_manifest_path=generated / "manifest.json", kape_root=kape,
                                         output_dir=analysis / "native-usb", evidence_sha256="0" * 64)


def test_the_usb_receipt_names_the_collected_shortcut_relative_to_itself(tmp_path: Path, monkeypatch) -> None:
    from fmb.analysis.native_preparation import repair_usb_companion_rows
    from fmb.core.hashing import sha256_file
    from fmb.index.adapters.usb_volume import usb_volume_parser_run
    from fmb.index.scanners import usb_volume as scanner

    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "native_media.vmdk").write_bytes(b"companion")
    (generated / "native_media_binding.json").write_text(json.dumps({
        "schema_version": "native_media_binding.v1", "companion_file": "native_media.vmdk", "disk_bus_type": "USB",
        "attachment_kind": "hypervisor_virtual_usb_mass_storage", "physical_host_device": False,
        "link_path": "C:\\Users\\vagrant\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\native.lnk"}), encoding="utf-8")
    write_json(generated / "manifest.json", {"artifacts": [
        {"file": name, "size_bytes": (generated / name).stat().st_size, "sha256": sha256_file(generated / name)}
        for name in ("native_media.vmdk", "native_media_binding.json")] + [{"file": "full.vmdk", "sha256": "0" * 64}]})
    first = _usb_receipt(generated, tmp_path / "one" / "analysis", monkeypatch)
    second = _usb_receipt(generated, tmp_path / "two" / "deeper" / "analysis", monkeypatch)
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["source_link_path"] == (
        "../execution/01-collection/extracted/kape-output/targets/C/Users/vagrant/AppData/Roaming/Microsoft/Windows/"
        "Recent/native.lnk")
    facts = {"device_instance_id": "d", "active_mft_complete": True, "journal_scan_complete": True}
    monkeypatch.setattr("fmb.index.adapters.usb_volume.parse_usb_volume_facts", lambda **_: dict(facts))
    run = usb_volume_parser_run(native_manifest_path=first, normalized_output_dir=tmp_path / "normalized",
                                collector_run={"collector": "kape"})
    assert run["observations"][0]["subject_ref"] == "d"
    links = []
    monkeypatch.setattr(scanner, "lecmd_link_row", lambda link: links.append(link) or (None, {}))
    monkeypatch.setattr(scanner, "parse_usb_volume_facts", lambda **_: dict(facts))
    with pytest.raises(ValueError, match="omit a retained device"):
        repair_usb_companion_rows(type("Bundle", (), {"payload": {"candidate_roster": []}})(), first.parent)
    assert links == [(tmp_path / "one" / "analysis" / "execution/01-collection/extracted/kape-output/targets/C/Users/"
                      "vagrant/AppData/Roaming/Microsoft/Windows/Recent/native.lnk").resolve()]


def _paper_collection(analysis: Path, started: str, monkeypatch) -> dict:
    from argparse import Namespace

    from fmb.collection import analysis as collection_analysis
    from fmb.collection.paper_collection import collect

    out = analysis / "execution" / "01-collection" / "kape-output" / "modules" / "X" / "Tool_Output.csv"
    out.parent.mkdir(parents=True)
    out.write_text("a\n", encoding="utf-8")
    index = {"run_id": "analysis", "parser_runs": [{"parser": "Tool", "raw_outputs": [{"path": str(out)}]}],
             "collector_runs": [{"collector": "kape", "provenance": {"started_at": started}}]}
    monkeypatch.setattr(collection_analysis, "collect_evidence_index", lambda *_args, **_kwargs: index)
    collect(Namespace(output=analysis, evidence=analysis.parent / "full_scale.vmdk", windows_parsers=None,
                      host_toolchain_root=None), profile={})
    return json.loads((analysis / "factual-collection.json").read_text(encoding="utf-8"))


def test_two_collections_of_one_image_share_their_content_hash(tmp_path: Path, monkeypatch) -> None:
    first = _paper_collection(tmp_path / "one" / "analysis", "2026-10-11T10:15:00Z", monkeypatch)
    second = _paper_collection(tmp_path / "two" / "analysis", "2026-10-12T09:00:00Z", monkeypatch)
    assert first["evidence_index_sha256"] != second["evidence_index_sha256"]
    assert first["evidence_content_sha256"] == second["evidence_content_sha256"]
    assert first["analysis"] == str(tmp_path / "one" / "analysis")
    index = json.loads((tmp_path / "one" / "analysis" / "evidence_index.json").read_text(encoding="utf-8"))
    assert index["parser_runs"][0]["raw_outputs"][0]["path"] == (
        "execution/01-collection/kape-output/modules/X/Tool_Output.csv")


def test_g3_binds_the_collection_content_and_diff_compares_that(tmp_path: Path) -> None:
    from fmb.core.hashing import sha256_file
    from fmb.pipeline.diff import LOCATION_FIELDS, content
    from fmb.preparation.native import image_binding

    generation, analysis = tmp_path / "generation", tmp_path / "analysis"
    generation.mkdir()
    (generation / "full_scale.vmdk").write_bytes(b"image")
    image = sha256_file(generation / "full_scale.vmdk")
    write_json(generation / "manifest.json", {"artifacts": [{"file": "full_scale.vmdk", "sha256": image}]})
    (analysis / "factual-supplement").mkdir(parents=True)
    write_json(analysis / "factual-collection.json", {"evidence": "/x/full_scale.vmdk", "evidence_index_sha256": "7" * 64,
                                                      "evidence_content_sha256": "8" * 64})
    for name in ("native-surface-preparation.json", "public-population-binding.json"):
        write_json(analysis / "factual-supplement" / name, {"evidence_sha256": image})
    binding = image_binding(analysis=analysis, generation=generation)
    assert binding["evidence_content_sha256"] == "8" * 64
    drop = LOCATION_FIELDS["G3"]
    g3 = {"collection": binding}
    assert content(g3, drop=drop) == content({"collection": {**binding, "evidence_index_sha256": "9" * 64}}, drop=drop)
    assert content(g3, drop=drop) != content({"collection": {**binding, "evidence_content_sha256": "9" * 64}},
                                             drop=drop)


def test_a_repeated_run_is_compared_by_its_g3_to_g5_gates_and_evidence_content(tmp_path: Path, monkeypatch) -> None:
    from fmb.pipeline import diff

    gates = {"G1": {"status": "different"}, "G3": {"status": "same"},
             "G4:rules": {"status": "different", "first": [{"path": "/results/0/id", "a": "finding:a", "b": "finding:b"}]}}
    monkeypatch.setattr(diff, "diff_runs", lambda *_runs: {"gates": gates})
    for run, started in (("first", "10:15"), ("second", "11:30")):
        write_json(tmp_path / run / "analysis" / "evidence_index.json",
                   {"parser_runs": [{"path": "a.csv"}], "collector_runs": [{"started_at": started}]})
    assert diff.repeat_differences(tmp_path / "first", tmp_path / "second") == [
        "gates/G4-rules.json: different", "  /results/0/id: 'finding:a' | 'finding:b'"]
    gates["G4:rules"]["status"] = "same"
    assert diff.repeat_differences(tmp_path / "first", tmp_path / "second") == []
    write_json(tmp_path / "second" / "analysis" / "evidence_index.json", {"parser_runs": [{"path": "b.csv"}]})
    assert diff.repeat_differences(tmp_path / "first", tmp_path / "second") == [
        "analysis/evidence_index.json: 1 differences besides its collector runs", "  /parser_runs/0/path: 'a.csv' | 'b.csv'"]
    runs = [[{"path": "a.csv", "observations": [{"fields": {"read": f"{run}{n}"}} for n in range(3)]}] for run in "ab"]
    for run, parser_runs in zip(("first", "second"), runs):
        write_json(tmp_path / run / "analysis" / "evidence_index.json", {"parser_runs": parser_runs})
    assert diff.repeat_differences(tmp_path / "first", tmp_path / "second", shown=1) == [
        "analysis/evidence_index.json: 3 differences besides its collector runs",
        "  /parser_runs/0/observations/0/fields/read: 'a0' | 'b0'", "  all of them, by kind:",
        "  3 at /parser_runs/0/observations/*/fields/read, as 'a0' | 'b0'"]
