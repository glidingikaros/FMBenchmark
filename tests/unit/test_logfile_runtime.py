from __future__ import annotations

import json
import os
import shutil
import sys
import venv
from pathlib import Path

import pytest

from fmb.index.scanners import logfile_runtime
from fmb.index.scanners.logfile_runtime import (
    LogFileRuntimeError,
    LogFileToolchain,
    build_lock_document,
    logfile_runtime_availability,
    package_tree_sha256,
    run_logfile_driver,
)

FAKE_DRIVER = '''import argparse, json, sys
parser = argparse.ArgumentParser()
parser.add_argument("--logfile"); parser.add_argument("--output"); parser.add_argument("--ops")
parser.add_argument("--max-records", type=int); parser.add_argument("--usn-pages", action="store_true")
args = parser.parse_args()
document = {
    "schema_version": "fmb_logfile_records.v2",
    "driver": {"name": "fake"},
    "tool": {"name": "dfir_ntfs"},
    "logfile": {"path": args.logfile, "size_bytes": 0, "sha256": "0" * 64},
    "selection": {"operations": args.ops.split(","), "usn_pages": args.usn_pages, "max_records": args.max_records, "recover_log_data": True},
    "parse": {"log_version": [1, 1], "log_page_size": 4096, "lsn_first": 1, "lsn_last": 2, "record_count": 0,
              "restart_area_count": 0, "parse_error_count": 0, "emitted_record_count": 0, "records_truncated": False,
              "forgotten_transaction_count": 0, "rolled_back_transaction_count": 0, "open_transaction_count": 0, "duration_seconds": 0.0},
    "operation_counts": {},
    "embedded_usn": {"record_count": 0},
    "restart_areas": [],
    "records": [],
}
json.dump(document, open(args.output, "w"))
print(json.dumps({"ok": True}))
'''


def fake_environment(tmp_path: Path, *, driver_body: str = FAKE_DRIVER) -> tuple[Path, Path]:
    env_root = tmp_path / "venv"
    if os.name == "nt":
        venv.create(env_root)
        package = env_root / "Lib" / "site-packages" / "dfir_ntfs"
        (env_root / "pyvenv.cfg").write_text(
            (env_root / "pyvenv.cfg").read_text(encoding="utf-8") + "version_info = 3.13.5\n", encoding="utf-8")
    else:
        package = env_root / "lib" / "python3.13" / "site-packages" / "dfir_ntfs"
        (env_root / "bin").mkdir(parents=True)
        os.symlink(sys.executable, env_root / "bin" / "python")
        (env_root / "bin" / "ntfs_parser").write_text("#!/usr/bin/env python\n", encoding="utf-8")
        (env_root / "pyvenv.cfg").write_text("version = 3.13.5\n", encoding="utf-8")
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "LogFile.py").write_text("# fake\n", encoding="utf-8")
    (package / "__pycache__").mkdir()
    (package / "__pycache__" / "LogFile.cpython-313.pyc").write_bytes(b"ignored")
    driver = tmp_path / "driver.py"
    driver.write_text(driver_body, encoding="utf-8")
    return env_root, driver


def write_lock(tmp_path: Path, env_root: Path, driver: Path) -> Path:
    lock = build_lock_document(
        env_root=env_root,
        version="9.9.9",
        commit_id="deadbeef",
        generated_at="2026-09-12T00:00:00+00:00",
        driver_path=driver,
    )
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    return lock_path


def test_package_tree_hash_ignores_bytecode_and_is_order_stable(tmp_path: Path) -> None:
    env_root, _driver = fake_environment(tmp_path)
    package = logfile_runtime._package_dir(env_root)

    digest, files = package_tree_sha256(package)

    assert [row["path"] for row in files] == ["LogFile.py", "__init__.py"]
    assert digest == package_tree_sha256(package)[0]
    (package / "LogFile.py").write_text("# changed\n", encoding="utf-8")
    assert package_tree_sha256(package)[0] != digest


def test_toolchain_verifies_against_the_lock_and_reports_drift(tmp_path: Path) -> None:
    env_root, driver = fake_environment(tmp_path)
    lock_path = write_lock(tmp_path, env_root, driver)

    toolchain = LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=lock_path)
    verification = toolchain.verify()

    assert verification["status"] == "verified"
    assert verification["problems"] == []
    assert verification["python_version"] == "3.13.5"
    described = toolchain.describe(verification)
    assert described["name"] == "dfir_ntfs" and described["version"] == "9.9.9"
    assert described["lock_sha256"] == toolchain.lock_sha256
    assert logfile_runtime_availability(toolchain)["available"] is True

    (logfile_runtime._package_dir(env_root) / "LogFile.py").write_text("# drift\n", encoding="utf-8")
    drifted = toolchain.verify()
    assert drifted["status"] == "mismatch"
    assert "package_tree_sha256_mismatch" in drifted["problems"]
    availability = logfile_runtime_availability(toolchain)
    assert availability["available"] is False
    assert availability["reason"] == "dfir_ntfs_environment_mismatch"
    assert "package_tree_sha256_mismatch" in availability["detail"]
    with pytest.raises(LogFileRuntimeError, match="does not match its lock"):
        run_logfile_driver(tmp_path / "missing", output_path=tmp_path / "out.json", toolchain=toolchain)


def test_missing_lock_or_environment_is_reported_not_raised_by_availability(tmp_path: Path) -> None:
    with pytest.raises(LogFileRuntimeError, match="lock is missing"):
        LogFileToolchain.load(env_root=tmp_path, lock_path=tmp_path / "absent.json")
    env_root, driver = fake_environment(tmp_path)
    lock_path = write_lock(tmp_path, env_root, driver)
    toolchain = LogFileToolchain.load(env_root=tmp_path / "nowhere", driver_path=driver, lock_path=lock_path)
    verification = toolchain.verify()
    assert verification["status"] == "mismatch"
    expected = {"environment_python_missing", "package_missing"} | ({"console_script_missing"} if os.name != "nt" else set())
    assert expected <= set(verification["problems"])


def test_driver_run_returns_the_document_with_a_runtime_block(tmp_path: Path) -> None:
    env_root, driver = fake_environment(tmp_path)
    lock_path = write_lock(tmp_path, env_root, driver)
    toolchain = LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=lock_path)
    logfile = tmp_path / "$LogFile"
    logfile.write_bytes(b"\xff" * 16)

    document = run_logfile_driver(logfile, output_path=tmp_path / "records.json", toolchain=toolchain, timeout_seconds=60)

    assert document["schema_version"] == "fmb_logfile_records.v2"
    assert document["selection"]["operations"] == list(logfile_runtime.DEFAULT_OPERATIONS)
    runtime = document["runtime"]
    assert str(driver) in runtime["command_line"]
    assert runtime["tool_identity"]["verification"]["status"] == "verified"
    assert runtime["tool_identity"]["driver"]["sha256"]
    assert json.loads(runtime["stdout_excerpt"]) == {"ok": True}


def test_failing_or_absent_driver_raises(tmp_path: Path) -> None:
    env_root, driver = fake_environment(tmp_path, driver_body="import sys\nsys.stderr.write('boom')\nsys.exit(3)\n")
    lock_path = write_lock(tmp_path, env_root, driver)
    toolchain = LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=lock_path)
    logfile = tmp_path / "$LogFile"
    logfile.write_bytes(b"\xff" * 16)

    with pytest.raises(LogFileRuntimeError, match="exit 3: boom"):
        run_logfile_driver(logfile, output_path=tmp_path / "records.json", toolchain=toolchain, timeout_seconds=60)
    with pytest.raises(LogFileRuntimeError, match="missing"):
        run_logfile_driver(tmp_path / "absent", output_path=tmp_path / "records.json", toolchain=toolchain, timeout_seconds=60)


def test_shipped_lock_describes_the_pinned_release() -> None:
    lock = json.loads(logfile_runtime.DEFAULT_LOCK_PATH.read_text(encoding="utf-8"))

    assert lock["schema_version"] == "fmb_logfile_tool_lock.v1"
    assert lock["tool"] == "dfir_ntfs" and lock["license"] == "GPL-3.0"
    assert lock["version"] == "1.1.20"
    assert lock["commit_id"] == "ec3ae0884048ade106c91a68dab7c9fb3af393bf"
    assert lock["package_tree_hash_recipe"] == "sorted_relative_path_tab_sha256_lines.v1"
    assert len(lock["package_tree_sha256"]) == 64
    assert {row["path"] for row in lock["package_files"]} >= {"LogFile.py", "MFT.py", "USN.py"}
    assert lock["driver"]["path"] == "tools/dfir_ntfs/fmb_logfile_records.py"
    assert logfile_runtime.DEFAULT_DRIVER_PATH.is_file()
    assert "GPL-3.0-or-later" in logfile_runtime.DEFAULT_DRIVER_PATH.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="Windows console scripts are .exe launchers, not shebang files")
def test_portable_console_pin_allows_only_bound_interpreter_relocation(tmp_path: Path) -> None:
    import shutil
    first, driver = fake_environment(tmp_path / 'first')
    console = first / 'bin/ntfs_parser'
    body = b'print("pinned script")\n'
    console.write_bytes(b'#!' + str(first / 'bin/python').encode() + b'\n' + body)
    lock_path = write_lock(tmp_path, first, driver)
    second = tmp_path / 'relocated/venv'
    shutil.copytree(first, second, symlinks=True)
    moved_console = second / 'bin/ntfs_parser'
    moved_console.write_bytes(b'#!' + str(second / 'bin/python').encode() + b'\n' + body)
    moved = LogFileToolchain.load(env_root=second, driver_path=driver, lock_path=lock_path)
    checked = moved.verify()
    assert checked['status'] == 'verified'
    assert checked['console_script_hash_recipe'] == logfile_runtime.CONSOLE_HASH_RECIPE
    assert checked['console_script_sha256'] != moved.lock['console_script_sha256']
    moved_console.write_bytes(b'#!' + str(first / 'bin/python').encode() + b'\n' + body)
    assert 'console_script_portable_sha256_mismatch' in moved.verify()['problems']
    moved_console.write_bytes(b'#!' + str(second / 'bin/python').encode() + b' -I\n' + body)
    assert moved.verify()['status'] == 'mismatch'
    moved_console.write_bytes(b'#!' + str(second / 'bin/python').encode() + b'\n' + body + b'# changed\n')
    assert moved.verify()['status'] == 'mismatch'


@pytest.mark.skipif(os.name == "nt", reason="Windows console scripts are .exe launchers, not shebang files")
def test_legacy_console_lock_keeps_exact_byte_requirement(tmp_path: Path) -> None:
    env_root, driver = fake_environment(tmp_path)
    lock_path = write_lock(tmp_path, env_root, driver)
    locked = json.loads(lock_path.read_text())
    assert 'console_script_hash_recipe' not in locked
    console = env_root / 'bin/ntfs_parser'
    console.write_text('#!/different/python\n')
    checked = LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=lock_path).verify()
    assert 'console_script_sha256_mismatch' in checked['problems']


TIMED_DRIVER = '''import argparse, hashlib, json, os, random
parser = argparse.ArgumentParser()
parser.add_argument("--logfile"); parser.add_argument("--output"); parser.add_argument("--ops")
parser.add_argument("--max-records", type=int); parser.add_argument("--usn-pages", action="store_true")
args = parser.parse_args()
data = open(args.logfile, "rb").read()
duration = random.random()
document = {
    "schema_version": "fmb_logfile_records.v2",
    "driver": {"name": "fake"},
    "tool": {"name": "dfir_ntfs", "module_file": "/locked/LogFile.py"},
    "logfile": {"path": os.path.abspath(args.logfile), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
    "selection": {"operations": [name for name in args.ops.split(",") if name.strip()], "usn_pages": args.usn_pages,
                  "max_records": args.max_records, "recover_log_data": True},
    "parse": {"record_count": len(data), "parse_error_count": 0, "duration_seconds": duration},
    "operation_counts": {}, "embedded_usn": {"record_count": 0}, "restart_areas": [], "lifecycle_records": [],
    "records": [{"lsn": index, "byte": byte} for index, byte in enumerate(data)],
}
json.dump(document, open(args.output, "w"))
print(json.dumps({"record_count": len(data), "duration_seconds": duration}))
'''


def timed_toolchain(tmp_path: Path) -> LogFileToolchain:
    env_root, driver = fake_environment(tmp_path, driver_body=TIMED_DRIVER)
    return LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=write_lock(tmp_path, env_root, driver))


def without_timing(document: dict) -> dict:
    parse = {key: value for key, value in document["parse"].items() if key != "duration_seconds"}
    runtime = {key: value for key, value in document["runtime"].items() if key != "stdout_excerpt"}
    return {**document, "parse": parse, "runtime": runtime}


def test_relocated_document_is_a_fresh_run_for_the_new_output_but_for_its_timing(tmp_path: Path) -> None:
    toolchain = timed_toolchain(tmp_path)
    logfile, copy = tmp_path / "kape" / "$LogFile", tmp_path / "copy" / "$LogFile"
    for path in (logfile, copy):
        path.parent.mkdir()
        path.write_bytes(b"\x01\x02\x03")
    first, second = tmp_path / "first" / "records.json", tmp_path / "second" / "records.json"

    parsed = run_logfile_driver(logfile, output_path=first, toolchain=toolchain, timeout_seconds=60)
    fresh = run_logfile_driver(copy, output_path=second, toolchain=toolchain, timeout_seconds=60)
    relocated = logfile_runtime.relocated_logfile_document(
        parsed, copy, output_path=second, toolchain=toolchain, timeout_seconds=60)

    assert without_timing(relocated) == without_timing(fresh)
    assert list(relocated) == list(fresh) and list(relocated["logfile"]) == list(fresh["logfile"])
    assert relocated["parse"] == parsed["parse"]
    assert relocated["runtime"]["stdout_excerpt"] == parsed["runtime"]["stdout_excerpt"]
    assert str(second) in relocated["runtime"]["command_line"]
    assert relocated["logfile"]["path"] == str(copy) and parsed["logfile"]["path"] == str(logfile)


def test_relocation_refuses_another_logfile_selection_or_schema(tmp_path: Path) -> None:
    toolchain = timed_toolchain(tmp_path)
    logfile = tmp_path / "$LogFile"
    logfile.write_bytes(b"\x01\x02\x03")
    parsed = run_logfile_driver(logfile, output_path=tmp_path / "first.json", toolchain=toolchain, timeout_seconds=60)

    def relocate(document: dict, **options: object) -> dict | None:
        return logfile_runtime.relocated_logfile_document(
            document, logfile, output_path=tmp_path / "second.json", toolchain=toolchain, timeout_seconds=60, **options)

    assert relocate(parsed) is not None
    assert relocate(parsed, operations=("UpdateResidentValue",)) is None
    assert relocate(parsed, max_records=10) is None
    assert relocate({**parsed, "schema_version": "fmb_logfile_records.v1"}) is None
    logfile.write_bytes(b"\x01\x02\x04")
    assert relocate(parsed) is None


def test_adapter_parses_one_logfile_once_for_two_output_folders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from functools import partial

    from fmb.index.adapters import logfile as logfile_adapters

    toolchain = timed_toolchain(tmp_path)
    runs: list[Path] = []

    def counted_run(path: Path, *, output_path: Path, operations: tuple[str, ...]) -> dict:
        runs.append(output_path)
        return run_logfile_driver(path, output_path=output_path, operations=operations, toolchain=toolchain,
                                  timeout_seconds=60)

    monkeypatch.setattr(logfile_adapters, "run_logfile_driver", counted_run)
    monkeypatch.setattr(logfile_adapters, "relocated_logfile_document", partial(
        logfile_runtime.relocated_logfile_document, toolchain=toolchain, timeout_seconds=60))
    monkeypatch.setattr(logfile_adapters, "_PARSED_LOGFILE_DOCUMENTS", {})
    logfile = tmp_path / "kape" / "targets" / "C" / "$LogFile"
    logfile.parent.mkdir(parents=True)
    logfile.write_bytes(b"\x05\x06")

    first = logfile_adapters._logfile_driver_document(logfile, normalized_output_dir=tmp_path / "normalized")
    again = logfile_adapters._logfile_driver_document(logfile, normalized_output_dir=tmp_path / "normalized")
    second = logfile_adapters._logfile_driver_document(logfile, normalized_output_dir=tmp_path / "supplement")
    logfile.write_bytes(b"\x05\x07")
    changed = logfile_adapters._logfile_driver_document(logfile, normalized_output_dir=tmp_path / "other")

    assert len(runs) == 2 and runs[0].parent == tmp_path / "normalized" and runs[1].parent == tmp_path / "other"
    assert again == first and second["parse"] == first["parse"] and second["records"] == first["records"]
    assert str(tmp_path / "supplement") in second["runtime"]["command_line"]
    written = sorted((tmp_path / "supplement").glob("*" + logfile_adapters.LOGFILE_DRIVER_DOCUMENT_SUFFIX))
    assert [json.loads(path.read_text(encoding="utf-8")) for path in written] == [second]
    assert changed["records"] != first["records"]


def test_a_relocated_document_is_read_as_a_driver_run_reads_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from functools import partial

    from fmb.index.adapters import logfile as logfile_adapters
    from fmb.pipeline import reads

    toolchain = timed_toolchain(tmp_path)
    monkeypatch.setattr(logfile_adapters, "run_logfile_driver", partial(
        run_logfile_driver, toolchain=toolchain, timeout_seconds=60))
    relocate = partial(logfile_runtime.relocated_logfile_document, toolchain=toolchain, timeout_seconds=60)

    root = tmp_path / "case"

    def files_read(relocation) -> set[str]:
        # A pipeline step records every file it reads, so a relocation must read what a run reads.
        monkeypatch.setattr(logfile_adapters, "relocated_logfile_document", relocation)
        monkeypatch.setattr(logfile_adapters, "_PARSED_LOGFILE_DOCUMENTS", {})
        shutil.rmtree(root, ignore_errors=True)
        logfile = root / "kape" / "$LogFile"
        logfile.parent.mkdir(parents=True)
        logfile.write_bytes(b"\x05\x06")
        with reads.measured() as opened:
            for folder in ("normalized", "supplement"):
                logfile_adapters._logfile_driver_document(logfile, normalized_output_dir=root / folder)
        return opened

    parsed_twice = files_read(lambda *args, **options: None)
    relocated = files_read(relocate)

    assert relocated == parsed_twice
    assert any(path.startswith(str(root / "supplement")) for path in relocated)
