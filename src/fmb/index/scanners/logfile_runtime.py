from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from fmb.core.env_lookup import read_env_value
from fmb.core.hashing import sha256_file
from fmb.core.processes import (
    command_line_text,
    process_output_excerpt,
    timeout_seconds_from_env,
)

LOCK_SCHEMA_VERSION = "fmb_logfile_tool_lock.v1"
RECORDS_SCHEMA_VERSION = "fmb_logfile_records.v2"
PACKAGE_TREE_HASH_RECIPE = "sorted_relative_path_tab_sha256_lines.v1"
CONSOLE_HASH_RECIPE = "bound_venv_shebang_sha256.v1"
DEFAULT_LOCK_PATH = Path(__file__).resolve().parent / "dfir-ntfs-lock.json"
DEFAULT_ENV_ROOT = Path("~/.cache/fmb/dfir-ntfs/venv")
DEFAULT_DRIVER_PATH = (
    Path(__file__).resolve().parents[4] / "tools" / "dfir_ntfs" / "fmb_logfile_records.py"
)
ENV_ROOT_ENV = "FMB_DFIR_NTFS_ENV"
DRIVER_PATH_ENV = "FMB_DFIR_NTFS_DRIVER"
INSTALLED_DRIVER_NAME = "fmb-logfile-records"
TIMEOUT_ENV = "FMB_DFIR_NTFS_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT_SECONDS = 3600
DEFAULT_OPERATIONS = (
    "UpdateResidentValue",
    "InitializeFileRecordSegment",
    "DeallocateFileRecordSegment",
)
PACKAGE_NAME = "dfir_ntfs"


class LogFileRuntimeError(RuntimeError):
    pass


def package_tree_sha256(package_dir: Path) -> tuple[str, list[dict[str, Any]]]:
    files: list[dict[str, Any]] = []
    for path in sorted(package_dir.rglob("*"), key=lambda item: item.relative_to(package_dir).parts):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        files.append(
            {
                "path": path.relative_to(package_dir).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    text = "".join(f"{row['path']}\t{row['sha256']}\n" for row in files)
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), files


def _venv_python_version(env_root: Path) -> str | None:
    config = env_root / "pyvenv.cfg"
    if not config.is_file():
        return None
    version = None
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        key, _sep, value = line.partition("=")
        if key.strip() == "version_info":
            return value.strip()
        if key.strip() == "version":
            version = value.strip()
    return version


def portable_console_sha256(console: Path, python: Path) -> str | None:
    try:
        data = console.read_bytes()
        first, separator, body = data.partition(b"\n")
        if not separator:
            return None
        if first == b"#!/bin/sh":
            launch, separator, rest = body.partition(b"\n")
            close, separator_two, body = rest.partition(b"\n")
            wrapped = re.fullmatch(rb"'''exec' '(.+)' \"\$0\" \"\$@\"", launch)
            if not separator or not separator_two or close != b"' '''" or wrapped is None:
                return None
            interpreter = Path(wrapped.group(1).decode("utf-8"))
        elif first.startswith(b"#!/"):
            interpreter = Path(first[2:].decode("utf-8"))
        else:
            return None
        expected = python.expanduser().absolute()
        if interpreter.name != expected.name or interpreter.parent.resolve() != expected.parent.resolve():
            return None
        return hashlib.sha256(b"#!<locked-environment>/bin/python\n" + body).hexdigest()
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def scripts_dir(env_root: Path) -> Path:
    return env_root / ("Scripts" if os.name == "nt" else "bin")


def environment_python(env_root: Path) -> Path:
    return scripts_dir(env_root) / ("python.exe" if os.name == "nt" else "python")


def _package_dir(env_root: Path) -> Path | None:
    layout = "Lib/site-packages" if os.name == "nt" else "lib/python3.*/site-packages"
    candidates = sorted(env_root.glob(f"{layout}/{PACKAGE_NAME}"))
    if len(candidates) != 1 or not candidates[0].is_dir():
        return None
    return candidates[0]


def default_env_root() -> Path:
    value, _source = read_env_value(ENV_ROOT_ENV, environ=os.environ)
    return Path(value).expanduser() if value else DEFAULT_ENV_ROOT.expanduser()


def installed_driver_path(env_root: Path) -> Path:
    return scripts_dir(env_root) / INSTALLED_DRIVER_NAME


def resolve_driver_path(env_root: Path, explicit: Path | None = None) -> tuple[Path, str]:
    if explicit is not None:
        return explicit.expanduser(), "explicit"
    value, _source = read_env_value(DRIVER_PATH_ENV, environ=os.environ)
    if value:
        return Path(value).expanduser(), "environment_override"
    installed = installed_driver_path(env_root)
    if installed.is_file():
        return installed, "installed_in_environment"
    return DEFAULT_DRIVER_PATH, "repository_checkout"


@dataclass(frozen=True)
class LogFileToolchain:
    env_root: Path
    python: Path
    package_dir: Path | None
    driver_path: Path
    lock: dict[str, Any]
    lock_path: Path
    lock_sha256: str
    driver_source: str = "repository_checkout"

    @classmethod
    def load(
        cls,
        *,
        env_root: Path | None = None,
        driver_path: Path | None = None,
        lock_path: Path | None = None,
    ) -> LogFileToolchain:
        lock_file = (lock_path or DEFAULT_LOCK_PATH).expanduser().resolve()
        if not lock_file.is_file():
            raise LogFileRuntimeError(f"dfir_ntfs lock is missing: {lock_file}")
        lock = json.loads(lock_file.read_text(encoding="utf-8"))
        if lock.get("schema_version") != LOCK_SCHEMA_VERSION:
            raise LogFileRuntimeError("unsupported dfir_ntfs lock schema")
        root = (env_root or default_env_root()).expanduser()
        resolved_driver, driver_source = resolve_driver_path(root, driver_path)
        return cls(
            env_root=root,
            python=environment_python(root),
            package_dir=_package_dir(root),
            driver_path=resolved_driver,
            lock=lock,
            lock_path=lock_file,
            lock_sha256=sha256_file(lock_file),
            driver_source=driver_source,
        )

    def verify(self) -> dict[str, Any]:
        problems: list[str] = []
        actual_tree: str | None = None
        actual_console: str | None = None
        portable_console: str | None = None
        if not self.python.is_file():
            problems.append("environment_python_missing")
        if self.package_dir is None:
            problems.append("package_missing")
        else:
            actual_tree, _files = package_tree_sha256(self.package_dir)
            if actual_tree != self.lock.get("package_tree_sha256"):
                problems.append("package_tree_sha256_mismatch")
        console = self.env_root / str(self.lock.get("console_script", "bin/ntfs_parser"))
        if os.name == "nt":
            pass
        elif console.is_file():
            actual_console = sha256_file(console)
            recipe = self.lock.get("console_script_hash_recipe")
            if recipe == CONSOLE_HASH_RECIPE:
                portable_console = portable_console_sha256(console, self.python)
                if portable_console is None or portable_console != self.lock.get("console_script_portable_sha256"):
                    problems.append("console_script_portable_sha256_mismatch")
            elif recipe is not None:
                problems.append("console_script_hash_recipe_unsupported")
            elif actual_console != self.lock.get("console_script_sha256"):
                problems.append("console_script_sha256_mismatch")
        else:
            problems.append("console_script_missing")
        python_version = _venv_python_version(self.env_root)
        expected_python = self.lock.get("python_version")
        if expected_python and python_version != expected_python:
            problems.append("python_version_mismatch")
        driver_sha256 = sha256_file(self.driver_path) if self.driver_path.is_file() else None
        expected_driver = (self.lock.get("driver") or {}).get("sha256")
        if driver_sha256 is None:
            problems.append("driver_missing")
        elif expected_driver and driver_sha256 != expected_driver:
            problems.append("driver_sha256_mismatch")
        elif not expected_driver:
            problems.append("driver_identity_unlocked")
        return {
            "status": "verified" if not problems else "mismatch",
            "problems": problems,
            "env_root": str(self.env_root),
            "package_dir": str(self.package_dir) if self.package_dir else None,
            "package_tree_sha256": actual_tree,
            "expected_package_tree_sha256": self.lock.get("package_tree_sha256"),
            "console_script_sha256": actual_console,
            "console_script_hash_recipe": self.lock.get("console_script_hash_recipe", "raw_sha256"),
            "console_script_portable_sha256": portable_console,
            "python_version": python_version,
            "driver_path": str(self.driver_path),
            "driver_source": self.driver_source,
            "driver_sha256": driver_sha256,
            "expected_driver_sha256": expected_driver,
        }

    def describe(self, verification: dict[str, Any] | None = None) -> dict[str, Any]:
        verification = verification or self.verify()
        return {
            "name": self.lock.get("tool", PACKAGE_NAME),
            "version": self.lock.get("version"),
            "source": self.lock.get("source"),
            "commit_id": self.lock.get("commit_id"),
            "license": self.lock.get("license"),
            "boundary": "subprocess in a separate environment; no GPL-3 code imported into fmb",
            "lock_path": str(self.lock_path),
            "lock_sha256": self.lock_sha256,
            "package_tree_hash_recipe": self.lock.get("package_tree_hash_recipe"),
            "verification": verification,
            "driver": {
                "path": str(self.driver_path),
                "source": verification.get("driver_source"),
                "sha256": verification.get("driver_sha256"),
                "expected_sha256": verification.get("expected_driver_sha256"),
                "license": "GPL-3.0-or-later",
            },
        }

    def install_driver(self, source: Path | None = None) -> Path:
        source_path = (source or DEFAULT_DRIVER_PATH).expanduser()
        if not source_path.is_file():
            raise LogFileRuntimeError(f"driver source is missing: {source_path}")
        expected = (self.lock.get("driver") or {}).get("sha256")
        actual = sha256_file(source_path)
        if not expected or actual != expected:
            raise LogFileRuntimeError("driver source does not match the locked driver hash")
        target = installed_driver_path(self.env_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_path.read_bytes())
        target.chmod(0o755)
        return target


def build_lock_document(
    *,
    env_root: Path,
    version: str,
    commit_id: str,
    generated_at: str,
    driver_path: Path = DEFAULT_DRIVER_PATH,
) -> dict[str, Any]:
    package_dir = _package_dir(env_root)
    if package_dir is None:
        raise LogFileRuntimeError(f"dfir_ntfs package not found under {env_root}")
    tree_sha256, files = package_tree_sha256(package_dir)
    console = env_root / "bin" / "ntfs_parser"
    portable_console = portable_console_sha256(console, environment_python(env_root)) if console.is_file() else None
    return {
        "schema_version": LOCK_SCHEMA_VERSION,
        "purpose": (
            "Phase C $LogFile witness. dfir_ntfs is GPL-3 and stays outside the fmb "
            "package: it is invoked as a subprocess in this locked environment through "
            "the GPL-3 driver tools/dfir_ntfs/fmb_logfile_records.py; fmb consumes only "
            "the JSON the driver writes."
        ),
        "generated_at": generated_at,
        "tool": PACKAGE_NAME,
        "version": version,
        "source": "https://github.com/msuhanov/dfir_ntfs",
        "vcs": "git",
        "commit_id": commit_id,
        "license": "GPL-3.0",
        "environment_root_default": str(DEFAULT_ENV_ROOT),
        "environment_root_env": ENV_ROOT_ENV,
        "python_version": _venv_python_version(env_root),
        "package_relative_dir": package_dir.relative_to(env_root).as_posix(),
        "package_tree_hash_recipe": PACKAGE_TREE_HASH_RECIPE,
        "package_tree_sha256": tree_sha256,
        "package_files": files,
        "console_script": "bin/ntfs_parser",
        "console_script_sha256": sha256_file(console) if console.is_file() else None,
        **({"console_script_hash_recipe": CONSOLE_HASH_RECIPE,
            "console_script_portable_sha256": portable_console} if portable_console else {}),
        "driver": {
            "path": "tools/dfir_ntfs/fmb_logfile_records.py",
            "installed_name": INSTALLED_DRIVER_NAME,
            "sha256": sha256_file(driver_path) if driver_path.is_file() else None,
            "size_bytes": driver_path.stat().st_size if driver_path.is_file() else None,
            "license": "GPL-3.0-or-later",
            "records_schema_version": RECORDS_SCHEMA_VERSION,
            "note": (
                "the resolved driver must hash to this value (checkout copy, installed "
                "copy or an explicit override alike); installed distributions install the "
                "companion into the parser environment with --install-driver"
            ),
        },
        "boundary": (
            "subprocess only; no GPL-3 code imported into the fmb package; the fmb "
            "adapter consumes structured JSON emitted by the driver run in this environment"
        ),
    }


def run_logfile_driver(
    logfile_path: Path,
    *,
    output_path: Path,
    toolchain: LogFileToolchain | None = None,
    operations: tuple[str, ...] = DEFAULT_OPERATIONS,
    max_records: int = 500_000,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    toolchain = toolchain or LogFileToolchain.load()
    verification = toolchain.verify()
    if verification["status"] != "verified":
        raise LogFileRuntimeError(
            "dfir_ntfs environment does not match its lock: "
            + ", ".join(verification["problems"])
        )
    if not logfile_path.is_file():
        raise LogFileRuntimeError(f"raw $LogFile is missing: {logfile_path}")
    timeout = (
        float(timeout_seconds)
        if timeout_seconds is not None
        else timeout_seconds_from_env(TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS)
    )
    command = [
        str(toolchain.python),
        str(toolchain.driver_path),
        "--logfile",
        str(logfile_path),
        "--output",
        str(output_path),
        "--ops",
        ",".join(operations),
        "--max-records",
        str(int(max_records)),
    ]
    kept = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
    if os.name == "nt":
        kept |= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "PYTHONUTF8", "COMSPEC", "PATHEXT"}
    environment = {key: value for key, value in os.environ.items() if key in kept}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise LogFileRuntimeError(
            f"dfir_ntfs driver exceeded {timeout:.0f} s: "
            + process_output_excerpt(error.stdout, error.stderr)
        ) from error
    if completed.returncode != 0:
        raise LogFileRuntimeError(
            f"dfir_ntfs driver failed with exit {completed.returncode}: "
            + process_output_excerpt(completed.stdout, completed.stderr)
        )
    try:
        document = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise LogFileRuntimeError(f"dfir_ntfs driver wrote no readable document: {error}") from error
    if document.get("schema_version") != RECORDS_SCHEMA_VERSION:
        raise LogFileRuntimeError("dfir_ntfs driver document has an unexpected schema")
    document["runtime"] = {
        "command_line": command_line_text(command),
        "timeout_seconds": timeout,
        "stdout_excerpt": process_output_excerpt(completed.stdout, None),
        "tool_identity": toolchain.describe(verification),
    }
    return document


def logfile_runtime_availability(
    toolchain: LogFileToolchain | None = None,
) -> dict[str, Any]:
    try:
        toolchain = toolchain or LogFileToolchain.load()
    except LogFileRuntimeError as error:
        message = str(error)
        code = (
            "dfir_ntfs_lock_missing"
            if "lock is missing" in message
            else "dfir_ntfs_lock_unsupported"
            if "lock schema" in message
            else "dfir_ntfs_runtime_unavailable"
        )
        return {"available": False, "reason": code, "detail": message, "tool_identity": None}
    verification = toolchain.verify()
    return {
        "available": verification["status"] == "verified",
        "reason": None
        if verification["status"] == "verified"
        else "dfir_ntfs_environment_mismatch",
        "detail": None
        if verification["status"] == "verified"
        else ",".join(verification["problems"]),
        "tool_identity": toolchain.describe(verification),
    }


def _main(argv: list[str]) -> int:
    import argparse
    from datetime import datetime

    parser = argparse.ArgumentParser(description="dfir_ntfs $LogFile runtime helper")
    parser.add_argument("--env-root", type=Path, default=None)
    parser.add_argument("--describe", action="store_true", help="print the verification")
    parser.add_argument("--write-lock", type=Path, default=None, help="write a lock document")
    parser.add_argument("--version", default=None)
    parser.add_argument("--commit-id", default=None)
    parser.add_argument("--logfile", type=Path, default=None, help="run the driver on this copy")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--install-driver", action="store_true", help="copy the locked driver into the environment")
    parser.add_argument("--driver-source", type=Path, default=None, help="driver file to install (default: checkout copy)")
    args = parser.parse_args(argv)
    env_root = (args.env_root or default_env_root()).expanduser()
    if args.install_driver:
        toolchain = LogFileToolchain.load(env_root=env_root, driver_path=args.driver_source or DEFAULT_DRIVER_PATH)
        target = toolchain.install_driver(args.driver_source)
        print(json.dumps({"installed": str(target), "sha256": sha256_file(target)}))
        return 0
    if args.write_lock is not None:
        if not args.version or not args.commit_id:
            parser.error("--write-lock needs --version and --commit-id")
        document = build_lock_document(
            env_root=env_root,
            version=args.version,
            commit_id=args.commit_id,
            driver_path=(args.driver_source or DEFAULT_DRIVER_PATH).expanduser(),
            generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        )
        args.write_lock.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"lock": str(args.write_lock), "package_tree_sha256": document["package_tree_sha256"]}))
        return 0
    toolchain = LogFileToolchain.load(env_root=env_root)
    if args.describe:
        print(json.dumps(toolchain.describe(), indent=2))
        return 0
    if args.logfile is not None:
        output = args.output or Path(tempfile.mkdtemp(prefix="fmb-logfile-")) / "records.json"
        document = run_logfile_driver(args.logfile, output_path=output, toolchain=toolchain)
        print(json.dumps({"output": str(output), "parse": document["parse"], "embedded_usn": document["embedded_usn"]}, indent=2))
        return 0
    parser.error("nothing to do")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
