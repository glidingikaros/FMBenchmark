#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fmb.core.hashing import sha256_file
from fmb.index.scanners import logfile_runtime as runtime

UV_ENV = "FMB_UV"
DEFAULT_REPORT_PATH = Path("~/.cache/fmb/dfir-ntfs/bootstrap-report.json")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VENV_TIMEOUT_SECONDS = 600
INSTALL_TIMEOUT_SECONDS = 900
DRIVER_TIMEOUT_SECONDS = 120

Runner = Callable[..., subprocess.CompletedProcess]


class BootstrapError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_lock(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BootstrapError(f"dfir_ntfs lock is missing: {path}")
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != runtime.LOCK_SCHEMA_VERSION:
        raise BootstrapError(f"unsupported dfir_ntfs lock schema in {path}")
    return lock


def install_requirement(lock: dict[str, Any]) -> str:
    commit = str(lock.get("commit_id") or "").lower()
    if not COMMIT_PATTERN.match(commit):
        raise BootstrapError("the lock has no full commit id for dfir_ntfs")
    source = str(lock.get("source") or "")
    if not source.startswith("https://"):
        raise BootstrapError("the lock has no https source for dfir_ntfs")
    return f"{lock.get('tool', runtime.PACKAGE_NAME)} @ git+{source}@{commit}"


def venv_command(uv: str, lock: dict[str, Any], env_root: Path, *, clear: bool = False) -> list[str]:
    version = str(lock.get("python_version") or "")
    if not version:
        raise BootstrapError("the lock records no python_version for the environment")
    argv = [uv, "venv"]
    if clear:
        argv.append("--clear")
    argv += ["--python", version, str(env_root)]
    return argv


def install_command(uv: str, lock: dict[str, Any], env_root: Path) -> list[str]:
    return [
        uv,
        "pip",
        "install",
        "--no-cache",
        "--python",
        str(runtime.environment_python(env_root)),
        "--no-deps",
        install_requirement(lock),
    ]


def install_environment(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    env = dict(environ)
    count = int(env.get("GIT_CONFIG_COUNT") or 0)
    for offset, (key, value) in enumerate((("core.autocrlf", "false"), ("core.eol", "lf"))):
        env[f"GIT_CONFIG_KEY_{count + offset}"], env[f"GIT_CONFIG_VALUE_{count + offset}"] = key, value
    env["GIT_CONFIG_COUNT"] = str(count + 2)
    return env


def driver_install_command(python: str, env_root: Path) -> list[str]:
    return [python, "-m", "fmb.index.scanners.logfile_runtime", "--env-root", str(env_root), "--install-driver"]


def driver_install_environment(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    env = dict(environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT / "src") + (os.pathsep + existing if existing else "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_step(
    run: Runner,
    argv: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess:
    try:
        completed = run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(env) if env is not None else None,
        )
    except subprocess.TimeoutExpired as error:
        raise BootstrapError(f"timed out after {timeout:.0f} s: {' '.join(argv)}") from error
    except OSError as error:
        raise BootstrapError(f"cannot run {argv[0]}: {error}") from error
    if completed.returncode != 0:
        excerpt = ((completed.stderr or "") + (completed.stdout or "")).strip()[-2000:]
        raise BootstrapError(f"exit {completed.returncode}: {' '.join(argv)}\n{excerpt}")
    return completed


def verify(env_root: Path, lock_path: Path) -> dict[str, Any]:
    toolchain = runtime.LogFileToolchain.load(env_root=env_root, lock_path=lock_path)
    verification = toolchain.verify()
    return {
        "status": verification["status"],
        "problems": list(verification["problems"]),
        "verified": verification["status"] == "verified",
        "env_root": str(toolchain.env_root),
        "lock_path": str(toolchain.lock_path),
        "lock_sha256": toolchain.lock_sha256,
        "verification": verification,
        "tool_identity": toolchain.describe(verification),
        "availability": runtime.logfile_runtime_availability(toolchain),
    }


def format_verification(report: dict[str, Any]) -> str:
    verification = report["verification"]
    lines = [
        f"environment: {report['env_root']}",
        f"lock: {report['lock_path']} (sha256 {report['lock_sha256']})",
        f"  package dir: {verification.get('package_dir')}",
        f"  package tree sha256: {verification.get('package_tree_sha256')} (expected {verification.get('expected_package_tree_sha256')})",
        f"  console script sha256: {verification.get('console_script_sha256')}",
        f"  python version: {verification.get('python_version')}",
        f"  driver: {verification.get('driver_path')} [{verification.get('driver_source')}]",
        f"  driver sha256: {verification.get('driver_sha256')} (expected {verification.get('expected_driver_sha256')})",
    ]
    if report["verified"]:
        lines.append("result: verified")
    else:
        lines.append("result: mismatch (" + ", ".join(report["problems"]) + ")")
    return "\n".join(lines)


def rebuild(
    args: argparse.Namespace,
    *,
    run: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    environ: Mapping[str, str] = os.environ,
    python: str = sys.executable,
) -> dict[str, Any]:
    uv = args.uv or environ.get(UV_ENV) or which("uv")
    if not uv or (os.sep in uv and not Path(uv).is_file()) or (os.sep not in uv and not which(uv)):
        raise BootstrapError("uv is required to create the dfir_ntfs environment; install uv, then rerun")
    lock_path = args.lock.expanduser().resolve()
    if lock_path != runtime.DEFAULT_LOCK_PATH.resolve():
        raise BootstrapError("rebuild uses the runtime's packaged lock; custom locks are verify-only")
    lock = load_lock(lock_path)
    env_root = (args.env_root or runtime.default_env_root()).expanduser()
    exists = env_root.exists()
    if exists and not args.recreate and not args.dry_run:
        raise BootstrapError(f"environment already exists: {env_root} (pass --recreate to rebuild it, or --verify-only)")
    commands = [
        venv_command(uv, lock, env_root, clear=exists),
        install_command(uv, lock, env_root),
        driver_install_command(python, env_root),
    ]
    report: dict[str, Any] = {
        "schema_version": "fmb_dfir_ntfs_bootstrap_report.v1",
        "started_at": utc_now(),
        "env_root": str(env_root),
        "lock_path": str(lock_path),
        "lock_sha256": sha256_file(lock_path),
        "requirement": install_requirement(lock),
        "commands": commands,
    }
    if args.dry_run:
        report["dry_run"] = True
        return report
    run_step(run, commands[0], timeout=VENV_TIMEOUT_SECONDS)
    run_step(run, commands[1], timeout=INSTALL_TIMEOUT_SECONDS, env=install_environment(environ))
    installed = run_step(run, commands[2], timeout=DRIVER_TIMEOUT_SECONDS, env=driver_install_environment(environ))
    report["driver_install_output"] = (installed.stdout or "").strip()
    verification = verify(env_root, lock_path)
    report.update({"verification": verification, "verified": verification["verified"], "finished_at": utc_now()})
    report_path = args.report.expanduser()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["report_path"] = str(report_path)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="rebuild or verify the locked dfir_ntfs environment")
    parser.add_argument("--verify-only", action="store_true", help="verify an existing environment and exit")
    parser.add_argument("--env-root", type=Path, default=None, help="environment root (default: FMB_DFIR_NTFS_ENV or ~/.cache/fmb/dfir-ntfs/venv)")
    parser.add_argument("--lock", type=Path, default=runtime.DEFAULT_LOCK_PATH)
    parser.add_argument("--uv", default=None, help="uv executable (default: FMB_UV, then PATH)")
    parser.add_argument("--recreate", action="store_true", help="replace an existing environment")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--dry-run", action="store_true", help="print the commands without running them")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    run: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    environ: Mapping[str, str] = os.environ,
    python: str = sys.executable,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.verify_only:
            env_root = (args.env_root or runtime.default_env_root()).expanduser()
            report = verify(env_root, args.lock.expanduser().resolve())
            print(format_verification(report))
            if args.json:
                print(json.dumps(report, indent=2))
            return 0 if report["verified"] else 1
        report = rebuild(args, run=run, which=which, environ=environ, python=python)
        if report.get("dry_run"):
            print("rebuild plan (dry run):")
            for command in report["commands"]:
                print("  " + " ".join(command))
            if args.json:
                print(json.dumps(report, indent=2))
            return 0
        print(format_verification(report["verification"]))
        print(f"report: {report['report_path']}")
        if args.json:
            print(json.dumps(report, indent=2))
        return 0 if report["verified"] else 1
    except (BootstrapError, runtime.LogFileRuntimeError, OSError, ValueError) as error:
        print(f"bootstrap_dfir_ntfs: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
