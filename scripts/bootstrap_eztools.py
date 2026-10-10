#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import io
import tarfile
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fmb.collection.tools.host.toolchain import (
    DEFAULT_LOCK_PATH,
    LOCK_SCHEMA_VERSION,
    STATUS_VERIFIED,
    HostToolchain,
    HostToolchainError,
    default_toolchain_root,
    list_dotnet_runtimes,
    resolve_dotnet,
    tree_sha256,
)
from fmb.core.hashing import sha256_file

DEFAULT_SOURCE_ROOT = Path("~/.cache/fmb/eztools-src")
DEFAULT_STAGE_ROOT = Path("~/.cache/fmb/eztools/plugins-stage")
DEFAULT_LOG_DIR = Path("~/.cache/fmb/eztools/logs/bootstrap")
DEFAULT_REPORT_PATH = Path("~/.cache/fmb/eztools/bootstrap-report.json")
TOOL_FRAMEWORK = "net9.0"
PLUGIN_FRAMEWORK = "netstandard2.0"
PLUGIN_PROJECT_GLOB = "RegistryPlugin.*/*.csproj"
PLUGIN_ASSEMBLY_PATTERN = re.compile(r"^RegistryPlugin\..+\.dll$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PUBLISH_ENVIRONMENT = {
    "MSBUILDDISABLENODEREUSE": "1",
    "DOTNET_CLI_USE_MSBUILD_SERVER": "0",
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_NOLOGO": "1",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
}
GIT_TIMEOUT_SECONDS = 120
CLONE_TIMEOUT_SECONDS = 1800
PUBLISH_TIMEOUT_SECONDS = 900

Runner = Callable[..., subprocess.CompletedProcess]


class BootstrapError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_step(
    run: Runner,
    argv: list[str],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    log: Path | None = None,
) -> subprocess.CompletedProcess:
    try:
        completed = run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
        )
    except subprocess.TimeoutExpired as error:
        raise BootstrapError(f"timed out after {timeout:.0f} s: {' '.join(argv)}") from error
    except OSError as error:
        raise BootstrapError(f"cannot run {argv[0]}: {error}") from error
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(
            f"$ {' '.join(argv)}\n\n[stdout]\n{completed.stdout or ''}\n[stderr]\n{completed.stderr or ''}\n",
            encoding="utf-8",
        )
    if completed.returncode != 0:
        excerpt = ((completed.stderr or "") + (completed.stdout or "")).strip()[-2000:]
        raise BootstrapError(f"exit {completed.returncode}: {' '.join(argv)}\n{excerpt}")
    return completed


def load_lock(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BootstrapError(f"host toolchain lock is missing: {path}")
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != LOCK_SCHEMA_VERSION:
        raise BootstrapError(f"unsupported host toolchain lock schema in {path}")
    return lock


def checkout_name(repository: Any) -> str:
    return str(repository).rstrip("/").rsplit("/", 1)[-1]


def pinned_sources(lock: dict[str, Any]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for row in lock.get("tools", []):
        source = row.get("source") or {}
        sources.append(
            {
                "name": str(row["tool"]),
                "kind": "tool",
                "repository": str(source["repository"]),
                "commit_sha": str(source["commit_sha"]).lower(),
                "commit_date": source.get("commit_date"),
                "checkout": checkout_name(source["repository"]),
                "project": str(source["project"]),
                "directory": str(row["directory"]),
                "entry_assembly": str(row["entry_assembly"]),
                "target_framework": str(source.get("target_framework") or TOOL_FRAMEWORK),
            }
        )
    plugins = lock.get("registry_plugins") or {}
    if plugins:
        sources.append(
            {
                "name": "RegistryPlugins",
                "kind": "registry_plugins",
                "repository": str(plugins["repository"]),
                "commit_sha": str(plugins["commit_sha"]).lower(),
                "commit_date": plugins.get("commit_date"),
                "checkout": checkout_name(plugins["repository"]),
                "directory": str(plugins["directory"]),
                "target_framework": str(plugins.get("target_framework") or PLUGIN_FRAMEWORK),
            }
        )
    for source in sources:
        if not COMMIT_PATTERN.match(source["commit_sha"]):
            raise BootstrapError(f"{source['name']} has no full commit sha in the lock")
    if not sources:
        raise BootstrapError("the lock pins no sources")
    return sources


def tool_publish_argv(dotnet: str, project: Path | str, output: Path | str, *, framework: str = TOOL_FRAMEWORK) -> list[str]:
    return [
        dotnet,
        "publish",
        str(project),
        "-c",
        "Release",
        "-f",
        framework,
        "-o",
        str(output),
        "--self-contained",
        "false",
        "-p:RollForward=Major",
        "-p:DebugType=None",
        "-p:PublishSingleFile=false",
        "-nodeReuse:false",
        "-p:UseSharedCompilation=false",
    ]


def plugin_publish_argv(dotnet: str, project: Path | str, output: Path | str, *, framework: str = PLUGIN_FRAMEWORK) -> list[str]:
    return [
        dotnet,
        "publish",
        str(project),
        "-c",
        "Release",
        "-f",
        framework,
        "-o",
        str(output),
        "-p:DebugType=None",
        "-nodeReuse:false",
        "-p:UseSharedCompilation=false",
    ]


def publish_environment(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    return {**environ, **PUBLISH_ENVIRONMENT}


def preflight_dotnet(
    lock: dict[str, Any],
    dotnet: str,
    run: Runner,
    *,
    allow_sdk_drift: bool = False,
    list_runtimes: Callable[[str], list[str] | None] | None = None,
) -> dict[str, Any]:
    sdk = run_step(run, [dotnet, "--version"], timeout=GIT_TIMEOUT_SECONDS).stdout.strip()
    expected_sdk = lock.get("dotnet_sdk")
    runtimes = (list_runtimes or list_dotnet_runtimes)(dotnet) or []
    expected_runtime = str(lock.get("dotnet_runtime") or "")
    runtime_present = any(
        line == expected_runtime or line.startswith(expected_runtime + " ") for line in runtimes
    )
    report = {
        "dotnet": dotnet,
        "sdk": sdk,
        "expected_sdk": expected_sdk,
        "sdk_matches": sdk == expected_sdk,
        "runtimes": runtimes,
        "expected_runtime": expected_runtime,
        "runtime_present": runtime_present,
    }
    if not runtime_present:
        raise BootstrapError(f"locked runtime {expected_runtime!r} is not installed for {dotnet}")
    if sdk != expected_sdk and not allow_sdk_drift:
        raise BootstrapError(
            f"dotnet SDK {sdk} differs from the locked {expected_sdk}; the published bytes would "
            "differ (pass --allow-sdk-drift to try anyway)"
        )
    return report


def checkout_pinned(
    source: dict[str, Any], source_root: Path, run: Runner, git: str, *, log_dir: Path | None = None
) -> dict[str, Any]:
    directory = source_root / source["checkout"]
    sha = source["commit_sha"]
    cloned = False
    if not (directory / ".git").exists():
        directory.parent.mkdir(parents=True, exist_ok=True)
        if directory.exists():
            raise BootstrapError("refusing to remove an existing non-repository source directory")
        first = run(
            [git, "clone", "--quiet", "--filter=blob:none", source["repository"], str(directory)],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
        )
        if first.returncode != 0 or not (directory / ".git").exists():
            shutil.rmtree(directory, ignore_errors=True)
            run_step(
                run,
                [git, "clone", "--quiet", source["repository"], str(directory)],
                timeout=CLONE_TIMEOUT_SECONDS,
                log=log_dir / f"{source['name']}.clone.log" if log_dir else None,
            )
        cloned = True
    else:
        status = run_step(run, [git, "-C", str(directory), "status", "--porcelain"], timeout=GIT_TIMEOUT_SECONDS).stdout
        if status.strip():
            raise BootstrapError("source checkout has local changes; use a fresh source-root")
    present = run(
        [git, "-C", str(directory), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if present.returncode != 0:
        fetched = run(
            [git, "-C", str(directory), "fetch", "--quiet", "origin", sha],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
        )
        if fetched.returncode != 0:
            run_step(
                run,
                [git, "-C", str(directory), "fetch", "--quiet", "--tags", "origin"],
                timeout=CLONE_TIMEOUT_SECONDS,
            )
    run_step(run, [git, "-C", str(directory), "checkout", "--quiet", "--detach", sha], timeout=GIT_TIMEOUT_SECONDS)
    run_step(run, [git, "-C", str(directory), "clean", "-xdfq"], timeout=GIT_TIMEOUT_SECONDS)
    head = run_step(run, [git, "-C", str(directory), "rev-parse", "HEAD"], timeout=GIT_TIMEOUT_SECONDS).stdout.strip()
    date = run_step(
        run, [git, "-C", str(directory), "show", "-s", "--format=%cI", "HEAD"], timeout=GIT_TIMEOUT_SECONDS
    ).stdout.strip()
    if head.lower() != sha:
        raise BootstrapError(f"{source['name']}: HEAD {head} is not the pinned {sha}")
    if source.get("commit_date") and date != source["commit_date"]:
        raise BootstrapError(
            f"{source['name']}: committer date {date} differs from the locked {source['commit_date']}"
        )
    return {
        "name": source["name"],
        "repository": source["repository"],
        "directory": str(directory),
        "commit_sha": head,
        "commit_date": date,
        "cloned": cloned,
    }


def publish_tool(
    source: dict[str, Any],
    checkout_dir: Path,
    root: Path,
    dotnet: str,
    run: Runner,
    *,
    environ: Mapping[str, str] = os.environ,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    project = checkout_dir / Path(*source["project"].replace("\\", "/").split("/"))
    if not project.is_file():
        raise BootstrapError(f"{source['name']}: project file is missing: {project}")
    output = root / source["directory"]
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    argv = tool_publish_argv(dotnet, project, output, framework=source["target_framework"])
    run_step(
        run,
        argv,
        timeout=PUBLISH_TIMEOUT_SECONDS,
        env=publish_environment(environ),
        log=log_dir / f"{source['name']}.publish.log" if log_dir else None,
    )
    entry = output / source["entry_assembly"]
    if not entry.is_file():
        raise BootstrapError(f"{source['name']}: publish produced no {entry}")
    return {
        "tool": source["name"],
        "argv": argv,
        "output": str(output),
        "entry_assembly": str(entry),
        "entry_assembly_sha256": sha256_file(entry),
    }


def publish_plugins(
    source: dict[str, Any],
    checkout_dir: Path,
    root: Path,
    dotnet: str,
    stage_root: Path,
    run: Runner,
    *,
    environ: Mapping[str, str] = os.environ,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    projects = sorted(checkout_dir.glob(PLUGIN_PROJECT_GLOB))
    if not projects:
        raise BootstrapError(f"no {PLUGIN_PROJECT_GLOB} projects below {checkout_dir}")
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True)
    plugins_dir = root / Path(*source["directory"].replace("\\", "/").split("/"))
    if plugins_dir.exists():
        shutil.rmtree(plugins_dir)
    plugins_dir.mkdir(parents=True)
    collected: list[str] = []
    for project in projects:
        stage = stage_root / project.parent.name
        argv = plugin_publish_argv(dotnet, project, stage, framework=source["target_framework"])
        run_step(
            run,
            argv,
            timeout=PUBLISH_TIMEOUT_SECONDS,
            env=publish_environment(environ),
            log=log_dir / "plugins" / f"{project.parent.name}.log" if log_dir else None,
        )
        assemblies = sorted(path for path in stage.iterdir() if PLUGIN_ASSEMBLY_PATTERN.match(path.name))
        if not assemblies:
            raise BootstrapError(f"{project.parent.name}: publish produced no RegistryPlugin.*.dll")
        for assembly in assemblies:
            shutil.copyfile(assembly, plugins_dir / assembly.name)
            collected.append(assembly.name)
    return {
        "project_count": len(projects),
        "plugins_dir": str(plugins_dir),
        "collected": collected,
        "publish_argv_template": plugin_publish_argv(dotnet, "<RegistryPlugin.X.csproj>", stage_root / "<RegistryPlugin.X>"),
    }


def copy_pinned_assets(
    lock: dict[str, Any], root: Path, source_root: Path, run: Runner, git: str
) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for tree, declaration in (lock.get("assets") or {}).items():
        relative = tree.replace("\\", "/").strip("/")
        destination = root.joinpath(*relative.split("/"))
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True)
        count = 0
        for source in declaration.get("sources") or []:
            checkout = source_root / checkout_name(source["repository"])
            sha = str(source["commit_sha"]).lower()
            if not COMMIT_PATTERN.match(sha) or not (checkout / ".git").exists():
                raise BootstrapError(f"asset source {source['repository']}@{sha} is not checked out in {checkout}")
            prefix = str(source["path"]).strip("/") + "/"
            archived = run(
                [git, "-C", str(checkout), "archive", "--format=tar", sha, "--", prefix.rstrip("/")],
                capture_output=True, timeout=CLONE_TIMEOUT_SECONDS, check=False,
            )
            if archived.returncode != 0:
                raise BootstrapError(f"git archive {sha} {prefix} failed: {archived.stderr[-500:]!r}")
            wanted = set(source.get("files") or [])
            with tarfile.open(fileobj=io.BytesIO(archived.stdout)) as tar:
                for member in tar.getmembers():
                    if not member.isfile() or not member.name.startswith(prefix):
                        continue
                    name = member.name[len(prefix):]
                    if wanted and name not in wanted:
                        continue
                    target = destination / name
                    if Path(name).is_absolute() or ".." in Path(name).parts or target.exists():
                        raise BootstrapError(f"unsafe or duplicate asset member: {member.name}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(member).read())
                    count += 1
        observed, _count = tree_sha256(destination)
        expected = str(declaration.get("tree_sha256") or "").lower() or None
        reports.append(
            {
                "tree": tree,
                "sources": declaration.get("sources"),
                "destination": str(destination),
                "file_count": count,
                "expected_file_count": declaration.get("file_count"),
                "tree_sha256": observed,
                "expected_tree_sha256": expected,
                "status": STATUS_VERIFIED if observed == expected else "hash_mismatch",
            }
        )
    return reports


def verify_root(
    root: Path,
    lock_path: Path,
    dotnet: str | None,
    *,
    list_runtimes: Callable[[str], list[str] | None] | None = None,
) -> dict[str, Any]:
    toolchain = HostToolchain.load(root=root, lock_path=lock_path)
    rows = toolchain.verify(dotnet=dotnet, list_runtimes=list_runtimes)
    unverified = [row for row in rows if row["status"] != STATUS_VERIFIED]
    return {
        "root": str(toolchain.root),
        "lock_path": str(toolchain.lock_path),
        "lock_sha256": toolchain.lock_sha256,
        "dotnet": dotnet,
        "tool_count": len(toolchain.bindings()),
        "tree_count": len(toolchain.trees()),
        "rows": rows,
        "unverified": unverified,
        "verified": not unverified,
    }


def format_verification(report: dict[str, Any]) -> str:
    lines = [
        f"toolchain root: {report['root']}",
        f"lock: {report['lock_path']} (sha256 {report['lock_sha256']})",
    ]
    for row in report["rows"]:
        if row["kind"] == "entry_assembly":
            label = f"{row['tool']}: {row['entry_assembly']}"
        elif row["kind"] == "tree":
            label = f"{row['role']} {row['tree']} ({row.get('observed_file_count')} files)"
        else:
            label = f"{row.get('expected_runtime')} via {row.get('dotnet')}"
        lines.append(f"  {row['status']:<20} {row['kind']:<15} {label}")
    if report["verified"]:
        lines.append(f"result: verified ({report['tool_count']} tools, {report['tree_count']} trees)")
    else:
        lines.append(f"result: {len(report['unverified'])} unverified row(s)")
    return "\n".join(lines)


def rebuild_plan(
    sources: list[dict[str, Any]], root: Path, source_root: Path, stage_root: Path, dotnet: str
) -> list[str]:
    plan: list[str] = []
    for source in sources:
        directory = source_root / source["checkout"]
        plan.append(f"git clone {source['repository']} {directory}; git checkout --detach {source['commit_sha']}; git clean -xdf")
    for source in sources:
        if source["kind"] == "tool":
            argv = tool_publish_argv(dotnet, source_root / source["checkout"] / source["project"], root / source["directory"], framework=source["target_framework"])
            plan.append(" ".join(argv))
        else:
            argv = plugin_publish_argv(dotnet, source_root / source["checkout"] / "<RegistryPlugin.X>/<RegistryPlugin.X>.csproj", stage_root / "<RegistryPlugin.X>", framework=source["target_framework"])
            plan.append(" ".join(argv) + f"  # for every {PLUGIN_PROJECT_GLOB}; collect RegistryPlugin.*.dll into {root / source['directory']}")
    plan.append(f"{dotnet} build-server shutdown")
    return plan


def rebuild(
    args: argparse.Namespace,
    *,
    run: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    environ: Mapping[str, str] = os.environ,
    list_runtimes: Callable[[str], list[str] | None] | None = None,
) -> dict[str, Any]:
    lock_path = args.lock.expanduser().resolve()
    lock = load_lock(lock_path)
    root = (args.root or default_toolchain_root()).expanduser().resolve()
    source_root = args.source_root.expanduser().resolve()
    stage_root = args.stage_root.expanduser().resolve()
    log_dir = args.log_dir.expanduser().resolve()
    git = which("git")
    if not git:
        raise BootstrapError("git is required to clone the pinned sources")
    dotnet = args.dotnet or resolve_dotnet(which)
    if not dotnet:
        raise BootstrapError("dotnet is required to publish the tools")
    sources = pinned_sources(lock)
    report: dict[str, Any] = {
        "schema_version": "fmb_eztools_bootstrap_report.v1",
        "started_at": utc_now(),
        "root": str(root),
        "lock_path": str(lock_path),
        "lock_sha256": sha256_file(lock_path),
        "source_root": str(source_root),
        "plan": rebuild_plan(sources, root, source_root, stage_root, dotnet),
    }
    for tree, declaration in (lock.get("assets") or {}).items():
        for source in declaration.get("sources") or []:
            checkout = source_root / checkout_name(source["repository"])
            report["plan"].append(f"git -C {checkout} archive {source['commit_sha']} -- {source['path']}  # into {root / tree}")
    if args.dry_run:
        report["dry_run"] = True
        return report
    report["preflight"] = preflight_dotnet(lock, dotnet, run, allow_sdk_drift=args.allow_sdk_drift, list_runtimes=list_runtimes)
    root.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    report["checkouts"] = [checkout_pinned(item, source_root, run, git, log_dir=log_dir) for item in sources]
    report["publishes"] = []
    for item in sources:
        checkout_dir = source_root / item["checkout"]
        if item["kind"] == "tool":
            report["publishes"].append(publish_tool(item, checkout_dir, root, dotnet, run, environ=environ, log_dir=log_dir))
        else:
            report["registry_plugins"] = publish_plugins(item, checkout_dir, root, dotnet, stage_root, run, environ=environ, log_dir=log_dir)
    report["assets"] = copy_pinned_assets(lock, root, source_root, run, git)
    run([dotnet, "build-server", "shutdown"], capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
    verification = verify_root(root, lock_path, None if args.no_runtime_check else dotnet, list_runtimes=list_runtimes)
    report["verification"] = verification
    report["verified"] = verification["verified"]
    report["finished_at"] = utc_now()
    report_path = args.report.expanduser()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["report_path"] = str(report_path)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="rebuild or verify the pinned Zimmerman host toolchain")
    parser.add_argument("--verify-only", action="store_true", help="verify an existing root against the lock and exit")
    parser.add_argument("--root", type=Path, default=None, help="toolchain root (default: FMB_HOST_TOOLCHAIN_ROOT or ~/.cache/fmb/eztools/net9)")
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK_PATH)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT, help="where the pinned repositories are cloned")
    parser.add_argument("--stage-root", type=Path, default=DEFAULT_STAGE_ROOT, help="staging directory for the RegistryPlugin publishes")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--dotnet", default=None, help="dotnet executable (default: resolved from PATH)")
    parser.add_argument("--no-runtime-check", action="store_true", help="skip the dotnet runtime row of the verification")
    parser.add_argument("--allow-sdk-drift", action="store_true", help="publish even when the SDK differs from the locked one")
    parser.add_argument("--dry-run", action="store_true", help="print the rebuild plan without cloning or publishing")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    run: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    environ: Mapping[str, str] = os.environ,
    list_runtimes: Callable[[str], list[str] | None] | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.verify_only:
            root = (args.root or default_toolchain_root()).expanduser().resolve()
            dotnet = None if args.no_runtime_check else (args.dotnet or resolve_dotnet(which))
            report = verify_root(root, args.lock.expanduser().resolve(), dotnet, list_runtimes=list_runtimes)
            print(format_verification(report))
            if args.json:
                print(json.dumps(report, indent=2))
            return 0 if report["verified"] else 1
        report = rebuild(args, run=run, which=which, environ=environ, list_runtimes=list_runtimes)
        if report.get("dry_run"):
            print("rebuild plan (dry run):")
            for line in report["plan"]:
                print(f"  {line}")
            if args.json:
                print(json.dumps(report, indent=2))
            return 0
        print(format_verification(report["verification"]))
        print(f"report: {report['report_path']}")
        if args.json:
            print(json.dumps(report, indent=2))
        return 0 if report["verified"] else 1
    except (BootstrapError, HostToolchainError, OSError, ValueError) as error:
        print(f"bootstrap_eztools: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
