from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_file

LOCK_SCHEMA_VERSION = "fmb_host_toolchain_lock.v1"
DEFAULT_TOOLCHAIN_ROOT_ENV = "FMB_HOST_TOOLCHAIN_ROOT"
DEFAULT_TOOLCHAIN_ROOT = Path.home() / ".cache" / "fmb" / "eztools" / "net9"
DEFAULT_LOCK_PATH = Path(__file__).resolve().parent / "eztools-lock.json"
TREE_HASH_RECIPE = "fmb_tree_sha256.v1"
RUNTIME_LIST_TIMEOUT_SECONDS = 60
STATUS_VERIFIED = "verified"

RuntimeLister = Callable[[str], list[str] | None]


class HostToolchainError(ValueError):
    pass


def tree_sha256(directory: Path) -> tuple[str, int]:
    lines: list[str] = []
    for path in sorted(directory.rglob("*"), key=lambda item: item.relative_to(directory).parts):
        if path.is_symlink() or not path.is_file():
            continue
        lines.append(f"{path.relative_to(directory).as_posix()}\t{sha256_file(path)}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest(), len(lines)


def list_dotnet_runtimes(dotnet: str) -> list[str] | None:
    try:
        completed = subprocess.run(
            [dotnet, "--list-runtimes"],
            capture_output=True,
            text=True,
            timeout=RUNTIME_LIST_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


@dataclass(frozen=True)
class ToolBinding:
    executable: str
    tool_name: str
    entry_assembly: Path
    working_directory: Path
    expected_sha256: str
    version: str | None
    source: dict[str, Any]
    host_runnable: bool = True
    host_runnable_note: str | None = None

    def verify(self) -> dict[str, Any]:
        if not self.entry_assembly.is_file():
            return {
                "kind": "entry_assembly",
                "tool": self.tool_name,
                "status": "missing",
                "entry_assembly": str(self.entry_assembly),
                "expected_sha256": self.expected_sha256,
                "observed_sha256": None,
            }
        observed = sha256_file(self.entry_assembly)
        return {
            "kind": "entry_assembly",
            "tool": self.tool_name,
            "status": STATUS_VERIFIED if observed == self.expected_sha256 else "hash_mismatch",
            "entry_assembly": str(self.entry_assembly),
            "expected_sha256": self.expected_sha256,
            "observed_sha256": observed,
        }


@dataclass(frozen=True)
class TreeDeclaration:

    role: str
    tree: str
    directory: Path
    expected_sha256: str | None
    expected_file_count: int | None

    def verify(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "kind": "tree",
            "role": self.role,
            "tree": self.tree,
            "directory": str(self.directory),
            "recipe": TREE_HASH_RECIPE,
            "expected_sha256": self.expected_sha256,
            "expected_file_count": self.expected_file_count,
            "observed_sha256": None,
            "observed_file_count": None,
        }
        if not self.directory.is_dir():
            row["status"] = "missing"
            return row
        observed, count = tree_sha256(self.directory)
        row["observed_sha256"] = observed
        row["observed_file_count"] = count
        if self.expected_sha256 is None:
            row["status"] = "undeclared_hash"
        elif observed != self.expected_sha256:
            row["status"] = "hash_mismatch"
        elif self.expected_file_count is not None and count != self.expected_file_count:
            row["status"] = "file_count_mismatch"
        else:
            row["status"] = STATUS_VERIFIED
        return row


def default_toolchain_root() -> Path:
    override = os.environ.get(DEFAULT_TOOLCHAIN_ROOT_ENV)
    if override:
        return Path(override).expanduser()
    return DEFAULT_TOOLCHAIN_ROOT


def resolve_dotnet(which=shutil.which) -> str | None:
    return which("dotnet")


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def _optional_hash(value: Any) -> str | None:
    return str(value).lower() if isinstance(value, str) and value else None


class HostToolchain:

    def __init__(self, root: Path, lock: dict[str, Any], *, lock_path: Path | None = None) -> None:
        if lock.get("schema_version") != LOCK_SCHEMA_VERSION:
            raise HostToolchainError("unsupported host toolchain lock schema")
        self.root = root.expanduser().resolve()
        self.lock = lock
        self.lock_path = lock_path
        self.lock_sha256 = sha256_file(lock_path) if lock_path is not None else None
        self._bindings: dict[str, ToolBinding] = {}
        for row in lock.get("tools", []):
            tool_dir = self.root / str(row["directory"])
            binding = ToolBinding(
                executable=str(row["executable"]),
                tool_name=str(row["tool"]),
                entry_assembly=tool_dir / str(row["entry_assembly"]),
                working_directory=tool_dir,
                expected_sha256=str(row["entry_assembly_sha256"]),
                version=row.get("version"),
                source=dict(row.get("source", {})),
                host_runnable=bool(row.get("host_runnable", True)),
                host_runnable_note=row.get("host_runnable_note"),
            )
            self._bindings[binding.executable.casefold().replace("/", "\\")] = binding
        self._trees: list[TreeDeclaration] = []
        plugins = lock.get("registry_plugins")
        if isinstance(plugins, dict) and plugins.get("directory"):
            self._trees.append(self._tree_declaration("registry_plugins", str(plugins["directory"]), plugins))
        assets = lock.get("assets")
        if isinstance(assets, dict):
            for tree, declaration in assets.items():
                if isinstance(declaration, dict):
                    self._trees.append(self._tree_declaration("asset", str(tree), declaration))

    def _tree_declaration(self, role: str, tree: str, declaration: dict[str, Any]) -> TreeDeclaration:
        relative = tree.replace("\\", "/").strip("/")
        return TreeDeclaration(
            role=role,
            tree=tree,
            directory=self.root.joinpath(*relative.split("/")),
            expected_sha256=_optional_hash(declaration.get("tree_sha256")),
            expected_file_count=_optional_int(declaration.get("file_count")),
        )

    @classmethod
    def load(cls, *, root: Path | None = None, lock_path: Path | None = None) -> HostToolchain:
        lock_file = (lock_path or DEFAULT_LOCK_PATH).expanduser().resolve()
        if not lock_file.is_file():
            raise HostToolchainError(f"host toolchain lock is missing: {lock_file}")
        lock = json.loads(lock_file.read_text(encoding="utf-8"))
        return cls(root or default_toolchain_root(), lock, lock_path=lock_file)

    def binding_for(self, executable: str) -> ToolBinding | None:
        return self._bindings.get(executable.casefold().replace("/", "\\"))

    def bindings(self) -> list[ToolBinding]:
        return list(self._bindings.values())

    def trees(self) -> list[TreeDeclaration]:
        return list(self._trees)

    def verify_runtime(
        self, dotnet: str | None, *, list_runtimes: RuntimeLister | None = None
    ) -> dict[str, Any]:
        expected = self.lock.get("dotnet_runtime")
        row: dict[str, Any] = {
            "kind": "runtime",
            "dotnet": dotnet,
            "dotnet_sha256": None,
            "expected_runtime": expected,
            "observed_runtimes": None,
        }
        if not dotnet:
            row["status"] = "missing"
            return row
        dotnet_path = Path(dotnet)
        if dotnet_path.is_file():
            row["dotnet_sha256"] = sha256_file(dotnet_path)
        observed = (list_runtimes or list_dotnet_runtimes)(dotnet)
        row["observed_runtimes"] = observed
        if observed is None:
            row["status"] = "unreadable"
        elif not isinstance(expected, str) or not expected.strip():
            row["status"] = "undeclared_runtime"
        elif any(line == expected or line.startswith(expected + " ") for line in observed):
            row["status"] = STATUS_VERIFIED
        else:
            row["status"] = "mismatch"
        return row

    def verify(
        self, *, dotnet: str | None = None, list_runtimes: RuntimeLister | None = None,
        executables: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        bindings = self.bindings()
        unknown = []
        if executables is not None:
            keys = {name.casefold().replace("/", "\\") for name in executables}
            windows = {name.casefold() for name in self.lock.get("windows_only_processors", {})}
            unknown = sorted(keys - set(self._bindings) - windows)
            bindings = [b for key, b in self._bindings.items() if key in keys and b.host_runnable]
        rows = [binding.verify() for binding in bindings]
        rows.extend({"kind": "entry_assembly", "tool": name, "status": "undeclared"} for name in unknown)
        rows.extend(tree.verify() for tree in self.trees() if executables is None or any(
            tree.directory.is_relative_to(binding.working_directory) for binding in bindings))
        if dotnet is not None:
            rows.append(self.verify_runtime(dotnet, list_runtimes=list_runtimes))
        return rows

    def unverified(
        self, *, dotnet: str | None = None, list_runtimes: RuntimeLister | None = None,
        executables: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        return [
            row
            for row in self.verify(dotnet=dotnet, list_runtimes=list_runtimes, executables=executables)
            if row["status"] != STATUS_VERIFIED
        ]

    def describe(self, *, verification: list[dict[str, Any]]) -> dict[str, Any]:
        rows = list(verification)
        return {
            "schema_version": LOCK_SCHEMA_VERSION,
            "root": str(self.root),
            "lock_path": str(self.lock_path) if self.lock_path else None,
            "lock_sha256": self.lock_sha256,
            "dotnet_sdk": self.lock.get("dotnet_sdk"),
            "dotnet_runtime": self.lock.get("dotnet_runtime"),
            "tools": [
                {
                    "tool": binding.tool_name,
                    "executable": binding.executable,
                    "entry_assembly": str(binding.entry_assembly),
                    "entry_assembly_sha256": binding.expected_sha256,
                    "version": binding.version,
                    "source": binding.source,
                    "host_runnable": binding.host_runnable,
                }
                for binding in self.bindings()
            ],
            "registry_plugins": self.lock.get("registry_plugins"),
            "assets": self.lock.get("assets"),
            "windows_only_processors": self.lock.get("windows_only_processors"),
            "tree_hash_recipe": TREE_HASH_RECIPE,
            "verification": rows,
            "verified": all(row["status"] == STATUS_VERIFIED for row in rows),
        }


__all__ = [
    "DEFAULT_LOCK_PATH",
    "DEFAULT_TOOLCHAIN_ROOT",
    "DEFAULT_TOOLCHAIN_ROOT_ENV",
    "HostToolchain",
    "HostToolchainError",
    "LOCK_SCHEMA_VERSION",
    "TREE_HASH_RECIPE",
    "ToolBinding",
    "TreeDeclaration",
    "default_toolchain_root",
    "list_dotnet_runtimes",
    "resolve_dotnet",
    "tree_sha256",
]
