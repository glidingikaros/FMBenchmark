from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import shutil
import sys
from pathlib import Path, PurePosixPath

from fmb.generation.recipe import BOX, SHA256, VERSION, _object as _fields, digest, file_row

LOCK_SCHEMA = "generation_dependency_lock.v2"
HOST_RECORD_SCHEMA = "generation_host_record.v1"
PINNED_SECTIONS = ("backend", "base", "guest", "guest_code", "host_libraries")
LOCK_FIELDS = {"schema_version", *PINNED_SECTIONS, "recorded_host"}
ANSIBLE_CORE_GUEST_PATHS = ("executor/powershell", "module_utils/powershell", "module_utils/csharp",
                            "plugins/shell/powershell.py")
GUEST_COLLECTIONS = ("ansible.windows",)
TOOL_TIMEOUT_SECONDS = 120
DISTRIBUTION = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


def _text(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")


def _relative(path, label):
    parts = PurePosixPath(path).parts if isinstance(path, str) else ()
    if (not isinstance(path, str) or not path or "\\" in path or path.startswith("/")
            or any(part in {".", ".."} for part in parts) or PurePosixPath(path).as_posix() != path):
        raise ValueError(f"{label} has an unsafe relative path: {path!r}")


def _rows(rows, label):
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{label} lists no files")
    for row in rows:
        _fields(row, {"path", "sha256", "size_bytes"}, f"{label} file")
        _relative(row["path"], label)
        if (not SHA256.fullmatch(str(row["sha256"])) or isinstance(row["size_bytes"], bool)
                or not isinstance(row["size_bytes"], int) or row["size_bytes"] < 0):
            raise ValueError(f"{label} file digest or size is invalid")
    paths = [row["path"] for row in rows]
    if paths != sorted(set(paths)):
        raise ValueError(f"{label} files must be unique and sorted")


def canonical_distribution(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def pinned_digest(lock):
    return digest({section: lock[section] for section in PINNED_SECTIONS})


def _backend(name):
    from fmb.generation.backends import BACKENDS

    try:
        return BACKENDS[name]
    except KeyError:
        raise ValueError(f"no generation backend {name!r}; available: {', '.join(sorted(BACKENDS))}") from None


def validate_lock(lock):
    _fields(lock, LOCK_FIELDS, "dependency lock")
    if lock["schema_version"] != LOCK_SCHEMA:
        raise ValueError("unsupported generation dependency lock")
    _fields(lock["backend"], {"name", "hypervisor"}, "dependency backend")
    backend = _backend(lock["backend"]["name"])
    _fields(lock["backend"]["hypervisor"], {"product", "version", "build"}, "dependency hypervisor")
    for key, value in lock["backend"]["hypervisor"].items():
        _text(value, f"hypervisor {key}")
    base = lock["base"]
    _fields(base, {"location", "entry", "files"}, "dependency base")
    location = base["location"]
    _fields(location, {"kind", "box", "version", "architecture", "provider"}, "dependency base location")
    if (location["kind"] != backend.base_store or location["provider"] != backend.name
            or not BOX.fullmatch(str(location["box"])) or not VERSION.fullmatch(str(location["version"]))
            or not (location["architecture"] is None or VERSION.fullmatch(str(location["architecture"])))):
        raise ValueError("dependency base location is invalid for its backend")
    _rows(base["files"], "dependency base")
    if base["entry"] != backend.base_entry or base["entry"] not in {row["path"] for row in base["files"]}:
        raise ValueError("the base's entry file is not locked")
    _fields(lock["guest"], {"windows_build", "timezone", "locale"}, "dependency guest")
    for key, value in lock["guest"].items():
        _text(value, f"guest {key}")
    guest_code = lock["guest_code"]
    _fields(guest_code, {"ansible_core", "collections"}, "dependency guest code")
    _fields(guest_code["ansible_core"], {"version", "files"}, "ansible-core")
    _text(guest_code["ansible_core"]["version"], "ansible-core version")
    _rows(guest_code["ansible_core"]["files"], "ansible-core")
    collections = guest_code["collections"]
    if not isinstance(collections, dict) or set(collections) != set(GUEST_COLLECTIONS):
        raise ValueError("dependency lock must pin exactly the collections the playbooks use")
    for name, collection in collections.items():
        _fields(collection, {"version", "files"}, f"collection {name}")
        _text(collection["version"], f"collection {name} version")
        _rows(collection["files"], f"collection {name}")
    libraries = lock["host_libraries"]
    _fields(libraries, {"imports", "distributions"}, "dependency host libraries")
    distributions = libraries["distributions"]
    if not isinstance(distributions, dict) or not distributions or list(distributions) != sorted(distributions):
        raise ValueError("dependency host libraries are missing or unsorted")
    for name, version in distributions.items():
        if not DISTRIBUTION.fullmatch(name):
            raise ValueError(f"host library name is not canonical: {name!r}")
        _text(version, f"host library {name} version")
    imports = libraries["imports"]
    if not isinstance(imports, dict) or list(imports) != sorted(imports) or not all(
            isinstance(names, list) and names and names == sorted(set(names)) and set(names) <= set(distributions)
            for names in imports.values()):
        raise ValueError("dependency host library imports must name locked distributions")
    if not isinstance(lock["recorded_host"], dict):
        raise ValueError("recorded host must be an object")
    return lock


def _run_text(command, *, cwd=None):
    from fmb.core.owned_process import run_owned

    return run_owned([str(part) for part in command], cwd=cwd, capture_output=True,
                     timeout=TOOL_TIMEOUT_SECONDS).stdout


def tree_rows(root, selectors=None):
    root = Path(root)
    rows = []
    for target in [root] if selectors is None else [root / selector for selector in selectors]:
        if target.is_symlink() or not target.exists():
            raise ValueError(f"locked path is missing or a link: {target}")
        paths = [target] if target.is_file() else sorted(target.rglob("*"))
        for path in paths:
            if "__pycache__" in path.parts or path.suffix == ".pyc" or (path.is_dir() and not path.is_symlink()):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"locked tree contains a link or special file: {path}")
            rows.append(file_row(path, path.relative_to(root).as_posix()))
    return sorted(rows, key=lambda row: row["path"])


def ansible_layout(ansible, collections=GUEST_COLLECTIONS, *, cwd=None):
    text = _run_text([ansible, "--version"], cwd=cwd)
    core = re.search(r"^ansible \[core ([^\]]+)\]", text, re.M)
    module = re.search(r"^\s*ansible python module location = (.+)$", text, re.M)
    if not core or not module:
        raise RuntimeError("ansible --version names no ansible-core version or module location")
    galaxy = shutil.which("ansible-galaxy", path=str(Path(ansible).parent)) or Path(ansible).with_name("ansible-galaxy")
    found = {}
    for fqcn in collections:
        listing = json.loads(_run_text([galaxy, "collection", "list", fqcn, "--format", "json"], cwd=cwd) or "{}")
        match = next(((path, entries[fqcn]) for path, entries in listing.items() if fqcn in entries), None)
        if match is None:
            raise RuntimeError(f"collection {fqcn} is not installed for {ansible}")
        namespace, name = fqcn.split(".")
        found[fqcn] = {"version": match[1]["version"], "root": Path(match[0]) / namespace / name}
    return {"core_version": core.group(1), "core_root": Path(module.group(1).strip()), "collections": found}


def guest_code(layout):
    return {"ansible_core": {"version": layout["core_version"],
                             "files": tree_rows(layout["core_root"], ANSIBLE_CORE_GUEST_PATHS)},
            "collections": {fqcn: {"version": collection["version"], "files": tree_rows(collection["root"])}
                            for fqcn, collection in sorted(layout["collections"].items())}}


def installed_version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def library_versions(imports):
    providers = importlib.metadata.packages_distributions()
    provided = {}
    for top in sorted(imports):
        if not providers.get(top):
            raise RuntimeError(f"no installed distribution provides {top!r}")
        provided[top] = sorted({canonical_distribution(name) for name in providers[top]})
    pending = [name for names in provided.values() for name in names]
    versions = {}
    while pending:
        name = canonical_distribution(pending.pop())
        if name in versions:
            continue
        version = installed_version(name)
        if version is None:
            raise RuntimeError(f"distribution {name} is not installed")
        versions[name] = version
        for requirement in importlib.metadata.requires(name) or ():
            head, _, marker = requirement.partition(";")
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", head)
            if not match or "extra" in marker:
                continue
            if marker.strip() and installed_version(match.group(1)) is None:
                continue
            pending.append(match.group(1))
    return {"imports": provided, "distributions": dict(sorted(versions.items()))}


def base_rows(backend, directory):
    return [file_row(path, path.relative_to(directory).as_posix()) for path in backend.base_files(directory)]


def _tool_versions(tools):
    rows = {}
    for name, path in sorted(tools.items()):
        if not path:
            rows[name] = None
            continue
        version = None
        if name != "vmrun":
            try:
                version = _run_text([path, "--version"]).splitlines()[0].strip()
            except Exception as error:
                version = f"unavailable: {type(error).__name__}"
        rows[name] = {"path": str(path), "resolved": str(Path(path).resolve()), "version": version}
    return rows


def recorded_host(backend, tools):
    distributions = {}
    for distribution in importlib.metadata.distributions():
        name = canonical_distribution(distribution.metadata["Name"] or "")
        if name and name not in distributions:
            distributions[name] = distribution.version
    return {"platform": platform.platform(), "machine": platform.machine(),
            "python": {"version": platform.python_version(), "executable": sys.executable},
            "tools": _tool_versions(tools), "backend": backend.host_facts(tools),
            "python_distributions": dict(sorted(distributions.items()))}


def _resolved_tools(backend, tools):
    resolved = {**backend.discover_tools(), **{name: path for name, path in (tools or {}).items() if path}}
    missing = sorted(name for name in backend.TOOLS if not resolved.get(name))
    if missing:
        raise RuntimeError("missing generation tools: " + ", ".join(missing))
    return resolved


def build_lock(*, backend_name, box, version, guest, imports, tools=None, cwd=None):
    backend = _backend(backend_name)
    tools = _resolved_tools(backend, tools)
    location = backend.base_location(box, version)
    directory = backend.base_directory(location)
    rows = base_rows(backend, directory)
    backend.check_base(directory, backend.base_entry, rows)
    lock = {"schema_version": LOCK_SCHEMA,
            "backend": {"name": backend.name, "hypervisor": backend.hypervisor_identity(tools)},
            "base": {"location": location, "entry": backend.base_entry, "files": rows},
            "guest": dict(guest),
            "guest_code": guest_code(ansible_layout(tools["ansible"], cwd=cwd)),
            "host_libraries": library_versions(imports),
            "recorded_host": recorded_host(backend, tools)}
    return validate_lock(lock)


def _compare_rows(expected, observed, label):
    want = {row["path"]: row for row in expected}
    have = {row["path"]: row for row in observed}
    problems = ([f"missing {path}" for path in sorted(set(want) - set(have))]
                + [f"unlocked {path}" for path in sorted(set(have) - set(want))]
                + [f"changed {path}" for path in sorted(set(want) & set(have)) if want[path] != have[path]])
    if problems:
        raise ValueError(f"{label} differs from its lock: " + "; ".join(problems[:5])
                         + (f"; and {len(problems) - 5} more" if len(problems) > 5 else ""))


def base_directory(lock):
    return _backend(lock["backend"]["name"]).base_directory(lock["base"]["location"])


def verify_lock(lock, *, tools=None, cwd=None):
    validate_lock(lock)
    backend = _backend(lock["backend"]["name"])
    tools = _resolved_tools(backend, tools)
    identity = backend.hypervisor_identity(tools)
    if identity != lock["backend"]["hypervisor"]:
        raise ValueError(f"hypervisor differs from its lock: {identity} instead of {lock['backend']['hypervisor']}")
    directory = backend.base_directory(lock["base"]["location"])
    if not directory.is_dir():
        raise ValueError(f"locked base is not installed: {lock['base']['location']}")
    _compare_rows(lock["base"]["files"], base_rows(backend, directory), "installed base")
    backend.check_base(directory, lock["base"]["entry"], lock["base"]["files"])
    layout = ansible_layout(tools["ansible"], cwd=cwd)
    pinned = lock["guest_code"]
    if layout["core_version"] != pinned["ansible_core"]["version"]:
        raise ValueError(f"ansible-core {layout['core_version']} differs from its lock "
                         f"({pinned['ansible_core']['version']})")
    observed = guest_code(layout)
    _compare_rows(pinned["ansible_core"]["files"], observed["ansible_core"]["files"], "ansible-core guest code")
    for fqcn, collection in pinned["collections"].items():
        if observed["collections"][fqcn]["version"] != collection["version"]:
            raise ValueError(f"collection {fqcn} {observed['collections'][fqcn]['version']} differs from its lock "
                             f"({collection['version']})")
        _compare_rows(collection["files"], observed["collections"][fqcn]["files"], f"collection {fqcn}")
    locked = lock["host_libraries"]["distributions"]
    drifted = {name: installed_version(name) for name, version in locked.items() if installed_version(name) != version}
    if drifted:
        raise ValueError("host libraries differ from their lock: "
                         + ", ".join(f"{name} {found or 'missing'} (locked {locked[name]})"
                                     for name, found in sorted(drifted.items())))
    return {"schema_version": HOST_RECORD_SCHEMA, "pinned_inputs_sha256": pinned_digest(lock),
            "verified": ["backend", "base", "guest_code", "host_libraries"], "guest": "checked_in_guest",
            "recorded": recorded_host(backend, tools)}


def check_host(*, backend_name, box, version, imports, tools=None, cwd=None):
    backend = _backend(backend_name)
    found = {**backend.discover_tools(), **{name: path for name, path in (tools or {}).items() if path}}
    checks = []

    def add(name, passed, detail):
        checks.append({"check": name, "ok": bool(passed), "detail": detail})

    reason = backend.supported_host()
    add("host", reason is None, reason or f"{platform.system()} {platform.machine()}")
    add("python", sys.version_info >= (3, 11), platform.python_version())
    for name in backend.TOOLS:
        add(name, found.get(name), found.get(name) or "not found on PATH")
    for name, passed, detail in backend.host_checks(found):
        add(name, passed, detail)
    try:
        add("hypervisor", True, backend.hypervisor_identity(found))
    except Exception as error:
        add("hypervisor", False, str(error))
    try:
        layout = ansible_layout(found["ansible"], cwd=cwd) if found.get("ansible") else None
        add("ansible collections", layout is not None,
            {"ansible-core": layout["core_version"],
             **{fqcn: row["version"] for fqcn, row in layout["collections"].items()}} if layout else
            "ansible is not installed")
    except Exception as error:
        add("ansible collections", False, str(error))
    try:
        add("python libraries", True, library_versions(imports)["distributions"])
    except Exception as error:
        add("python libraries", False, f"{error}; install the package with its generation and collection extras")
    try:
        location = backend.base_location(box, version)
        directory = backend.base_directory(location)
        rows = [{"path": path.relative_to(directory).as_posix(), "sha256": "0" * 64, "size_bytes": 0}
                for path in backend.base_files(directory)]
        backend.check_base(directory, backend.base_entry, rows)
        add("base box", True, f"{box} {version}: {directory}")
    except Exception as error:
        add("base box", False, f"{box} {version}: {error}")
    return {"ready": all(row["ok"] for row in checks), "checks": checks}

