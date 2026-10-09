from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

RECIPE_SCHEMA = "generation_recipe.v1"
RECIPE_SCHEMA_V2 = "generation_recipe.v2"
PRIVATE_SCHEMA = "private_generation.v1"
LOCK_SCHEMA = "generation_dependency_lock.v1"
LOCK_SCHEMA_V2 = "generation_dependency_lock.v2"
REQUIRED_TOOLS = {"python", "vagrant", "qemu-img", "ansible", "ansible-playbook", "vmrun"}
REQUIRED_ROLES = {"base", "provider", "runtime", "ansible_collection"}
REGENERATION_CLAIM = "new_realization_requires_independent_conformance_validation"
VERIFICATION_SCOPES = {1: "declared_files_and_base_disk_closure", 2: "evidence_inputs_pinned_host_recorded"}
RECIPE_FIELDS = {"schema_version", "recipe_id", "config", "private_sha256", "dependency_lock_sha256",
                 "source", "source_sha256", "regeneration_claim", "dependency_verification_scope"}
RECIPE_V2_FIELDS = RECIPE_FIELDS | {"pinned_inputs_sha256", "assignment_origin"}
CLOSURE_DATA = ("index/scanners/dfir-ntfs-lock.json",)
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")
BOX = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _object(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(f"{label} fields are invalid")


QEMU_BOXES = {"x86_64": "fmb/windows-11-x64", "amd64": "fmb/windows-11-x64",
              "arm64": "fmb/windows-11-arm64", "aarch64": "fmb/windows-11-arm64"}


def qemu_box():
    import platform

    return QEMU_BOXES[platform.machine().lower()]


def paper_config(image, provider='vmware_desktop', windows_box=None):
    from fmb.core.paths import PROJECT_ROOT
    protocol = read_json(PROJECT_ROOT / 'contracts/paper/protocol.json')
    if image not in protocol['images']:
        raise ValueError('unknown paper image')
    fixed = {key:value for key,value in protocol['generation'].items()
             if key not in {'base_box_version', 'native_context'}}
    if provider == 'qemu':
        fixed.update(provider='qemu', windows_box=windows_box or qemu_box())
    elif provider != fixed['provider'] or windows_box not in {None, fixed['windows_box']}:
        raise ValueError('unknown generation provider')
    fixed['population_seed'] = protocol['images'][image]['population_seed']
    return fixed


def validate_paper_config(config):
    for image in ('I1','I2','I3'):
        candidates = [paper_config(image)] + [paper_config(image, 'qemu', box) for box in sorted(set(QEMU_BOXES.values()))]
        if any(digest(config) == digest(candidate) for candidate in candidates):
            return image
    raise ValueError('recipe configuration differs from the three fixed paper images')

def validate_resolved_inputs(config, population, assignment, guest_plan):
    image = validate_paper_config(config)
    from fmb.generation import population as population_support
    from fmb.core.paths import PROJECT_ROOT
    protocol = read_json(PROJECT_ROOT / 'contracts/paper/protocol.json')
    contract = population_support.load_population_contract(
        PROJECT_ROOT / protocol['images'][image]['population_contract'])
    if not isinstance(population, dict):
        raise ValueError("recipe population differs from its configuration")
    population_support.verify_public_manifest(population)
    expected = population_support.build_public_manifest(
        experiment=config['experiment'], seed=config['population_seed'], contract=contract)
    if population != expected:
        raise ValueError("recipe population differs from its configuration")
    _object(assignment, {"schema_version", "population_manifest_sha256", "bindings"}, "private assignment")
    expected_plan = population_support.build_guest_plan(expected, assignment, case=config["case"])
    if guest_plan != expected_plan:
        raise ValueError("resolved guest plan differs from its private assignment")


def _fsync_directory(path):
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def file_digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def file_row(path, relative):
    return {"path": relative, "sha256": file_digest(path), "size_bytes": path.stat().st_size}


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def write_private(path, value):
    path = Path(path)
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _member(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("invalid recipe member path")
    path = Path(relative)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("unsafe recipe member path")
    root = Path(root).resolve()
    result = root / path
    if not result.resolve().is_relative_to(root) or any(
        parent.is_symlink() for parent in [result, *result.parents] if parent != root
    ):
        raise ValueError("recipe member must not traverse a symbolic link")
    return result


def source_inventory(root):
    root = Path(root)
    paths = sorted([*root.glob("*.py"), root / "Vagrantfile", *root.glob("populations*.json"),
                    *root.glob("*.ps1"), *root.joinpath("ansible").rglob("*.yml"),
                    *root.joinpath("ansible").rglob("*.cfg"),
                    *root.joinpath("ansible").rglob("*.py"),
                    *root.joinpath("ansible").rglob("*.ps1"),
                    *root.joinpath("ansible").rglob("*.b64")])
    return [file_row(path, path.relative_to(root).as_posix()) for path in paths if path.is_file()]


def _module_file(package_root, dotted):
    parts = dotted.split(".")[1:]
    base = Path(package_root).joinpath(*parts)
    for candidate in ([base.with_suffix(".py")] if parts else []) + [base / "__init__.py"]:
        if candidate.is_file():
            return candidate
    return None


def _import_nodes(tree, module_level_only):
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        pending.extend(child for child in ast.iter_child_nodes(node) if not (
            module_level_only and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))))


def _file_imports(path, package_root):
    package = ["fmb", *path.relative_to(package_root).parts[:-1]]
    fmb_names, third_party = set(), set()
    tree = ast.parse(path.read_bytes(), filename=str(path))
    for node in _import_nodes(tree, module_level_only=path.name == "__init__.py"):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            if node.level:
                base = package[:len(package) - node.level + 1]
                stem = ".".join(base + ([node.module] if node.module else []))
            else:
                stem = node.module or ""
            names = [stem, *(f"{stem}.{alias.name}" for alias in node.names if alias.name != "*")]
        for name in names:
            top = name.split(".")[0]
            if top == "fmb":
                fmb_names.add(name)
            elif top and top != "__future__" and top not in sys.stdlib_module_names:
                third_party.add(top)
    return fmb_names, third_party


def closure_modules(package_root):
    package_root = Path(package_root)
    pending = sorted((package_root / "generation").glob("*.py"))
    seen, third_party = set(), set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        names, outside = _file_imports(path, package_root)
        third_party |= outside
        for name in names:
            parts = name.split(".")
            for end in range(1, len(parts) + 1):
                module = _module_file(package_root, ".".join(parts[:end]))
                if module is not None and module not in seen:
                    pending.append(module)
    return sorted(seen), sorted(third_party)


def source_closure(package_root):
    package_root = Path(package_root)
    rows = [{**row, "path": "generation/" + row["path"]} for row in source_inventory(package_root / "generation")]
    listed = {row["path"] for row in rows}
    modules, _ = closure_modules(package_root)
    for path in [*modules, *(package_root / name for name in CLOSURE_DATA)]:
        relative = path.relative_to(package_root).as_posix()
        if relative not in listed:
            listed.add(relative)
            rows.append(file_row(path, relative))
    return sorted(rows, key=lambda row: row["path"])


def lock_version(lock):
    versions = {LOCK_SCHEMA: 1, LOCK_SCHEMA_V2: 2}
    if not isinstance(lock, dict) or lock.get("schema_version") not in versions:
        raise ValueError("unsupported generation dependency lock")
    return versions[lock["schema_version"]]


def locked_box(lock):
    base = lock["base"] if lock_version(lock) == 1 else lock["base"]["location"]
    return base["box"], base["version"]


def base_vmx_path(lock):
    if lock_version(lock) == 1:
        return Path(lock["base"]["vmx_path"]).resolve()
    from fmb.generation import dependency_lock

    return (dependency_lock.base_directory(lock) / lock["base"]["entry"]).resolve()


def base_file_rows(lock):
    if lock_version(lock) == 2:
        return sorted(lock["base"]["files"], key=lambda row: row["path"])
    source_root = base_vmx_path(lock).parent
    return sorted([
        {"path": Path(row["path"]).resolve().relative_to(source_root).as_posix(),
         "sha256": row["sha256"], "size_bytes": row["size_bytes"]}
        for row in lock["artifacts"] if Path(row["path"]).resolve().is_relative_to(source_root)
    ], key=lambda row: row["path"])


def resolved_activity(seed, count=36):
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("activity seed must be a non-negative integer")
    directories = [r"C:\Users\Public\Documents", r"C:\Windows\Temp",
                   r"C:\Users\vagrant\Desktop"]
    plan = []
    for index in range(count):
        token = hashlib.sha256(f"fmb-activity.v1:{seed}:{index}".encode()).hexdigest()
        plan.append({"path": directories[int(token[:8], 16) % 3] + "\\" + token[8:24] + ".txt",
                     "content": f"Local activity {index}: {token[24:40]}",
                     "append_content": f"Update {token[40:56]}", "delete": index % 3 != 0,
                     "sleep_ms": 100 + int(token[56:64], 16) % 250})
    return plan


def resolved_hardware(seed):
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("hardware seed must be a non-negative integer")
    token = hashlib.sha256(f"fmb-hardware.v1:{seed}".encode()).hexdigest()
    def uuid_hex(value):
        return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:32]}"
    return {"base_mac": f"00:50:56:{int(token[:2], 16) % 64:02X}:{token[2:4].upper()}:{token[4:6].upper()}",
            "uuid_bios": uuid_hex(token[:32]), "uuid_location": uuid_hex(token[32:]),
            "display_name": "Forensic-Gen-" + token[:8]}


def validate_dependency_lock(lock, *, verify_bytes=True):
    if isinstance(lock, dict) and lock.get("schema_version") == LOCK_SCHEMA_V2:
        from fmb.generation import dependency_lock

        dependency_lock.validate_lock(lock)
        if verify_bytes:
            dependency_lock.verify_lock(lock)
        return lock
    _object(lock, {"schema_version", "base", "guest", "tools", "artifacts"}, "dependency lock")
    if lock.get("schema_version") != LOCK_SCHEMA:
        raise ValueError("unsupported generation dependency lock")
    base = lock.get("base", {})
    _object(base, {"provider", "box", "version", "vmx_path"}, "dependency base")
    if (base.get("provider") != "vmware_desktop" or not base.get("box")
            or not isinstance(base.get("version"), str)
            or not VERSION.fullmatch(base["version"])
            or not BOX.fullmatch(str(base["box"]))
            or not Path(base.get("vmx_path", "")).is_absolute()):
        raise ValueError("recipe mode requires an exact installed VMware base and version")
    guest = lock.get("guest", {})
    if set(guest) != {"windows_build", "timezone", "locale"} or not all(
        isinstance(value, str) and value for value in guest.values()
    ):
        raise ValueError("lock must declare guest build, timezone and locale")
    tools = lock.get("tools", {})
    if set(tools) != REQUIRED_TOOLS:
        raise ValueError("dependency lock must identify every required executable")
    artifacts = lock.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("dependency lock artifacts are missing")
    files, roles = {}, set()
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size_bytes", "role"}:
            raise ValueError("dependency file fields are invalid")
        path = Path(record["path"])
        if not path.is_absolute() or str(path) in files or path.is_symlink():
            raise ValueError("dependency paths must be unique absolute regular-file locators")
        if (not SHA256.fullmatch(str(record["sha256"]))
                or isinstance(record["size_bytes"], bool)
                or not isinstance(record["size_bytes"], int) or record["size_bytes"] < 0):
            raise ValueError("dependency file digest or size is invalid")
        if verify_bytes and (not path.is_file() or path.stat().st_size != record["size_bytes"]
                             or file_digest(path) != record["sha256"]):
            raise ValueError(f"generation dependency changed or missing: {path}")
        files[str(path)] = record
        roles.add(record["role"])
    if not REQUIRED_ROLES <= roles:
        raise ValueError("dependency lock must retain base, provider, runtime and Ansible collection files")
    if base["vmx_path"] not in files or files[base["vmx_path"]]["role"] != "base":
        raise ValueError("selected base VMX is not locked")
    for name, tool in tools.items():
        if not isinstance(tool, dict) or set(tool) != {"path", "version"} or not tool["version"]:
            raise ValueError(f"missing version/path for {name}")
        if tool["path"] not in files:
            raise ValueError(f"executable is not content locked: {name}")
    if verify_bytes:
        _verify_base_closure(base, files)
    return lock


def _verify_base_closure(base, files):
    vmx = Path(base["vmx_path"])
    referenced = re.findall(r'(?im)^\s*[^\n=]+\.fileName\s*=\s*"([^"]+\.vmdk)"',
                            vmx.read_text(encoding="utf-8"))
    if not referenced:
        raise ValueError("locked base VMX contains no disk")
    for name in referenced:
        path = (vmx.parent / name).resolve()
        if str(path) not in files or files[str(path)]["role"] != "base":
            raise ValueError("base disk is outside dependency lock")
        with path.open("rb") as stream:
            prefix = stream.read(65536)
        if b"# Disk DescriptorFile" not in prefix:
            raise ValueError("recipe mode requires a flat base with explicit VMDK descriptors")
        descriptor = prefix.decode("utf-8")
        if re.search(r"(?im)^\s*parentFileNameHint\s*=", descriptor):
            raise ValueError("recipe base may not have a backing parent")
        extents = re.findall(r'(?m)^\s*(?:RW|RDONLY|NOACCESS)\s+\d+\s+\S+\s+"([^"]+)"', descriptor)
        if not extents:
            raise ValueError("base disk descriptor has no extents")
        for extent in extents:
            resolved = str((path.parent / extent).resolve())
            if resolved not in files or files[resolved]["role"] != "base":
                raise ValueError("base disk extent is outside dependency lock")


def _assignment_origin(origin):
    if origin == {"kind": "fresh_entropy"}:
        return origin
    _object(origin, {"kind", "recipe_id", "private_sha256"}, "assignment origin")
    if (origin["kind"] != "reused" or not re.fullmatch(r"recipe:[0-9a-f]{64}", str(origin["recipe_id"]))
            or not SHA256.fullmatch(str(origin["private_sha256"]))):
        raise ValueError("assignment origin is invalid")
    return origin


def _factual_challenge_plan(config, guest_plan, population):
    from fmb.generation.factual_challenge import build_plan
    from fmb.generation.pilot_profile import parameters_for_manifest

    return build_plan(config["population_seed"],
                      shellbag_input=guest_plan["scenario_inputs"]["shellbag_path_residue_01"], profile="pilot_min.v1",
                      pilot_parameters=parameters_for_manifest(population))


def _check_closure_libraries(package_root, lock):
    _, imports = closure_modules(package_root)
    missing = sorted(set(imports) - set(lock["host_libraries"]["imports"]))
    if missing:
        raise ValueError("dependency lock pins no library for the generator's imports: " + ", ".join(missing))


def freeze_recipe(destination, *, source_root, config, population, assignment, guest_plan,
                  dependency_lock, activity_seed=None, hardware_seed=None, assignment_origin=None):
    destination = Path(destination).expanduser().absolute()
    if destination.exists():
        raise FileExistsError("recipe destination already exists")
    validate_resolved_inputs(config, population, assignment, guest_plan)
    version = lock_version(dependency_lock)
    if version == 1:
        if assignment_origin is not None:
            raise ValueError("a reused assignment needs a portable (v2) dependency lock")
        validate_dependency_lock(dependency_lock)
    else:
        from fmb.generation import dependency_lock as portable

        portable.validate_lock(dependency_lock)
        _check_closure_libraries(Path(source_root).parent, dependency_lock)
        assignment_origin = _assignment_origin(assignment_origin or {"kind": "fresh_entropy"})
    box, box_version = locked_box(dependency_lock)
    if config["windows_box"] != box:
        raise ValueError("configured box differs from locked base")
    activity_seed = config["population_seed"] if activity_seed is None else activity_seed
    hardware_seed = config["population_seed"] if hardware_seed is None else hardware_seed
    if activity_seed != config["population_seed"] or hardware_seed != config["population_seed"]:
        raise ValueError("activity and hardware seeds must match the declared paper image")
    if box_version != "0":
        raise ValueError("paper generation requires the declared base box version 0")
    private = {"schema_version": PRIVATE_SCHEMA, "population_manifest": population,
               "assignment": assignment, "guest_plan": guest_plan,
               "activity_seed": activity_seed,
               "activity_plan": resolved_activity(
                   activity_seed, count=config.get("activity_count", 36)
               ),
               "hardware_seed": hardware_seed, "hardware": resolved_hardware(hardware_seed)}
    if config.get("factual_challenge") == "pilot_min.v1":
        private["factual_challenge_plan"] = _factual_challenge_plan(config, guest_plan, population)
    files_root = Path(source_root) if version == 1 else Path(source_root).parent
    source = source_inventory(files_root) if version == 1 else source_closure(files_root)
    body = {"schema_version": RECIPE_SCHEMA if version == 1 else RECIPE_SCHEMA_V2, "config": config,
            "private_sha256": digest(private), "dependency_lock_sha256": digest(dependency_lock),
            "source": source, "source_sha256": digest(source),
            "regeneration_claim": REGENERATION_CLAIM,
            "dependency_verification_scope": VERIFICATION_SCOPES[version]}
    if version == 2:
        body.update(pinned_inputs_sha256=portable.pinned_digest(dependency_lock),
                    assignment_origin=assignment_origin)
    recipe = {**body, "recipe_id": "recipe:" + digest(body)}
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".fmb-recipe-", dir=destination.parent))
    try:
        for item in source:
            target = staging / "source" / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_member(files_root, item["path"]), target)
            os.chmod(target, 0o600)
            with target.open("r+b") as stream:
                os.fsync(stream.fileno())
        write_private(staging / "private-generation.json", private)
        write_private(staging / "dependency-lock.json", dependency_lock)
        write_private(staging / "recipe.json", recipe)
        load_recipe(staging, source_root=source_root, verify_dependencies=False)
        for directory in sorted((item for item in staging.rglob("*") if item.is_dir()),
                                key=lambda item: len(item.parts), reverse=True):
            _fsync_directory(directory)
        _fsync_directory(staging)
        if destination.exists():
            raise FileExistsError("recipe destination appeared during freeze")
        staging.rename(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return recipe


def _read_recipe(directory, source_root):
    directory = Path(directory).expanduser().resolve()
    recipe = read_json(_member(directory, "recipe.json"))
    private = read_json(_member(directory, "private-generation.json"))
    lock = read_json(_member(directory, "dependency-lock.json"))
    version = {RECIPE_SCHEMA: 1, RECIPE_SCHEMA_V2: 2}.get(recipe.get("schema_version")) if isinstance(
        recipe, dict) else None
    _object(recipe, RECIPE_V2_FIELDS if version == 2 else RECIPE_FIELDS, "recipe")
    private_keys = {"schema_version", "population_manifest", "assignment", "guest_plan", "activity_seed",
                    "activity_plan", "hardware_seed", "hardware"}
    if recipe["config"].get("factual_challenge") == "pilot_min.v1":
        private_keys.add("factual_challenge_plan")
    _object(private, private_keys, "private generation")
    body = {key: value for key, value in recipe.items() if key != "recipe_id"}
    if version is None or recipe.get("recipe_id") != "recipe:" + digest(body):
        raise ValueError("recipe identity or schema mismatch")
    if (private.get("schema_version") != PRIVATE_SCHEMA or digest(private) != recipe["private_sha256"]
            or digest(lock) != recipe["dependency_lock_sha256"]):
        raise ValueError("private recipe or dependency lock hash mismatch")
    if lock_version(lock) != version:
        raise ValueError("recipe and dependency lock versions differ")
    if digest(recipe["source"]) != recipe["source_sha256"]:
        raise ValueError("recipe source manifest hash mismatch")
    if source_root is not None:
        executing = (source_inventory(source_root) if version == 1
                     else source_closure(Path(source_root).parent))
        if executing != recipe["source"]:
            raise ValueError("executing generation source differs from frozen recipe")
    for item in recipe["source"]:
        path = _member(directory / "source", item["path"])
        if not path.is_file() or path.stat().st_size != item["size_bytes"] or file_digest(path) != item["sha256"]:
            raise ValueError("retained recipe source changed or missing")
    if version == 2:
        from fmb.generation import dependency_lock

        dependency_lock.validate_lock(lock)
        if recipe["pinned_inputs_sha256"] != dependency_lock.pinned_digest(lock):
            raise ValueError("recipe pinned-input digest differs from its dependency lock")
        _assignment_origin(recipe["assignment_origin"])
    if (recipe["regeneration_claim"] != REGENERATION_CLAIM
            or recipe["dependency_verification_scope"] != VERIFICATION_SCOPES[version]):
        raise ValueError("unsupported recipe regeneration or dependency claim")
    return {"directory": str(directory), "recipe": recipe, "private": private, "lock": lock}


def inspect_recipe(directory):
    return _read_recipe(directory, None)


def load_recipe(directory, *, source_root, verify_dependencies=True, tools=None):
    bundle = _read_recipe(directory, source_root)
    recipe, private, lock = bundle["recipe"], bundle["private"], bundle["lock"]
    bundle["host"] = None
    if lock_version(lock) == 1:
        validate_dependency_lock(lock, verify_bytes=verify_dependencies)
    elif verify_dependencies:
        from fmb.generation import dependency_lock

        bundle["host"] = dependency_lock.verify_lock(lock, tools=tools, cwd=Path(source_root))
    validate_resolved_inputs(recipe["config"], private["population_manifest"],
                             private["assignment"], private["guest_plan"])
    if recipe["config"]["windows_box"] != locked_box(lock)[0]:
        raise ValueError("recipe Windows box differs from dependency lock")
    if private["activity_seed"] != recipe["config"]["population_seed"] or private["hardware_seed"] != recipe["config"]["population_seed"]:
        raise ValueError("paper activity/hardware seeds must equal the population seed")
    if private["activity_plan"] != resolved_activity(
        private["activity_seed"], count=recipe["config"]["activity_count"]
    ):
        raise ValueError("recipe activity plan does not match its declared version/seed")
    if private["hardware"] != resolved_hardware(private["hardware_seed"]):
        raise ValueError("recipe hardware plan does not match its declared version/seed")
    if recipe["config"].get("factual_challenge") == "pilot_min.v1":
        expected = _factual_challenge_plan(recipe["config"], private["guest_plan"], private["population_manifest"])
        if private["factual_challenge_plan"] != expected:
            raise ValueError("pilot resolved operations differ from the frozen source and seed")
    return bundle
