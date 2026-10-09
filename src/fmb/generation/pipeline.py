import os
import subprocess
import sys
import json
import shutil
import re
import select
import secrets
import signal
import socket
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fmb.generation.population import (
    build_ground_truth,
    build_finding_reference,
    build_guest_plan,
    build_public_manifest,
    load_population_contract,
    register_population_contract,
    population_scenario_order,
    select_private_assignment,
    validate_guest_receipts,
)

from fmb.generation import recipe as recipe_support

from fmb.generation import archive_control
from fmb.generation import vmware_clone

MIN_GENERATION_RUNTIME_RESERVE_BYTES = 8 * 1024**3


EXECUTION_ORDER_LAST = ("timestomp_01",)


def execution_order(scenario_ids):
    ordered = [item for item in scenario_ids if item not in EXECUTION_ORDER_LAST]
    ordered.extend(item for item in EXECUTION_ORDER_LAST if item in scenario_ids)
    return ordered


POST_EXPORT_DIRECTORY = "post-export"
POST_EXPORT_STATE_NAME = "state.json"
POST_EXPORT_CLEANUP_NAME = "cleanup-receipt.json"
POST_EXPORT_ENTRY_SCHEMA = "generation_post_export_journal_entry.v1"
POST_EXPORT_STATE_SCHEMA = "generation_post_export_state.v1"
POST_EXPORT_ENTRY_PATTERN = re.compile(r"^(\d{2})-([a-z0-9_]+)\.json$")
POST_EXPORT_ENTRY_STATUSES = ("started", "completed", "failed")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _host_phase(name):
    started = time.monotonic_ns()

    def emit(status, error=None):
        record = {
            "utc": utc_now_iso(),
            "phase": name,
            "outcome": status,
            "elapsed_seconds": 0.0 if status == "start" else round((time.monotonic_ns() - started) / 1_000_000_000, 3),
        }
        if error is not None:
            record["error_type"] = type(error).__name__
        line = "FMB_GENERATION_PHASE " + json.dumps(record, sort_keys=True)
        try:
            print(line, flush=True)
        except (OSError, ValueError):
            pass

    emit("start")
    try:
        yield
    except BaseException as error:
        emit("error", error)
        raise
    else:
        emit("ok")


def _timeout_failure(error, command):
    failure = subprocess.CalledProcessError(124, command, output=error.output or "")
    for note in getattr(error, "__notes__", ()):
        failure.add_note(note)
    return failure


def write_json_replace(path, value, *, private=False):
    path = Path(path)
    partial = path.with_name(f".{path.name}.{secrets.token_hex(4)}.partial")
    try:
        with partial.open("x", encoding="utf-8") as stream:
            if private:
                os.chmod(partial, 0o600)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(partial, path)
    finally:
        partial.unlink(missing_ok=True)


class PostExportJournal:

    def __init__(self, directory, *, hasher, checkpoint=None):
        self.directory = Path(directory)
        self.hasher = hasher
        self.checkpoint = checkpoint
        self.boundary_hashes = {}
        self.consumed = 0
        self.entries = self.load_entries()

    def load_entries(self):
        entries = []
        if not self.directory.is_dir():
            return entries
        for path in sorted(self.directory.iterdir()):
            match = POST_EXPORT_ENTRY_PATTERN.match(path.name)
            if match is None:
                continue
            entry = recipe_support.read_json(path)
            if (not isinstance(entry, dict)
                    or entry.get("schema_version") != POST_EXPORT_ENTRY_SCHEMA
                    or entry.get("ordinal") != int(match.group(1))
                    or entry.get("name") != match.group(2)):
                raise ValueError(f"post-export journal entry does not match its file name: {path}")
            entries.append(entry)
        expected_before = {}
        for index, entry in enumerate(entries, start=1):
            ordinal, status, image = entry["ordinal"], entry.get("status"), entry.get("image")
            if ordinal != index:
                raise ValueError(f"post-export journal is missing entry {index:02d}")
            if status not in POST_EXPORT_ENTRY_STATUSES or not isinstance(image, str):
                raise ValueError(f"post-export journal entry {ordinal:02d} is malformed")
            if status != "completed" and index != len(entries):
                raise ValueError(
                    f"post-export journal entry {ordinal:02d} is {status} but later entries exist"
                )
            if image in expected_before and entry.get("sha256_before") != expected_before[image]:
                raise ValueError(
                    f"post-export journal chain is broken at entry {ordinal:02d} for {image}"
                )
            if status == "completed":
                after = entry.get("sha256_after")
                if not isinstance(after, str) or not SHA256_PATTERN.match(after):
                    raise ValueError(f"post-export journal entry {ordinal:02d} has no after hash")
                expected_before[image] = after
        return entries

    def completed_count(self):
        return sum(1 for entry in self.entries if entry["status"] == "completed")

    def journaled_hash(self, image_name, *, before_ordinal=None):
        recorded = None
        for entry in self.entries:
            if before_ordinal is not None and entry["ordinal"] >= before_ordinal:
                break
            if entry["image"] != image_name:
                continue
            if entry["status"] == "completed":
                recorded = entry["sha256_after"]
            elif entry.get("sha256_before") is not None:
                recorded = entry["sha256_before"]
        return recorded

    def verify_images(self, output_dir):
        for image_name in dict.fromkeys(entry["image"] for entry in self.entries):
            recorded = self.journaled_hash(image_name)
            path = Path(output_dir) / image_name
            if recorded is None:
                if path.exists() or path.is_symlink():
                    raise ValueError(
                        f"unsealed created image remains after interrupted post-export work: {path}; "
                        "preserve it for operator recovery or use a new output; refusing to resume"
                    )
                continue
            if not path.is_file():
                raise ValueError(f"journaled post-export image is missing: {path}")
            current = self.hasher(path)
            if current != recorded:
                raise ValueError(
                    f"image {image_name} has SHA-256 {current} but the post-export journal "
                    f"recorded {recorded}; the image differs from its journaled state, "
                    "refusing to resume"
                )
            self.boundary_hashes[image_name] = current

    def run(self, name, image, action, *, read_only=False, creates_image=False):
        self.consumed += 1
        ordinal = self.consumed
        image = Path(image)
        previous = self.entries[ordinal - 1] if ordinal <= len(self.entries) else None
        if previous is not None:
            if previous["name"] != name or previous["image"] != image.name:
                raise RuntimeError(
                    f"post-export journal entry {ordinal:02d} records {previous['name']} on "
                    f"{previous['image']} but the pipeline reached {name} on {image.name}"
                )
            if previous["status"] == "completed":
                print(f"[*] Post-export intervention {ordinal:02d} {name} already completed; skipping.")
                return None
        if creates_image:
            before = None
        else:
            before = self.boundary_hashes.get(image.name)
            if before is None:
                before = self.hasher(image)
            recorded = self.journaled_hash(image.name, before_ordinal=ordinal)
            if recorded is not None and before != recorded:
                raise ValueError(
                    f"image {image.name} has SHA-256 {before} but the post-export journal "
                    f"recorded {recorded} before intervention {ordinal:02d} {name}; "
                    "refusing to intervene"
                )
            self.boundary_hashes[image.name] = before
        attempt, previous_attempts = 1, []
        if previous is not None:
            attempt = int(previous.get("attempt", 1)) + 1
            previous_attempts = list(previous.get("previous_attempts", []))
            previous_attempts.append({key: previous.get(key) for key in
                                      ("attempt", "status", "started_utc", "finished_utc", "error")})
        entry = {
            "schema_version": POST_EXPORT_ENTRY_SCHEMA,
            "ordinal": ordinal,
            "name": name,
            "image": image.name,
            "status": "started",
            "started_utc": utc_now_iso(),
            "finished_utc": None,
            "sha256_before": before,
            "sha256_after": None,
            "read_only": bool(read_only),
            "attempt": attempt,
            "previous_attempts": previous_attempts,
        }
        path = self.directory / f"{ordinal:02d}-{name}.json"
        self.directory.mkdir(parents=True, exist_ok=True)
        write_json_replace(path, entry, private=True)
        self._record(entry)
        print(f"[*] Post-export intervention {ordinal:02d} {name} on {image.name} "
              f"(SHA-256 before: {before})")
        try:
            result = action()
            after = self.hasher(image)
            if read_only and after != before:
                raise RuntimeError(f"read-only post-export intervention {name} changed {image.name}")
            if self.checkpoint is not None:
                self.checkpoint()
        except BaseException as error:
            entry.update(status="failed", finished_utc=utc_now_iso(),
                         error=f"{type(error).__name__}: {error}")
            write_json_replace(path, entry, private=True)
            raise
        entry.update(status="completed", finished_utc=utc_now_iso(), sha256_after=after)
        write_json_replace(path, entry, private=True)
        self.boundary_hashes[image.name] = after
        print(f"[*] Post-export intervention {ordinal:02d} {name} completed (SHA-256 after: {after})")
        return result

    def _record(self, entry):
        index = entry["ordinal"] - 1
        if index < len(self.entries):
            self.entries[index] = entry
        else:
            self.entries.append(entry)


class GenerationPipeline:
    def __init__(
        self,
        provider,
        scenario,
        export_format,
        keep_vm,
        randomize_hw,
        *,
        experiment=None,
        case="positive",
        population_seed=None,
        output_root=None,
        windows_box=None,
        vmware_bridge=None,
        recipe=None,
        population_contract=None,
        assignment_entropy=None,
        activity_count=None,
        vm_work_root=None,
    ):
        if vm_work_root is not None and (recipe is None or sys.platform != "darwin"):
            raise ValueError("--vm-work-root requires frozen recipe execution on macOS")
        from fmb.generation.recipe import QEMU_BOXES

        allowed_boxes = {None, "fmb/windows-11-arm64"} | (set(QEMU_BOXES.values()) if provider == "qemu" else set())
        if (provider not in {"vmware_desktop", "qemu"} or export_format != "vmdk" or experiment != "full_scale"
                or case != "positive" or randomize_hw or keep_vm or vmware_bridge is not None
                or windows_box not in allowed_boxes
                or activity_count not in {None, 12}):
            raise ValueError("generation is restricted to the fixed paper configuration")
        windows_box = windows_box or "fmb/windows-11-arm64"
        activity_count = 12
        self.recipe_bundle = None
        if recipe is not None:
            with _host_phase("source_recipe_verification"):
                self.recipe_bundle = recipe_support.load_recipe(
                    recipe, source_root=Path(__file__).parent, verify_dependencies=False
                )
                actual_config = dict(provider=provider, experiment=experiment, case=case,
                                     population_seed=population_seed, export_format=export_format,
                                     windows_box=windows_box, vmware_bridge=vmware_bridge,
                                     randomize_hw=randomize_hw)
                frozen_config = self.recipe_bundle["recipe"]["config"]
                for key in ("clock_policy", "vmware_boot_clock_bias_minutes", "activity_count", "factual_challenge",
                            "population_contract"):
                    if key in frozen_config:
                        actual_config[key] = frozen_config[key]
                if actual_config != frozen_config:
                    raise ValueError("generation overrides conflict with frozen recipe")
                recipe_overrides = (
                    "GENERATION_ANSIBLE_TAGS", "VMRUN_TARGET", "VAGRANT_CWD", "VAGRANT_VAGRANTFILE",
                    "ANSIBLE_CONFIG", "ANSIBLE_COLLECTIONS_PATH", "ANSIBLE_COLLECTIONS_PATHS", "ANSIBLE_ROLES_PATH",
                )
                if any(os.environ.get(key) for key in recipe_overrides):
                    raise ValueError("recipe execution rejects ambient scenario/provider/dependency overrides")
                self.require_locked_interpreter()
        self.provider = provider
        self.windows_box = windows_box
        self.vmware_bridge = None
        self.case = case
        self.experiment = experiment
        if population_contract is not None and recipe is not None:
            raise ValueError("a frozen recipe rejects a population-contract override")
        custom_contract = population_contract if isinstance(population_contract, dict) else None
        if self.recipe_bundle is not None:
            custom_contract = self.recipe_bundle["recipe"]["config"].get("population_contract")
        if custom_contract is None and population_seed not in {2026091811, 2026091812, 2026091813}:
            raise ValueError("generation is restricted to the fixed paper configuration")
        if custom_contract is not None:
            self.population_contract = register_population_contract(custom_contract)
        elif population_contract is not None:
            contract_path = Path(population_contract).expanduser().resolve(strict=True)
            source_root = Path(__file__).parent.resolve()
            if (contract_path.parent != source_root
                    or not contract_path.name.startswith("populations.")
                    or contract_path.suffix != ".json"):
                raise ValueError("population contract must be a populations.*.json source file")
            self.population_contract = load_population_contract(contract_path)
        else:
            name = {2026091811: 'i1', 2026091812: 'i2', 2026091813: 'i3'}[population_seed]
            self.population_contract = load_population_contract(Path(__file__).with_name(f'populations.pilot-{name}-20260918.json'))
        if assignment_entropy is not None and (
            not isinstance(assignment_entropy, bytes) or len(assignment_entropy) < 16
        ):
            raise ValueError("assignment entropy must contain at least 16 bytes")
        self.assignment_entropy = assignment_entropy
        self.activity_count = activity_count
        self.marker_receipt_times = []
        self.clock_block = None
        contract = self.population_contract if self.recipe_bundle is None else None
        scenario_ids = (
            contract["experiments"][experiment] if contract is not None
            else population_scenario_order(self.recipe_bundle["private"]["population_manifest"])
        )
        self.scenario = ",".join(execution_order(scenario_ids))
        self.population_seed = population_seed
        self.export_format = export_format
        self.keep_vm = keep_vm
        self.randomize_hw = randomize_hw
        self.work_dir = Path(__file__).parent.absolute()
        self.vagrant_dir = self.work_dir
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        root = (
            Path(output_root).expanduser().resolve()
            if output_root is not None
            else self.work_dir / "outputs"
        )
        self.output_dir = root / self.experiment / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=False)
        self.vm_work_root = None
        self.vmware_state_identity = None
        self.vagrant_state_dir = self.output_dir / ".vagrant"
        if vm_work_root is not None:
            self.vm_work_root = Path(vm_work_root).expanduser().resolve(strict=True)
            if not self.vm_work_root.is_dir():
                raise ValueError("VM working root must be an existing directory")
            for protected in (root, self.work_dir.resolve()):
                if (self.vm_work_root.is_relative_to(protected)
                        or protected.is_relative_to(self.vm_work_root)):
                    raise ValueError("VM working root overlaps generation sources or outputs")
            self.vagrant_state_dir = self.vm_work_root / timestamp
            if self.vagrant_state_dir.exists() or self.vagrant_state_dir.is_symlink():
                raise FileExistsError("VM realization state already exists")
        self.provider_launch_attempted = False
        self.ground_truth = None
        self.native_media_binding = None
        self.public_population_manifest = None
        self.private_population_assignment = None
        self.population_guest_plan = None
        self.population_inputs_path = None
        self.post_export_journal = None
        self.post_export_system_image = None

        self._bind_host_runtime()
        if self.recipe_bundle is not None:
            recipe_support.write_private(self.output_dir / "recipe-reference.json", {
                "schema_version": "generation_recipe_reference.v1",
                "recipe_id": self.recipe_bundle["recipe"]["recipe_id"],
                "recipe_manifest_sha256": recipe_support.file_digest(
                    Path(self.recipe_bundle["directory"]) / "recipe.json"),
                "realization_id": "realization:" + secrets.token_hex(16),
                "regeneration_status": "not_independently_validated",
            })

    def require_locked_interpreter(self):
        lock = self.recipe_bundle["lock"]
        if recipe_support.lock_version(lock) == 1:
            locked_python = lock["tools"]["python"]["path"]
            if Path(sys.executable).resolve() != Path(locked_python).resolve():
                raise ValueError("recipe requires its locked Python interpreter")

    def _bind_host_runtime(self):
        self.is_macos = sys.platform == 'darwin'
        self.vagrant_cmd = self.first_available(['vagrant'])
        self.qemu_img_cmd = self.first_available(['qemu-img'])
        self.ansible_cmd = self.first_available(['ansible'])
        self.ansible_playbook_cmd = self.first_available(['ansible-playbook'])
        self.vmrun_cmd = self.resolve_vmrun()
        self.active_process = None
        self.vmware_guest_ip = None
        self.vmware_run_vmx_path = None
        self.vmware_source_media_slots = ()
        if self.recipe_bundle is not None and recipe_support.lock_version(self.recipe_bundle["lock"]) == 1:
            for tool, attribute in [('vagrant','vagrant_cmd'),('qemu-img','qemu_img_cmd'),
                                    ('ansible','ansible_cmd'),('ansible-playbook','ansible_playbook_cmd'),
                                    ('vmrun','vmrun_cmd')]:
                setattr(self,attribute,self.recipe_bundle['lock']['tools'][tool]['path'])

    def prepare_population(self):
        if self.population_guest_plan is not None:
            return self.public_population_manifest

        source_experiment = self.experiment
        seed = self.population_seed
        recipe_bundle = getattr(self, "recipe_bundle", None)
        if recipe_bundle is not None:
            private = recipe_bundle["private"]
            public_manifest = private["population_manifest"]
            private_assignment = private["assignment"]
        else:
            public_manifest = build_public_manifest(
                experiment=source_experiment,
                seed=seed,
                contract=self.population_contract,
            )
            private_assignment = select_private_assignment(
                public_manifest,
                entropy=self.assignment_entropy or secrets.token_bytes(32),
            )
        guest_plan = build_guest_plan(
            public_manifest,
            private_assignment,
            case=self.case,
        )

        if recipe_bundle is not None and guest_plan != private["guest_plan"]:
            raise ValueError("recipe guest inputs differ from frozen assignment")

        manifest_path = self.output_dir / "population_manifest.json"
        manifest_path.write_text(json.dumps(public_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        self.write_population_inputs(guest_plan)
        self.public_population_manifest = public_manifest
        self.private_population_assignment = private_assignment
        self.population_guest_plan = guest_plan
        return self.public_population_manifest

    def prepare_native_media(self):
        if (self.population_guest_plan or {}).get('native_pilot_profile') != 'pilot_min.v1':
            raise ValueError('paper generation requires the three-media native profile')
        self.pilot_media_module().prepare(self)

    def pilot_media_module(self):
        from fmb.generation import pilot_media
        return pilot_media

    def write_population_inputs(self, guest_plan):
        recipe_bundle = getattr(self, "recipe_bundle", None)
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="fmb-generation-inputs-",
            suffix=".json",
            delete=False,
        )
        try:
            payload = {"generation_inputs": guest_plan}
            if recipe_bundle is not None:
                private = recipe_bundle["private"]
                payload.update(fmb_activity_plan=private["activity_plan"],
                               fmb_expected_environment=recipe_bundle["lock"]["guest"],
                               fmb_hardware=private["hardware"])
                config = recipe_bundle["recipe"]["config"]
                factual_plan = private["factual_challenge_plan"]
                payload["fmb_factual_challenge_plan"] = factual_plan
                checkpoint_dir = self.output_dir / "factual-checkpoints"
                checkpoint_dir.mkdir(exist_ok=True)
                payload["fmb_factual_checkpoint_directory"] = str(checkpoint_dir.resolve())
                recipe_support.write_private(self.output_dir / "factual-challenge-plan.json", factual_plan)
                recipe_support.write_private(self.output_dir / "factual-challenge-population.json", factual_plan["public_manifest"])
                if "vmware_boot_clock_bias_minutes" in config:
                    payload["fmb_vmware_boot_clock_bias_minutes"] = config["vmware_boot_clock_bias_minutes"]
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.close()
        except BaseException:
            handle.close()
            Path(handle.name).unlink(missing_ok=True)
            raise
        population_inputs_path = Path(handle.name)
        population_inputs_path.chmod(0o600)
        self.population_inputs_path = population_inputs_path

    def cleanup_population_inputs(self):
        path = self.population_inputs_path
        if path is not None:
            path.unlink(missing_ok=True)
            self.population_inputs_path = None


    def first_available(self, names):
        for name in names:
            resolved = shutil.which(name)
            if resolved:
                return resolved
        return None


    def resolve_vmrun(self):
        if not self.is_macos:
            return None
        resolved = self.first_available(["vmrun", "vmrun.exe"])
        if resolved:
            return resolved

        from fmb.generation.backends import VMRUN_CANDIDATES

        for candidate in VMRUN_CANDIDATES:
            if candidate.exists():
                return str(candidate)
        return None

    def vmrun_target(self):
        if not self.is_macos:
            raise RuntimeError("vmware_desktop generation is only supported on macOS")
        return os.environ.get("VMRUN_TARGET") or "fusion"


    def prepare_env(self, env=None):
        return {**os.environ, **(env or {})}

    def resolve_command(self, cmd):
        resolved = list(cmd)
        resolved[0] = self.executed_tools().get(resolved[0], resolved[0]) or resolved[0]
        return resolved

    def run_command(self, cmd, env=None, capture_output=False, timeout_seconds=None):
        from fmb.core.owned_process import run_owned
        resolved_cmd = self.resolve_command(cmd)
        print(f"[*] Executing: {' '.join(resolved_cmd)}")
        try:
            return run_owned(resolved_cmd, cwd=self.vagrant_dir, env=self.prepare_env(env),
                             capture_output=capture_output,
                             timeout=3600 if timeout_seconds is None else timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise _timeout_failure(error, resolved_cmd) from error

    def terminate_process(self, process):
        if process is None:
            return

        if self.is_macos:
            print("[!] Terminating active subprocess before cleanup...")
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                process.wait(timeout=15)
                return
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=15)
            return

        if process.poll() is not None:
            return
        print("[!] Terminating active subprocess before cleanup...")
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)

    def run_streaming_command(self, cmd, env=None, timeout_seconds=3600):
        from fmb.core.owned_process import run_owned
        resolved_cmd = self.resolve_command(cmd)
        command_env = self.prepare_env(env)
        def line_received(line):
            print(line, end="")
            if "GENERATION_CLOCK" in line:
                self.marker_receipt_times.append((line.strip(), datetime.now(timezone.utc).isoformat()))
        try:
            return run_owned(resolved_cmd, cwd=self.vagrant_dir, env=command_env,
                             timeout=timeout_seconds, on_line=line_received).stdout
        except subprocess.TimeoutExpired as error:
            raise _timeout_failure(error, resolved_cmd) from error


    def executed_tools(self):
        return {"vagrant": self.vagrant_cmd, "qemu-img": self.qemu_img_cmd, "ansible": self.ansible_cmd,
                "ansible-playbook": self.ansible_playbook_cmd, "vmrun": self.vmrun_cmd}

    def vm_backend(self):
        backend = getattr(self, "_vm_backend", None)
        if backend is None:
            from fmb.generation.backends import backend_for

            backend = self._vm_backend = backend_for(self)
        return backend

    def preflight_checks(self):
        backend = self.vm_backend()
        backend.check_host()
        missing = [name for name, command in backend.required_tools() if not command]
        if missing:
            raise RuntimeError('missing generation tools: '+', '.join(missing))
        try:
            __import__("Evtx.Evtx")
        except ModuleNotFoundError as error:
            raise RuntimeError('generation requires python-evtx==0.8.1') from error
        backend.preflight_source()


    calculate_hash = staticmethod(recipe_support.file_digest)

    def parse_ground_truth_chunk(self, chunk):
        encoded = chunk.strip().removesuffix(",").rstrip()
        try:
            payload = json.loads(encoded)
        except json.JSONDecodeError:
            match = re.search(r"(\{.*\}|\[.*\])", encoded, re.DOTALL)
            if not match:
                raise ValueError("no JSON object or array found") from None
            payload = json.loads(match.group(1))
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise ValueError("generation receipt must be a JSON object")
        return payload

    def extract_ground_truth_chunks(self, output):
        inline = re.findall(
            r"GROUND_TRUTH_BEGIN\s+(.*?)\s+GROUND_TRUTH_END",
            output,
            re.DOTALL,
        )
        if inline:
            return inline
        chunks = []
        current = []
        collecting = False
        for line in output.splitlines():
            if "GROUND_TRUTH_BEGIN" in line:
                collecting = True
                current = []
                continue
            if "GROUND_TRUTH_END" in line and collecting:
                chunks.append("\n".join(current))
                collecting = False
                current = []
                continue
            if collecting:
                current.append(line)
        return chunks

    def capture_ground_truth(self, receipts):
        if self.population_guest_plan is None:
            raise ValueError("bounded generation inputs have not been prepared")
        if self.public_population_manifest is None:
            self.ground_truth = validate_guest_receipts(
                self.population_guest_plan,
                receipts,
                case=self.case,
            )
            return self.ground_truth
        self.ground_truth = build_ground_truth(
            self.public_population_manifest,
            self.private_population_assignment,
            receipts,
            case=self.case,
        )
        return self.ground_truth

    def ground_truth_receipts(self):
        if isinstance(self.ground_truth, list):
            return self.ground_truth
        if isinstance(self.ground_truth, dict):
            scenarios = self.ground_truth.get("scenarios", [])
            return [
                item["receipt"]
                for item in scenarios
                if isinstance(item, dict) and isinstance(item.get("receipt"), dict)
            ]
        return []

    def parse_winrm_config(self, output):
        config = {}
        for line in output.splitlines():
            match = re.match(r"^\s*([A-Za-z]+)\s*:?\s+(.+?)\s*$", line)
            if not match:
                continue
            key = match.group(1).lower()
            value = match.group(2).strip().strip('"')
            if key == "hostname":
                config["host"] = value
            elif key == "port":
                config["port"] = value
            elif key == "user":
                config["user"] = value
            elif key == "password":
                config["password"] = value
        return config


    def wait_for_tcp(self, host, port, label, timeout=30):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                with socket.create_connection((host, int(port)), timeout=2):
                    return
            except OSError as e:
                last_error = e
                time.sleep(1)

        raise TimeoutError(
            f"Timed out waiting for {label} at {host}:{port}: {last_error}"
        )

    def run_vmrun(self, args, *, capture_output=True, timeout_seconds=60):
        return self.run_command(
            ["vmrun", "-T", self.vmrun_target(), *args],
            capture_output=capture_output,
            timeout_seconds=timeout_seconds,
        )

    def vmware_provider_state(self):
        state = self.vagrant_state_dir
        identity = getattr(self, "vmware_state_identity", None)
        if (getattr(self, "vm_work_root", None) is not None and identity is None
                and (state.exists() or state.is_symlink())):
            raise ValueError("VM state is preexisting and unowned; refusing provider access")
        if identity is not None and (state.exists() or state.is_symlink()):
            actual = state.lstat()
            if state.is_symlink() or (actual.st_dev, actual.st_ino) != identity:
                raise ValueError("owned VM state identity changed; refusing provider access")
        provider = state / "machines" / "default" / "vmware_desktop"
        if getattr(self, "vm_work_root", None) is not None:
            for path in (provider, provider.parent, provider.parent.parent):
                if path.is_symlink():
                    raise ValueError("owned VM provider state must not traverse a symbolic link")
        return provider

    def prepare_vmware_clone(self):
        if getattr(self, "vm_work_root", None) is None:
            return
        state = self.vagrant_state_dir
        state.mkdir(mode=0o700, exist_ok=False)
        owned = state.lstat()
        self.vmware_state_identity = (owned.st_dev, owned.st_ino)
        vmx = self.vmware_provider_state() / "independent-apfs-clone" / "box.vmx"
        self.vmware_run_vmx_path = vmx
        locator = self.output_dir / ".vagrant"
        locator.symlink_to(state, target_is_directory=True)
        with _host_phase("independent_apfs_clone"):
            receipt = vmware_clone.clone_files(self.vagrant_box_vmx_path(), vmx)
        receipt["recipe_id"] = self.recipe_bundle["recipe"]["recipe_id"]
        receipt["dependency_lock_sha256"] = self.recipe_bundle["recipe"]["dependency_lock_sha256"]
        receipt["working_state_dir"] = str(state)
        receipt["storage_preflight"] = recipe_support.read_json(self.output_dir / "vmware-storage-preflight.json")
        vmware_clone.validate_receipt(receipt, self.recipe_bundle)
        recipe_support.write_private(self.output_dir / vmware_clone.RECEIPT_NAME, receipt)
        (self.vmware_provider_state() / "id").write_text(str(vmx), encoding="utf-8")

    def remove_vmware_owned_state(self):
        if getattr(self, "vm_work_root", None) is None:
            return
        self.vmware_provider_state()
        if self.provider_state_remaining():
            raise RuntimeError("owned VM provider state remains; refusing state removal")
        state = self.vagrant_state_dir
        if state.exists():
            if self.vmware_state_identity is None:
                raise ValueError("VM state has no ownership identity")
            shutil.rmtree(state)

    def provider_state_remaining(self):
        provider_state = self.vmware_provider_state()
        if provider_state.exists():
            return True
        vmx_path = getattr(self, "vmware_run_vmx_path", None)
        if vmx_path is None:
            return False
        return self.is_vmware_vm_running(vmx_path)

    def runtime_windows_box(self):
        return 'fmb/windows-11-arm64'

    def vagrant_box_vmx_path(self):
        recipe_bundle = getattr(self, "recipe_bundle", None)
        if recipe_bundle is not None:
            box, version = recipe_support.locked_box(recipe_bundle["lock"])
            vagrant_home = Path(os.environ.get("VAGRANT_HOME", str(Path.home() / ".vagrant.d")))
            root = vagrant_home / "boxes" / box.replace("/", "-VAGRANTSLASH-") / version
            candidates = [path.resolve() for path in root.glob("**/vmware_desktop/box.vmx")]
            expected = recipe_support.base_vmx_path(recipe_bundle["lock"])
            if candidates != [expected]:
                raise ValueError("installed Vagrant base does not match the exact recipe lock")
            return expected
        box = self.runtime_windows_box()
        vagrant_home = (
            Path(os.environ.get("VAGRANT_HOME", str(Path.home() / ".vagrant.d")))
            .expanduser()
            .resolve()
        )
        encoded_box = box.replace("/", "-VAGRANTSLASH-")
        candidates = sorted(
            (vagrant_home / "boxes" / encoded_box).glob("*/**/vmware_desktop/box.vmx")
        )
        if not candidates:
            raise RuntimeError(
                f"selected local Windows box is not installed for vmware_desktop: {box}"
            )
        return candidates[-1].resolve()

    def preflight_vmware_source(self):
        vmx_path = self.vagrant_box_vmx_path()
        locks = sorted(str(path) for path in vmx_path.parent.glob("*.lck"))
        if locks:
            raise RuntimeError(
                "selected VMware box has lock files and is not cleanly reusable: "
                + ", ".join(locks)
            )
        if self.is_vmware_vm_running(vmx_path):
            raise RuntimeError(f"selected VMware box source is running: {vmx_path}")
        vmx_text = vmx_path.read_text(encoding="utf-8", errors="replace")
        plan = getattr(self, "population_guest_plan", None)
        if plan is None and getattr(self, "recipe_bundle", None) is not None:
            plan = self.recipe_bundle["private"]["guest_plan"]
        if (plan or {}).get("native_pilot_profile") == "pilot_min.v1":
            layout = plan["scenario_inputs"]["usbstor_setupapi_discrepancy_01"]["media"]
            self.pilot_media_module().check_slots(vmx_text, layout)
        if "usbstor_setupapi_discrepancy_01" in getattr(self, "scenario", "").split(","):
            if (re.search(r"(?im)^\s*usb_xhci:8\.", vmx_text)
                    or re.search(r'(?im)^\s*usb_xhci:\d+\.port\s*=\s*"5"', vmx_text)):
                raise RuntimeError("selected VMware source occupies the native USB slot or compatible port")
        descriptors = []
        removable_media_slots = set()
        for line in vmx_text.splitlines():
            if "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            normalized_key = key.strip().casefold()
            value = raw_value.strip().strip('"')
            if "." in normalized_key:
                slot, attribute = normalized_key.rsplit(".", 1)
                if (attribute == "filename" and value.casefold().endswith(".iso")) or (
                    attribute == "devicetype" and value.casefold() == "cdrom-image"
                ):
                    removable_media_slots.add(slot)
            if not normalized_key.endswith(
                ".filename"
            ) or not value.casefold().endswith(".vmdk"):
                continue
            descriptor = Path(value).expanduser()
            if not descriptor.is_absolute():
                descriptor = vmx_path.parent / descriptor
            descriptor = descriptor.resolve()
            if descriptor not in descriptors:
                descriptors.append(descriptor)
        if not descriptors:
            raise RuntimeError(f"selected VMware box has no VMDK disk: {vmx_path}")
        for descriptor in descriptors:
            if not descriptor.is_file():
                raise RuntimeError(
                    f"selected VMware box disk descriptor is missing: {descriptor}"
                )
            descriptor_text = descriptor.read_text(encoding="utf-8", errors="replace")
            if re.search(r"(?im)^\s*parentFileNameHint\s*=", descriptor_text):
                raise RuntimeError(
                    f"selected VMware box disk has a backing parent: {descriptor}"
                )
            parent_cid = re.search(
                r'(?im)^\s*parentCID\s*=\s*"?([0-9a-f]+)"?\s*$',
                descriptor_text,
            )
            if parent_cid and parent_cid.group(1).casefold() != "ffffffff":
                raise RuntimeError(
                    f"selected VMware box disk has a non-flat parent CID: {descriptor}"
                )
            if re.search(r"-\d{6}\.vmdk$", descriptor.name, re.IGNORECASE):
                raise RuntimeError(
                    f"selected VMware box points at a snapshot disk: {descriptor}"
                )
        snapshot_count = 0
        for vmsd_path in vmx_path.parent.glob("*.vmsd"):
            vmsd_text = vmsd_path.read_text(encoding="utf-8", errors="replace")
            match = re.search(
                r'(?im)^\s*snapshot\.numSnapshots\s*=\s*"?(\d+)', vmsd_text
            )
            if match:
                snapshot_count += int(match.group(1))
            elif re.search(r"(?im)^\s*snapshot\d+\.", vmsd_text):
                snapshot_count += 1
        if snapshot_count:
            raise RuntimeError(
                f"selected VMware box has {snapshot_count} snapshot(s); a flat source is required"
            )
        self.vmware_source_media_slots = tuple(sorted(removable_media_slots))
        return {
            "box": self.runtime_windows_box(),
            "vmx_path": str(vmx_path),
            "disk_descriptors": [str(path) for path in descriptors],
            "snapshot_count": snapshot_count,
            "locks": locks,
            "removable_media_slots": list(self.vmware_source_media_slots),
        }

    def preflight_generation_storage(self, source_vmx):
        source_vmx = Path(source_vmx).expanduser().resolve()
        source_allocated_bytes = 0
        entries = (vmware_clone.source_entries(source_vmx.parent)
                   if getattr(self, "vm_work_root", None) is not None else source_vmx.parent.rglob("*"))
        for path in entries:
            if not path.is_file():
                continue
            stat = path.stat()
            blocks = getattr(stat, "st_blocks", 0)
            source_allocated_bytes += blocks * 512 if blocks else stat.st_size

        def storage_report(status, required, available):
            return {
                "schema_version": "generation_storage_preflight.v1",
                "status": status,
                "source_vmx": str(source_vmx),
                "source_allocated_bytes": source_allocated_bytes,
                "runtime_reserve_bytes": MIN_GENERATION_RUNTIME_RESERVE_BYTES,
                "required_free_bytes": required,
                "available_free_bytes": available,
                "destination_volume_path": str(self.output_dir),
            }

        if getattr(self, "vm_work_root", None) is not None:
            root = self.vm_work_root
            if (root.is_relative_to(source_vmx.parent)
                    or source_vmx.parent.is_relative_to(root)):
                raise ValueError("VM working root overlaps the protected VMware base")
            if source_vmx.stat().st_dev != root.stat().st_dev:
                raise ValueError("APFS source and VM working root must share a filesystem")
            plan = self.recipe_bundle["private"]["guest_plan"]
            media = plan["scenario_inputs"]["usbstor_setupapi_discrepancy_01"]["media"]
            capacities = [row["disk_size_bytes"] for row in media]
            if any(type(size) is not int or size <= 0 for size in capacities):
                raise ValueError("frozen native media capacities are invalid")
            auxiliary_bytes = 2 * sum(capacities) + 128 * 1024**2
            working_required = MIN_GENERATION_RUNTIME_RESERVE_BYTES
            artifact_required = source_allocated_bytes + MIN_GENERATION_RUNTIME_RESERVE_BYTES + auxiliary_bytes
            shared_volume = root.stat().st_dev == self.output_dir.stat().st_dev
            if shared_volume:
                artifact_required += working_required
            artifact_usage, working_usage = shutil.disk_usage(self.output_dir), shutil.disk_usage(root)
            passed = (artifact_usage.free >= artifact_required
                      and (shared_volume or working_usage.free >= working_required))
            report = storage_report("passed" if passed else "failed", artifact_required, artifact_usage.free)
            write_json_replace(self.output_dir / "generation_storage_preflight.json", report)
            report = {
                **report, "schema_version": "generation_vmware_storage_preflight.v1",
                "copy_method": vmware_clone.COPY_METHOD, "auxiliary_media_and_checkpoint_bytes": auxiliary_bytes,
                "shared_volume": shared_volume, "vm_work_root": str(root),
                "working_required_free_bytes": working_required,
                "working_available_free_bytes": working_usage.free,
            }
            write_json_replace(self.output_dir / "vmware-storage-preflight.json", report)
            if not passed:
                raise RuntimeError("insufficient per-volume free space for generation, export, media and reserves")
            return report
        required_free_bytes = (
            source_allocated_bytes * 2 + MIN_GENERATION_RUNTIME_RESERVE_BYTES
        )
        usage = shutil.disk_usage(self.output_dir)
        status = "passed" if usage.free >= required_free_bytes else "failed"
        report = storage_report(status, required_free_bytes, usage.free)
        write_json_replace(self.output_dir / "generation_storage_preflight.json", report)
        if status == "failed":
            raise RuntimeError(
                "insufficient free space for generation, export, and runtime reserve: "
                f"required={required_free_bytes} available={usage.free}"
            )
        return report

    def discover_current_vmware_vmx_path(self):
        provider_state = self.vmware_provider_state()
        if not provider_state.exists():
            raise FileNotFoundError(
                f"VMware provider state does not exist: {provider_state}"
            )

        vmx_candidates = sorted(
            provider_state.rglob("*.vmx"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not vmx_candidates:
            raise FileNotFoundError(f"No VMware VMX file found under: {provider_state}")
        vmx_path = vmx_candidates[0].resolve()
        self.vmware_run_vmx_path = vmx_path
        return vmx_path

    def is_vmware_vm_running(self, vmx_path):
        result = self.run_vmrun(["list"], timeout_seconds=30)
        vmx_text = str(Path(vmx_path).expanduser().resolve())
        if any(line.strip() == vmx_text for line in result.stdout.splitlines()):
            return True
        vmware_executable = str(Path(self.vmrun_cmd).resolve().with_name("vmware-vmx"))
        processes = self.run_command(
            ["/bin/ps", "-ww", "-axo", "pid=,ruid=,uid=,args="],
            capture_output=True,
            timeout_seconds=15,
        )
        for line in processes.stdout.splitlines():
            fields = line.split(None, 3)
            if len(fields) == 4:
                command = fields[3]
                if (command.startswith(vmware_executable + " ")
                        and command.endswith(" " + vmx_text)):
                    return True
        return False

    def vmware_tools_state(self, vmx_path):
        try:
            result = self.run_vmrun(
                ["checkToolsState", str(vmx_path)], timeout_seconds=30
            )
        except subprocess.CalledProcessError as e:
            return "unknown", (e.output or e.stderr or "").strip()
        output = result.stdout.strip()
        words = set(re.findall(r"[a-z]+", output.lower()))
        if "running" in words:
            return "running", output
        if "installed" in words:
            return "installed", output
        return "unknown", output

    def wait_for_vmware_tools(self, vmx_path, timeout=300):
        deadline = time.time() + timeout
        last_output = ""
        while time.time() < deadline:
            state, last_output = self.vmware_tools_state(vmx_path)
            if state == "running":
                return
            time.sleep(5)
        raise TimeoutError(
            f"Timed out waiting for VMware Tools in {vmx_path}: {last_output}"
        )

    def parse_vmware_ipv4_addresses(self, ipconfig_text):
        addresses = []
        pattern = re.compile(r"IPv4 Address[ .]*:\s*([0-9.]+)", re.IGNORECASE)
        for match in pattern.finditer(ipconfig_text):
            address = match.group(1).strip().strip(".")
            if (
                not address
                or address.startswith("127.")
                or address.startswith("169.254.")
                or address in addresses
            ):
                continue
            addresses.append(address)

        def sort_key(address):
            if address.startswith("192.168."):
                return 0
            if address.startswith("10."):
                return 1
            if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", address):
                return 2
            return 3

        return sorted(addresses, key=sort_key)

    def refresh_vmware_ipconfig(self, vmx_path):
        guest_path = r"C:\Windows\Temp\ipconfig-all.txt"
        host_path = self.output_dir / "vmware-ipconfig.txt"
        ps_command = (
            f"ipconfig /all | Out-File -Encoding utf8 '{guest_path}'; "
            "Write-Output 'fmb-ipconfig-ready'"
        )
        guest = ["-gu", "vagrant", "-gp", "vagrant"]
        self.run_vmrun([*guest, "runProgramInGuest", str(vmx_path),
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_command])
        self.run_vmrun([*guest, "copyFileFromGuestToHost", str(vmx_path), guest_path, str(host_path)])
        self.run_vmrun([*guest, "deleteFileInGuest", str(vmx_path), guest_path])
        return host_path.read_text(encoding="utf-8", errors="replace")

    def wait_for_vmware_guest_ip(self, vmx_path, timeout=360):
        state, _output = self.vmware_tools_state(vmx_path)
        if state == "installed":
            return None
        if state != "running":
            self.wait_for_vmware_tools(vmx_path, timeout=timeout)
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                ipconfig_text = self.refresh_vmware_ipconfig(vmx_path)
                for ip_address in self.parse_vmware_ipv4_addresses(ipconfig_text):
                    try:
                        self.wait_for_tcp(
                            ip_address, 5985, "VMware host-only WinRM", timeout=5
                        )
                        self.validate_vmware_ansible_winrm(ip_address)
                        print(
                            f"[*] VMware host-only WinRM reachable at {ip_address}:5985"
                        )
                        return ip_address
                    except (subprocess.CalledProcessError, OSError) as e:
                        last_error = e
            except (subprocess.CalledProcessError, OSError, TimeoutError) as e:
                last_error = e
            time.sleep(5)
        raise TimeoutError(f"Timed out waiting for VMware guest WinRM IP: {last_error}")

    def validate_vmware_ansible_winrm(self, ip_address):
        extra_vars = {
            "ansible_connection": "winrm",
            "ansible_user": "vagrant",
            "ansible_password": "vagrant",
            "ansible_port": 5985,
            "ansible_winrm_transport": "ntlm",
            "ansible_winrm_server_cert_validation": "ignore",
            "ansible_winrm_operation_timeout_sec": 120,
            "ansible_winrm_read_timeout_sec": 130,
        }
        env = {
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_FORKS": "1",
        }
        if sys.platform == "darwin":
            env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
        self.run_command(
            [
                "ansible",
                "all",
                "-i",
                f"{ip_address},",
                "-m",
                "ansible.windows.win_ping",
                "-e",
                json.dumps(extra_vars),
            ],
            env=env,
            capture_output=True,
            timeout_seconds=90,
        )

    def run_vmware_vagrant_boot(self, env_vars):
        self.prepare_vmware_clone()
        resolved_cmd = self.resolve_command(
            ["vagrant", "up", "--provider", self.provider, "--no-provision"]
        )
        print(
            f"[*] Executing: {' '.join(resolved_cmd)} (Randomize HW: {self.randomize_hw})"
        )
        self.provider_launch_attempted = True
        process = subprocess.Popen(
            resolved_cmd,
            cwd=self.vagrant_dir,
            env=self.prepare_env(env_vars),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )
        self.active_process = process
        full_output = []
        pending = b""
        boot_deadline = time.monotonic() + 3600

        def emit_output(data):
            line = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
            print(line, end="", flush=True)
            full_output.append(line)

        try:
            assert process.stdout is not None
            output_closed = False
            while True:
                return_code = process.poll()
                if return_code is not None and output_closed:
                    break
                remaining = boot_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out after 3600 seconds copying and booting the VMware VM")
                if output_closed:
                    try:
                        process.wait(timeout=min(0.2, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                    continue
                readable, _, _ = select.select([process.stdout], [], [], min(0.2, remaining))
                if not readable:
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    output_closed = True
                    if pending:
                        emit_output(pending)
                        pending = b""
                    continue
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    emit_output(line + b"\n")
            return_code = process.wait(timeout=15)
        except BaseException:
            if pending:
                emit_output(pending)
            self.terminate_process(process)
            raise
        finally:
            try:
                if process.stdout is not None:
                    process.stdout.close()
            finally:
                if self.active_process is process:
                    self.active_process = None

        try:
            vmx_path = self.discover_current_vmware_vmx_path()
        except FileNotFoundError as error:
            if return_code != 0:
                raise subprocess.CalledProcessError(
                    return_code, resolved_cmd, output="".join(full_output)
                ) from error
            raise
        if not self.is_vmware_vm_running(vmx_path):
            if return_code != 0:
                raise subprocess.CalledProcessError(
                    return_code, resolved_cmd, output="".join(full_output)
                )
            raise RuntimeError(
                f"Vagrant completed without a running VMware guest: {vmx_path}"
            )
        bridged_unavailable = False
        try:
            self.vmware_guest_ip = self.wait_for_vmware_guest_ip(vmx_path, timeout=20)
            bridged_unavailable = self.vmware_guest_ip is None
        except (subprocess.CalledProcessError, OSError, TimeoutError) as error:
            if return_code != 0:
                raise
            self.vmware_guest_ip = None
            print(
                "[!] Direct VMware guest-IP discovery failed; using Vagrant-managed "
                f"WinRM: {error}"
            )
        if bridged_unavailable and return_code != 0:
            raise RuntimeError(
                "Vagrant reported a VMware boot error and VMware Tools are installed "
                f"but not running in {vmx_path}; refusing to continue without a reachable guest"
            )
        if return_code != 0:
            print(
                "[!] Warning: Vagrant reported a VMware boot error, but the VM is running; continuing."
            )
        if self.vmware_guest_ip:
            print(
                "[*] Direct host-only WinRM is available as a fallback; "
                "continuing with run-scoped Vagrant WinRM."
            )
        elif bridged_unavailable:
            print(
                "[*] VMware Tools report installed but not running; the direct WinRM "
                "path is unavailable and the Vagrant WinRM configuration is used."
            )
        else:
            print("[*] Continuing with Ansible over Vagrant-managed WinRM.")
        return "".join(full_output)


    def get_ansible_connection(self):
        if self.provider == "qemu":
            return self.vm_backend().winrm_endpoint()
        direct_vmware_host = (
            self.vmware_guest_ip
            if self.vmware_guest_ip
            else None
        )

        try:
            result = self.run_command(
                ["vagrant", "winrm-config"],
                capture_output=True,
                env=self.vagrant_environment(),
            )
            config = self.parse_winrm_config(result.stdout)
        except subprocess.CalledProcessError:
            config = {}

        if "host" not in config:
            if direct_vmware_host:
                config["host"] = direct_vmware_host
            else:
                config["host"] = "127.0.0.1"
        config.setdefault("port", "5985")
        config.setdefault("user", "vagrant")
        config.setdefault("password", "vagrant")
        return config

    def run_ansible_playbook(self):
        connection = self.get_ansible_connection()
        extra_vars = {
            "scenario": self.scenario,
            "ansible_host": connection["host"],
            "ansible_port": int(connection["port"]),
            "ansible_user": connection["user"],
            "ansible_password": connection["password"],
            "ansible_connection": "winrm",
            "ansible_winrm_scheme": "http",
            "ansible_winrm_server_cert_validation": "ignore",
            "ansible_winrm_transport": "ntlm",
            "ansible_winrm_operation_timeout_sec": 120,
            "ansible_winrm_read_timeout_sec": 130,
        }
        if self.is_macos:
            extra_vars["fmb_generation_host_is_macos"] = True
        clock_policy = self.frozen_clock_policy()
        if clock_policy is not None:
            extra_vars["fmb_clock_policy"] = clock_policy
        connection_host = str(connection["host"]).strip().casefold()
        if connection_host in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            extra_vars["ansible_winrm_message_encryption"] = "always" if self.provider == "qemu" else "never"
        inventory = f"{connection['host']},"
        cmd = [
            "ansible-playbook",
            "-i",
            inventory,
            "ansible/playbook.yml",
            "-e",
            json.dumps(extra_vars),
        ]
        if self.population_inputs_path is not None:
            cmd.extend(["-e", f"@{self.population_inputs_path}"])
        env = None
        if self.is_macos:
            ansible_tags = os.environ.get("GENERATION_ANSIBLE_TAGS")
            if ansible_tags:
                cmd.extend(["--tags", ansible_tags])
            env = {
                "ANSIBLE_HOST_KEY_CHECKING": "False",
                "ANSIBLE_FORKS": "1",
            }
            env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
        output = self.run_streaming_command(cmd, env=env, timeout_seconds=7200 if self.provider == "qemu" else 3600)
        if getattr(self, "recipe_bundle", None) is not None:
            self.capture_recipe_runtime(output)
        return output

    CLOCK_REQUIRED_STAGES = frozenset({"manipulation_start", "manipulation_end", "pre_export"})

    def frozen_clock_policy(self):
        bundle = getattr(self, "recipe_bundle", None)
        if not bundle:
            return None
        return bundle["recipe"]["config"].get("clock_policy")

    def _marker_sections(self, output, kind):
        sections = []
        lines = output.splitlines()
        begin_times = [stamp for marker, stamp in getattr(self, "marker_receipt_times", [])
                       if f"GENERATION_{kind}_BEGIN" in marker]
        index = 0
        collecting = False
        current = []
        for line in lines:
            if f"GENERATION_{kind}_BEGIN" in line and not collecting:
                collecting = True
                current = ["GROUND_TRUTH_BEGIN"]
            elif f"GENERATION_{kind}_END" in line and collecting:
                current.append("GROUND_TRUTH_END")
                chunks = self.extract_ground_truth_chunks("\n".join(current))
                if len(chunks) != 1:
                    raise ValueError(f"malformed GENERATION_{kind} receipt section")
                stamp = begin_times[index] if index < len(begin_times) else None
                sections.append((self.parse_ground_truth_chunk(chunks[0]), stamp))
                index += 1
                collecting = False
            elif collecting:
                current.append(line)
        if collecting:
            raise ValueError(f"unterminated GENERATION_{kind} receipt section")
        return sections

    def capture_clock_receipt(self, output):
        from fmb.generation import clock_protocol as protocol
        policy = self.frozen_clock_policy()
        clock_sections = self._marker_sections(output, "CLOCK")
        checkpoint_sections = self._marker_sections(output, "CLOCKPOINT")
        if policy is None:
            if clock_sections or checkpoint_sections:
                raise ValueError("clock receipts were emitted without a frozen clock policy")
            return None
        if len(clock_sections) != 1:
            raise ValueError("exactly one guest clock receipt is required")
        receipt, _debug_received = clock_sections[0]
        fields = {"schema_version", "policy", "applied", "host_utc_iso", "guest_utc_before",
                  "guest_utc_after", "w32time_status", "calibration_measurement", "measurement"}
        expected_bias = self.recipe_bundle["recipe"]["config"].get("vmware_boot_clock_bias_minutes")
        if expected_bias is not None:
            fields.add("boot_clock")
        if (set(receipt) != fields or receipt.get("schema_version") != "generation_clock_receipt.v2"
                or receipt.get("policy") != policy):
            raise ValueError("guest clock receipt is incomplete or differs from the frozen policy")
        if (receipt.get("applied") is not (policy == "host_sync_then_service_stopped")
                or (policy == "host_sync_then_service_stopped"
                    and receipt.get("w32time_status") not in {"Stopped", "absent"})):
            raise ValueError("guest clock policy was not applied")
        calibration = receipt["calibration_measurement"]
        measurement = receipt["measurement"]
        calibration_bounds = protocol.validate_measurement(calibration)
        if expected_bias is not None:
            boot = receipt["boot_clock"]
            certain = (-protocol.TOLERANCE_SECONDS <= calibration_bounds["offset_lower_seconds"]
                       <= calibration_bounds["offset_upper_seconds"] <= protocol.TOLERANCE_SECONDS)
            expected_ticks = 0 if certain else round(-calibration_bounds["offset_seconds"] * 10_000_000)
            if (not isinstance(boot, dict)
                    or set(boot) != {"expected_rtc_bias_minutes", "observed_rtc_bias_minutes",
                                     "clock_adjustment_ticks", "forward_only"}
                    or type(boot.get("expected_rtc_bias_minutes")) is not int
                    or type(boot.get("observed_rtc_bias_minutes")) is not int
                    or boot["expected_rtc_bias_minutes"] != expected_bias
                    or boot["observed_rtc_bias_minutes"] != expected_bias
                    or boot.get("forward_only") is not True
                    or type(boot.get("clock_adjustment_ticks")) is not int
                    or boot["clock_adjustment_ticks"] != expected_ticks or expected_ticks < 0
                    or (not certain and calibration_bounds["offset_upper_seconds"] >= 0)):
                raise ValueError("guest boot clock receipt differs from the forward-only frozen bootstrap")
        initial = protocol.validate_measurement(measurement)
        if (receipt["guest_utc_before"] != calibration["guest_utc"]
                or receipt["guest_utc_after"] != measurement["guest_utc"]
                or receipt["host_utc_iso"] != calibration["host_send_utc"]):
            raise ValueError("guest clock measurement identity differs from the receipt")
        parse = protocol._instant
        guest_after = parse(receipt["guest_utc_after"])
        checkpoints = []
        previous_guest = guest_after
        max_backward = 0.0
        bounds = [initial]
        for point, _debug_stamp in checkpoint_sections:
            if set(point) != {"stage", "guest_utc", "measurement"}:
                raise ValueError("guest clock checkpoint is incomplete")
            point_measurement = point["measurement"]
            bound = protocol.validate_measurement(point_measurement)
            if point["guest_utc"] != point_measurement["guest_utc"]:
                raise ValueError("guest clock checkpoint measurement identity differs")
            guest_utc = parse(point["guest_utc"])
            max_backward = max(max_backward, (previous_guest - guest_utc).total_seconds())
            previous_guest = guest_utc
            bounds.append(bound)
            checkpoints.append({"stage": str(point["stage"]), "guest_utc": point["guest_utc"],
                                "host_received_utc": point_measurement["host_receive_utc"],
                                "offset_seconds": bound["offset_seconds"], "measurement": point_measurement})
        drift = max(row["offset_upper_seconds"] for row in bounds) - min(row["offset_lower_seconds"] for row in bounds)
        tolerance = protocol.TOLERANCE_SECONDS
        offsets = [row["offset_seconds"] for row in bounds]
        policy_met = policy == "unmanaged" or (
            max_backward <= 0.0 and drift <= tolerance
            and all(-tolerance <= row["offset_lower_seconds"] <= row["offset_upper_seconds"] <= tolerance for row in bounds)
            and self.CLOCK_REQUIRED_STAGES <= {row["stage"] for row in checkpoints})
        block = {**receipt, "host_received_utc": measurement["host_receive_utc"],
                 "offset_seconds_after": initial["offset_seconds"], "checkpoints": checkpoints,
                 "max_backward_step_seconds": max_backward, "offset_drift_seconds": drift,
                 "tolerance_seconds": tolerance, "policy_met": policy_met}
        self.clock_block = block
        if not policy_met:
            raise ValueError("guest clock policy violated: backward step "
                             f"{max_backward:.1f} s, bounded offsets {offsets} s "
                             f"(tolerance {tolerance:.0f} s); the attempt is a failure record")
        return block

    def capture_recipe_runtime(self, output):
        receipts = {}
        for kind in ["ENVIRONMENT", "ACTIVITY"]:
            sections = self._marker_sections(output, kind)
            if len(sections) != 1:
                raise ValueError(f"exactly one {kind} receipt is required")
            receipts[kind.casefold()] = sections[0][0]
        if receipts["environment"] != self.recipe_bundle["lock"]["guest"]:
            raise ValueError("guest environment receipt differs from locked values")
        activity = receipts["activity"]
        if (set(activity) != {"schema_version", "completed_count", "started_utc", "completed_utc"}
                or activity.get("schema_version") != "generation_activity_receipt.v1"
                or isinstance(activity.get("completed_count"), bool)
                or activity.get("completed_count") != len(self.recipe_bundle["private"]["activity_plan"])):
            raise ValueError("resolved activity completion receipt is incomplete")
        try:
            started = datetime.fromisoformat(activity["started_utc"].replace("Z", "+00:00"))
            completed = datetime.fromisoformat(activity["completed_utc"].replace("Z", "+00:00"))
        except (TypeError, AttributeError, ValueError) as error:
            raise ValueError("activity receipt times are invalid") from error
        if started.tzinfo is None or completed.tzinfo is None or completed < started:
            raise ValueError("activity receipt timing is invalid")
        clock = self.capture_clock_receipt(output)
        runtime_receipt = {
            "schema_version": "generation_runtime_receipt.v1",
            "recipe_id": self.recipe_bundle["recipe"]["recipe_id"], **receipts,
        }
        if clock is not None:
            runtime_receipt["clock"] = clock
        if getattr(self, "host_record", None) is not None:
            runtime_receipt["host"] = self.host_record
        recipe_support.write_private(self.output_dir / "recipe-runtime-receipt.json", runtime_receipt)

    def provision_vm(self):
        print(
            f"[*] Provisioning VM with provider: {self.provider}, scenario: {self.scenario}"
        )
        backend = self.vm_backend()
        with _host_phase(backend.boot_phase):
            output_str = backend.boot()
        with _host_phase("ansible_provisioning"):
            output_str += self.run_ansible_playbook()

        with _host_phase("host_record_validation"):
            self.capture_archive_control(output_str)

            matches = self.extract_ground_truth_chunks(output_str)
            if (getattr(self, "recipe_bundle", None)
                    and self.recipe_bundle["recipe"]["config"].get("factual_challenge")
                    in {"pilot_min.v1"}):
                from fmb.generation.factual_challenge import validate_receipt
                sections = self._marker_sections(output_str, "FACTUAL")
                if len(sections) != 1:
                    raise ValueError("factual challenge requires one complete native receipt")
                plan = recipe_support.read_json(self.output_dir / "factual-challenge-plan.json")
                validate_receipt(plan, sections[0][0])
                if plan.get("profile") == "pilot_min.v1":
                    from fmb.generation.pilot_profile import validate_materialization
                    initial = self._marker_sections(output_str, "PILOTMATERIALIZE")
                    if len(initial) != 1:
                        raise ValueError("pilot requires one complete initial materialization receipt")
                    validate_materialization(plan, initial[0][0], sections[0][0])
                    recipe_support.write_private(self.output_dir / "pilot-materialization.json", initial[0][0])
                recipe_support.write_private(self.output_dir / "factual-challenge-receipt.json", sections[0][0])
            receipts = []
            for match in matches:
                try:
                    receipts.append(self.parse_ground_truth_chunk(match))
                except Exception as error:
                    if self.population_guest_plan is not None:
                        raise RuntimeError(
                            "failed to parse a bounded generation receipt"
                        ) from error
                    print(
                        "[!] Warning: Failed to parse a captured Ground Truth JSON "
                        f"chunk: {error}"
                    )
            if receipts:
                self.capture_ground_truth(receipts)
                native = [row["native_binding"] for row in receipts if row.get("scenario_id") == "usbstor_setupapi_discrepancy_01" and "native_binding" in row]
                if (self.population_guest_plan or {}).get("native_pilot_profile") == "pilot_min.v1":
                    native = [row["native_bindings"] for row in receipts
                               if row.get("scenario_id") == "usbstor_setupapi_discrepancy_01"]
                if native:
                    if len(native) != 1:
                        raise ValueError("native media binding is ambiguous")
                    self.native_media_binding = native[0]
                print(f"\n[+] Successfully captured Ground Truth for: {self.scenario}")
            elif self.population_guest_plan is not None:
                raise RuntimeError(
                    "bounded generation emitted no verified scenario receipts"
                )

    def archive_control_paths(self):
        plan = getattr(self, "population_guest_plan", None) or {}
        return plan.get("scenario_inputs", {}).get("timestomp_01", {}).get("population_paths")

    def capture_archive_control(self, output):
        paths = self.archive_control_paths()
        if paths is None:
            return
        receipt = archive_control.extract_receipt(output, self.parse_ground_truth_chunk)
        planned = self.population_guest_plan["scenario_inputs"]["timestomp_01"]
        archive_control.validate_receipt(receipt, paths, restore_paths=planned.get("archive_restore_paths"))
        recipe_support.write_private(self.output_dir / archive_control.RECEIPT_NAME, receipt)

    def vagrant_environment(self):
        if getattr(self, "vm_work_root", None) is not None:
            self.vmware_provider_state()
        env_vars = {"VAGRANT_DOTFILE_PATH": str(self.vagrant_state_dir)}
        if getattr(self, "native_media_sources", None):
            env_vars["FMB_NATIVE_MEDIA_SOURCES"] = json.dumps([
                {**row, "path": str(row["path"])} for row in self.native_media_sources
            ], sort_keys=True)
        recipe_bundle = getattr(self, "recipe_bundle", None)
        if recipe_bundle is not None:
            env_vars["FMB_BOX_VERSION"] = recipe_support.locked_box(recipe_bundle["lock"])[1]
            env_vars["FMB_RECIPE_MODE"] = "1"
        removable_media_slots = tuple(getattr(self, "vmware_source_media_slots", ()))
        if removable_media_slots:
            env_vars["FMB_VMWARE_DISABLE_MEDIA_SLOTS"] = ",".join(removable_media_slots)
        if self.population_inputs_path is not None:
            env_vars["FMB_GENERATION_INPUTS_PATH"] = str(self.population_inputs_path)
        return env_vars

    def halt_vm(self):
        print("[*] Halting VM for forensic consistency...")
        vmx_path = self.discover_current_vmware_vmx_path()
        try:
            self.run_vmrun(["stop", str(vmx_path), "soft"], timeout_seconds=240)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                "soft VMware halt failed; refusing forensic export from an uncleanly stopped guest"
            ) from error

    def discover_disk_path(self):
        return self.vmware_disk_from_vmx(self.vmware_run_vmx_path)

    def vmware_disk_from_vmx(self, vmx_path):
        disk_pattern = re.compile(
            r'^\s*(?:nvme|scsi|sata|ide)\d+:\d+\.fileName\s*=\s*"([^"]+\.vmdk)"',
            re.IGNORECASE,
        )
        for line in vmx_path.read_text(errors="replace").splitlines():
            match = disk_pattern.match(line)
            if not match:
                continue
            disk_path = Path(match.group(1)).expanduser()
            if not disk_path.is_absolute():
                disk_path = vmx_path.parent / disk_path
            if disk_path.exists():
                return disk_path
            raise FileNotFoundError(f"VMware VMX disk does not exist: {disk_path}")

        vmdks = sorted(vmx_path.parent.glob("*.vmdk"))
        descriptor_disks = [
            path
            for path in vmdks
            if not re.search(r"-s\d+\.vmdk$", path.name, re.IGNORECASE)
        ]
        if len(descriptor_disks) == 1:
            return descriptor_disks[0]
        if len(vmdks) == 1:
            return vmdks[0]
        if descriptor_disks or vmdks:
            candidates = descriptor_disks or vmdks
            raise Exception(
                "VMware VMX has no explicit disk line and disk fallback is ambiguous: "
                + ", ".join(str(path) for path in candidates)
            )
        return None

    def convert_and_publish(self, source_disk, final_path, output_format):
        final_path = Path(final_path)
        if final_path.exists():
            raise FileExistsError(
                f"refusing to overwrite generated image: {final_path}"
            )
        partial_path = final_path.with_name(
            f"{final_path.name}.{secrets.token_hex(4)}.partial"
        )
        try:
            self.run_command(
                [
                    "qemu-img",
                    "convert",
                    "-O",
                    output_format,
                    str(source_disk),
                    str(partial_path),
                ]
            )
            if not partial_path.is_file() or partial_path.stat().st_size <= 0:
                raise RuntimeError(
                    f"converted image is missing or empty: {partial_path}"
                )
            self.run_command(
                ["qemu-img", "info", "--output=json", str(partial_path)],
                capture_output=True,
            )
            partial_path.replace(final_path)
            return final_path
        finally:
            if partial_path.exists():
                partial_path.unlink()

    def native_surface_module(self):
        from fmb.generation import ntfs_surface_injection as native
        return native

    def bind_post_export_receipt(self, scenario_id, receipt):
        for row in self.ground_truth_receipts():
            if row.get("scenario_id") == scenario_id:
                row["post_export_intervention"] = receipt
                return receipt
        raise ValueError(f"no verified guest receipt binds the {scenario_id} intervention")

    def apply_post_export_interventions(self, image_path):
        inputs = (self.population_guest_plan or {}).get("scenario_inputs", {})
        relevant = {
            "ntfs_allocation_01", "event_record_sequence_gap_01", "directory_cleaning_i30_01",
        }.intersection(inputs)
        if not relevant:
            return
        if self.export_format != "vmdk":
            raise ValueError("native post-export scenarios require standalone VMDK evidence")
        receipts_by_scenario = {row.get("scenario_id"): row for row in self.ground_truth_receipts()}
        if not relevant.issubset(receipts_by_scenario):
            raise ValueError("post-export interventions require every verified guest preparation receipt")
        image_path = Path(image_path)
        if "ntfs_allocation_01" in relevant:
            self.run_post_export_intervention(
                "ntfs_allocation_01", image_path,
                lambda: self.intervene_ntfs_allocation(image_path),
                read_only=not inputs["ntfs_allocation_01"]["operation_refs"],
            )
        if "event_record_sequence_gap_01" in relevant:
            self.run_post_export_intervention(
                "event_record_sequence_gap_01", image_path,
                lambda: self.intervene_event_record_sequence(image_path),
                read_only=not inputs["event_record_sequence_gap_01"]["operation_refs"],
            )
        if "directory_cleaning_i30_01" in relevant and inputs["directory_cleaning_i30_01"]["operation_refs"]:
            self.run_post_export_intervention(
                "directory_cleaning_i30_01", image_path,
                lambda: self.verify_directory_cleaning_residue(image_path),
                read_only=True,
            )
        if (self.population_guest_plan or {}).get("native_pilot_profile") == "pilot_min.v1":
            self.run_post_export_intervention("pilot_i30_retention", image_path,
                lambda: self.verify_pilot_directory_residue(image_path), read_only=True)

    def verify_pilot_directory_residue(self, image_path):
        native = self.native_surface_module()
        receipt = recipe_support.read_json(self.output_dir / "factual-challenge-receipt.json")
        rows = [row for row in receipt["members"] if row["operation_class"] == "recreated_children"]
        plan = recipe_support.read_json(self.output_dir / "factual-challenge-plan.json")
        planned = [m for m in plan["members"] if m["operation_class"] == "recreated_children"]
        if len(rows) != len(planned) or len(rows) > 1:
            raise ValueError("pilot must retain exactly its planned recreated-child construction")
        if not rows:
            result = {"schema_version": "i30_residue_postcondition.v1", "scenario_id": "directory_cleaning_i30_01",
                      "directories": [], "image_modified": False, "postcondition_verified": True,
                      "not_applicable": "the frozen pilot parameters plan no recreated-child construction"}
            write_json_replace(self.output_dir / "pilot-i30-retention.json", result, private=True)
            return result
        row = rows[0]
        child = row["child_transition"]["before"]
        bits = int(child["file_reference"].split(":")[1], 16)
        result = native.verify_i30_residue(Path(image_path), [row["path"]],
            [child["path"].rsplit("\\", 1)[-1]],
            removed_references={row["path"]: (bits & ((1 << 48) - 1), bits >> 48)})
        write_json_replace(self.output_dir / "pilot-i30-retention.json", result, private=True)
        return result

    def intervene_ntfs_allocation(self, image_path):
        native = self.native_surface_module()
        planned = self.population_guest_plan["scenario_inputs"]["ntfs_allocation_01"]
        receipts_by_scenario = {row.get("scenario_id"): row for row in self.ground_truth_receipts()}
        allocation_receipt = native.mutate_allocation_headers(
            Path(image_path), list(planned["operation_refs"]),
            validation_paths=list(planned["population_paths"]),
        )
        native_by_path = {row["path"].casefold(): row for row in allocation_receipt["validated_candidates"]}
        cluster_size = allocation_receipt["geometry"]["bytes_per_cluster"]
        close_controls = {row["path"].casefold(): row for row in
                          receipts_by_scenario["ntfs_allocation_01"]["preallocation_close_controls"]}
        allocation_receipt["preallocation_close_controls"] = []
        for control in planned["storage_cases"]:
            actual = native_by_path.get(control["path"].casefold(), {})
            mode, length = control["storage_mode"], control["logical_length"]
            if actual.get("logical_size") != length:
                raise ValueError("native allocation control logical length does not match preparation")
            if mode == "resident":
                valid = actual.get("resident_status") == "resident"
            else:
                valid = (actual.get("resident_status") == "nonresident"
                         and actual.get("is_sparse") is False
                         and actual.get("is_compressed") is False
                         and actual.get("runlist_complete") is True)
                if mode == "preallocation_request_then_close":
                    closed = close_controls.get(control["path"].casefold(), {})
                    rounded = ((length + cluster_size - 1) // cluster_size) * cluster_size
                    valid = (valid and actual.get("allocated_size") == rounded
                             and actual.get("allocated_cluster_count") * cluster_size == rounded
                             and closed.get("closed_allocation_bytes") == rounded
                             and closed.get("closed_eof_bytes") == length)
                    if valid:
                        content = native.transform_native_file(
                            Path(image_path), control["path"],
                            lambda data: (data, {"operation": "read_only_preallocation_close_content_check"}),
                        )
                        valid = (content["sha256_before"] == closed.get("content_sha256")
                                 and content["sha256_after"] == content["sha256_before"]
                                 and content["size_bytes"] == length and content["written_ranges"] == [])
                        allocation_receipt["preallocation_close_controls"].append({
                            "path": control["path"], "exported_allocated_bytes": rounded,
                            "exported_eof_bytes": length, "content_sha256": content["sha256_before"],
                            "native_open_close_receipt_verified": True, "content_readback": content,
                        })
            if not valid:
                raise ValueError("native allocation control storage mode was not realized")
        return self.bind_post_export_receipt("ntfs_allocation_01", allocation_receipt)

    def intervene_event_record_sequence(self, image_path):
        native = self.native_surface_module()
        planned = self.population_guest_plan["scenario_inputs"]["event_record_sequence_gap_01"]
        from fmb.generation.event_sequence_injection import mutate_evtx_bytes
        def recorded_mutation(data):
            self.retain_factual_checkpoint("checkpoint-02.evtx", data)
            if planned.get("native_pilot_profile") == "pilot_min.v1":
                from fmb.generation.pilot_profile import validate_log_a_source
                validate_log_a_source(data)
            return mutate_evtx_bytes(data)
        if planned["operation_refs"]:
            receipt = native.transform_native_file(
                Path(image_path), r"C:\Windows\System32\winevt\Logs\Security.evtx", recorded_mutation
            )
        else:
            def verify_contiguous(data):
                from fmb.index.scanners.evtx_sequence import retained_record_ids
                identifiers = retained_record_ids(data)
                if len(identifiers) < 3 or any(b != a + 1 for a, b in zip(identifiers, identifiers[1:])):
                    raise ValueError("benign event sequence is not a contiguous retained population")
                return data, {"schema_version": "generation_event_sequence_control.v1",
                              "retained_record_count": len(identifiers), "internal_gap_count": 0,
                              "postcondition_verified": True}
            receipt = native.transform_native_file(
                Path(image_path), r"C:\Windows\System32\winevt\Logs\Security.evtx", verify_contiguous
            )
        return self.bind_post_export_receipt("event_record_sequence_gap_01", receipt)

    def verify_directory_cleaning_residue(self, image_path):
        native = self.native_surface_module()
        planned = self.population_guest_plan["scenario_inputs"]["directory_cleaning_i30_01"]
        removed_names = [planned["leaf_names"][index] for index in planned["delete_leaf_indexes"]]
        receipt = native.verify_i30_residue(
            Path(image_path), list(planned["operation_refs"]), removed_names
        )
        return self.bind_post_export_receipt("directory_cleaning_i30_01", receipt)

    def logfile_retention_planned(self):
        inputs = (self.population_guest_plan or {}).get("scenario_inputs", {})
        planned = inputs.get("timestomp_01")
        if not planned or not (
            planned.get("operation_refs")
            or planned.get("require_archive_retention") is True
        ):
            return None
        if getattr(self, "ground_truth", None) is None:
            return None
        return planned

    def check_logfile_retention(self, image_path):
        planned = self.logfile_retention_planned()
        if planned is None:
            return None
        require = bool(planned.get("require_logfile_retention", False) or planned.get("require_archive_retention", False))
        receipts = {row.get("scenario_id"): row for row in self.ground_truth_receipts()}
        receipt = receipts.get("timestomp_01") or {}
        instances = receipt.get("instances") or []
        if len(instances) != len(planned["operation_refs"]):
            if require:
                raise ValueError("timestamp receipt instances do not match the planned operations")
            return None
        targets = [
            {
                "path": path,
                "assigned_timestamp": instance.get("assigned_timestamp"),
                "original_creation_utc": instance.get("original_creation_utc"),
                **({"original_modified_utc": instance["original_modified_utc"]}
                   if "original_modified_utc" in instance else {}),
            }
            for path, instance in zip(planned["operation_refs"], instances, strict=True)
        ]
        if planned.get("require_archive_retention") is True:
            control = recipe_support.read_json(self.output_dir / archive_control.RECEIPT_NAME)
            archive_control.validate_receipt(control, planned["population_paths"], restore_paths=planned.get("archive_restore_paths"))
            manipulated = {str(path).casefold() for path in planned["operation_refs"]}
            targets.extend({"path": row["path"], "assigned_timestamp": row["write_after_utc"],
                            "original_creation_utc": row["creation_before_utc"],
                            "original_modified_utc": row["write_before_utc"],
                            "modified_only": True}
                           for row in control["records"] if row.get("restored", True)
                           and row["path"].casefold() not in manipulated)
        if (self.population_guest_plan or {}).get("native_pilot_profile") == "pilot_min.v1":
            from fmb.core.ntfs_time import filetime_to_utc_iso
            supplement = recipe_support.read_json(self.output_dir / "factual-challenge-receipt.json")
            for row in supplement["members"]:
                if row["question_id"] == "BQ-TIME-01" and row["operation_class"] == "same_year":
                    fields = {"created": "creation_filetime", "modified": "modified_filetime"}
                    targets.append({"path": row["path"], "expected_transition": {
                        side: {name: filetime_to_utc_iso(row[native_side][field]) for name, field in fields.items()}
                        for side, native_side in (("old", "before"), ("new", "after"))
                    }})
        from fmb.generation import logfile_retention as module
        clock = getattr(self, "clock_block", None)
        if clock is None:
            runtime_path = self.output_dir / "recipe-runtime-receipt.json"
            if runtime_path.is_file():
                clock = json.loads(runtime_path.read_text(encoding="utf-8")).get("clock")
        timeline = None
        if isinstance(clock, dict):
            timeline = {
                row["stage"]: {"guest_utc": row["guest_utc"], "host_received_utc": row["host_received_utc"]}
                for row in clock.get("checkpoints", [])
            }
        result = module.check_logfile_retention(
            Path(image_path),
            targets=targets,
            output_dir=self.output_dir,
            require=require,
            timeline=timeline,
        )
        receipt["logfile_retention"] = {
            "status": result["status"],
            "targets": [
                {key: row.get(key) for key in ("retained", "transition_lsn", "committed", "candidate_update_count")}
                for row in result["targets"]
            ],
        }
        self.attach_runtime_receipt_block("logfile_retention", result)
        print(f"[*] $LogFile retention check: {result['status']}")
        return result

    def attach_runtime_receipt_block(self, name, block):
        path = self.output_dir / "recipe-runtime-receipt.json"
        if not path.is_file():
            return
        runtime_receipt = json.loads(path.read_text(encoding="utf-8"))
        runtime_receipt[name] = block
        write_json_replace(path, runtime_receipt, private=True)


    def retain_factual_checkpoint(self, name, data):
        if not (getattr(self, "recipe_bundle", None) and self.recipe_bundle["recipe"]["config"].get("factual_challenge")):
            return
        if name not in {"checkpoint-02.evtx", "checkpoint-03.log", "checkpoint-04.vmdk"}:
            raise ValueError("unregistered factual checkpoint")
        path = self.output_dir / "factual-checkpoints" / name
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError("existing native checkpoint differs; retain failed attempt")
        else:
            with path.open("xb") as stream:
                stream.write(data)

    def extract_disk(self, source_disk):
        output = self.output_dir / 'full_scale.vmdk'
        image = self.convert_and_publish(source_disk, output, 'vmdk')
        return self.complete_export(image)

    def complete_export(self, system_image):
        system_image = Path(system_image)
        final_artifacts = [system_image]
        journal = self.begin_post_export(system_image)
        self.apply_post_export_interventions(system_image)
        if self.logfile_retention_planned() is not None:
            self.run_post_export_intervention(
                "logfile_retention", system_image,
                lambda: self.check_logfile_retention(system_image), read_only=True,
            )
        if getattr(self, "native_media_sources", None):
            final_artifacts.extend(self.pilot_media_module().export(self, system_image))

        gt_path = self.output_dir / "ground_truth.json"
        if self.ground_truth:
            with open(gt_path, "w") as f:
                json.dump(self.ground_truth, f, indent=4)
            print(f"[*] Ground Truth written to: {gt_path}")

        def artifact_row(path, name=None):
            return {"file": name or path.name, "sha256": self.calculate_hash(path),
                    "size_bytes": path.stat().st_size}

        manifest = {
            "schema_version": "generation_manifest.v1",
            "scenario": self.scenario,
            "artifacts": [],
        }
        manifest["experiment"] = self.experiment
        for artifact in final_artifacts:
            h = journal.boundary_hashes.get(artifact.name)
            if h is None:
                print(f"[*] Calculating SHA-256 hash for {artifact.name}...")
                h = self.calculate_hash(artifact)
            else:
                print(f"[*] Reusing the journaled SHA-256 hash for {artifact.name}")
            manifest["artifacts"].append(
                {
                    "file": artifact.name,
                    "sha256": h,
                    "size_bytes": artifact.stat().st_size,
                }
            )
        population_path = self.output_dir / "population_manifest.json"
        if self.public_population_manifest is not None:
            if not population_path.is_file():
                raise RuntimeError(
                    "population manifest is missing from fmb.generation output"
                )
            manifest["artifacts"].append(artifact_row(population_path))

        control = self.output_dir / archive_control.RECEIPT_NAME
        if self.archive_control_paths() is not None:
            if not control.is_file() or control.is_symlink():
                raise ValueError("archive restore control receipt is missing before publication")
            archive_control.validate_receipt(
                recipe_support.read_json(control), self.archive_control_paths(),
                restore_paths=(self.population_guest_plan or {}).get("scenario_inputs", {}).get("timestomp_01", {}).get("archive_restore_paths")
            )
            if (self.logfile_retention_planned() or {}).get("require_archive_retention") is True:
                finding_reference = build_finding_reference(self.public_population_manifest,
                    self.ground_truth, recipe_support.read_json(control))
                (self.output_dir / "finding_reference.json").write_text(
                    json.dumps(finding_reference, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                manifest["finding_reference"] = "finding_reference.json"
                manifest["finding_reference_sha256"] = self.calculate_hash(self.output_dir / "finding_reference.json")
            manifest["artifacts"].append(artifact_row(control))

        receipt_names = ["recipe-reference.json", "recipe-runtime-receipt.json"]
        clone_path = self.output_dir / vmware_clone.RECEIPT_NAME
        if clone_path.exists() or clone_path.is_symlink():
            if not clone_path.is_file() or clone_path.is_symlink():
                raise ValueError("VMware clone receipt must be a regular retained artifact")
            if getattr(self, "recipe_bundle", None) is None:
                raise ValueError("VMware clone receipt requires a frozen recipe binding")
            vmware_clone.validate_receipt(recipe_support.read_json(clone_path), self.recipe_bundle)
            receipt_names.append(vmware_clone.RECEIPT_NAME)
        elif getattr(self, "vm_work_root", None) is not None or (self.output_dir / ".vagrant").is_symlink():
            raise ValueError("VMware clone receipt is missing before publication")
        if (self.population_guest_plan or {}).get("native_pilot_profile") == "pilot_min.v1":
            receipt_names.extend(("pilot-i30-retention.json", "pilot-materialization.json"))
        if getattr(self, "recipe_bundle", None) and self.recipe_bundle["recipe"]["config"].get("factual_challenge"):
            from fmb.generation.factual_challenge import validate_receipt
            plan_path = self.output_dir / "factual-challenge-plan.json"
            receipt_path = self.output_dir / "factual-challenge-receipt.json"
            plan = recipe_support.read_json(plan_path)
            validate_receipt(plan, recipe_support.read_json(receipt_path))
            public_path = self.output_dir / "factual-challenge-population.json"
            if recipe_support.read_json(public_path) != plan["public_manifest"]:
                raise ValueError("supplemental public population differs from frozen plan")
            receipt_names.extend((public_path.name, receipt_path.name, plan_path.name))
            for checkpoint in ("checkpoint-01.evtx", "checkpoint-02.evtx", "checkpoint-03.log", "checkpoint-04.vmdk"):
                path = self.output_dir / "factual-checkpoints" / checkpoint
                if not path.is_file() or path.is_symlink():
                    raise ValueError("scheduled native checkpoint is missing")
                manifest["artifacts"].append(artifact_row(path, "factual-checkpoints/" + checkpoint))
        for recipe_name in receipt_names:
            recipe_reference = self.output_dir / recipe_name
            if recipe_reference.is_file():
                manifest["artifacts"].append(artifact_row(recipe_reference))
        if gt_path.exists():
            manifest["ground_truth"] = "ground_truth.json"
            manifest["ground_truth_sha256"] = self.calculate_hash(gt_path)
        return manifest

    def publish_manifest(self, manifest, cleanup_receipt):
        expected_cleanup_fields = {
            "schema_version",
            "provider",
            "status",
            "provider_state_remaining",
        }
        if (
            not isinstance(cleanup_receipt, dict)
            or set(cleanup_receipt) != expected_cleanup_fields
            or cleanup_receipt.get("schema_version") != "generation_cleanup.v1"
            or cleanup_receipt.get("provider") != self.provider
            or cleanup_receipt.get("status") not in {"destroyed", "retained"}
            or not isinstance(cleanup_receipt.get("provider_state_remaining"), bool)
            or (
                (cleanup_receipt["status"] == "retained")
                != cleanup_receipt["provider_state_remaining"]
            )
        ):
            raise ValueError("generation cleanup receipt is invalid")
        if not isinstance(manifest, dict):
            raise ValueError("generation manifest is unavailable")

        manifest_path = self.output_dir / "manifest.json"
        if manifest_path.exists():
            raise FileExistsError(
                f"refusing to overwrite generation manifest: {manifest_path}"
            )
        published = {**manifest, "cleanup": dict(cleanup_receipt)}
        partial_path = manifest_path.with_name(
            f".{manifest_path.name}.{secrets.token_hex(4)}.partial"
        )
        try:
            partial_path.write_text(
                json.dumps(published, indent=4) + "\n",
                encoding="utf-8",
            )
            partial_path.replace(manifest_path)
        finally:
            partial_path.unlink(missing_ok=True)
        print(f"[*] Manifest created at: {manifest_path}")
        return published


    def cleanup_vmware_direct(self):
        if not self.is_macos:
            return False

        provider_state = self.vmware_provider_state()
        vmx_paths = {path.resolve() for path in provider_state.rglob("*.vmx")} if provider_state.exists() else set()
        tracked_vmx = getattr(self, "vmware_run_vmx_path", None)
        if tracked_vmx is not None:
            tracked_vmx = Path(tracked_vmx).expanduser().resolve()
            if not tracked_vmx.is_relative_to(provider_state.resolve()):
                print("[!] Warning: tracked VMware VM is outside owned provider state.")
                return False
            vmx_paths.add(tracked_vmx)
        if not provider_state.exists() and not vmx_paths:
            return False

        if any(not path.is_relative_to(provider_state.resolve()) for path in vmx_paths):
            print("[!] Warning: VMware VMX path is outside owned provider state.")
            return False
        for vmx_path in sorted(vmx_paths):
            try:
                if self.is_vmware_vm_running(vmx_path):
                    self.run_vmrun(["stop", str(vmx_path), "hard"], timeout_seconds=120)
                    if self.is_vmware_vm_running(vmx_path):
                        print(f"[!] Warning: VMware VM remains running after direct stop: {vmx_path}")
                        return False
            except (subprocess.CalledProcessError, TimeoutError, OSError) as e:
                print(f"[!] Warning: VMware direct stop could not be confirmed for {vmx_path}: {e}")
                return False

        if not provider_state.exists():
            return True
        try:
            shutil.rmtree(provider_state)
            print("[*] VMware VM removed via direct cleanup fallback.")
            return True
        except OSError as e:
            print(f"[!] Warning: VMware direct cleanup failed: {e}")
            return False


    def destroy_vm(self):
        self.terminate_process(self.active_process)
        print("[*] Strict Cleanup: Destroying VM to ensure next run is fresh...")
        if self.provider == "qemu":
            return self.vm_backend().destroy()

        last_error = None
        for attempt in range(1, 4):
            try:
                if self.is_macos:
                    self.run_command(
                        ["vagrant", "destroy", "-f"],
                        timeout_seconds=120,
                        env=self.vagrant_environment(),
                    )
                else:
                    self.run_command(
                        ["vagrant", "destroy", "-f"],
                        env=self.vagrant_environment(),
                    )
                if (
                    self.is_macos
                    and self.provider_state_remaining()
                ):
                    direct_cleanup_succeeded = self.cleanup_vmware_direct()
                    if (
                        not direct_cleanup_succeeded
                        or self.provider_state_remaining()
                    ):
                        raise RuntimeError(
                            "VMware provider state remains after vagrant destroy"
                        )
                elif self.provider_state_remaining():
                    raise RuntimeError(
                        f"{self.provider} provider state remains after vagrant destroy"
                    )
                return True
            except subprocess.CalledProcessError as e:
                last_error = e
                print(
                    f"[!] Warning: VM cleanup attempt {attempt} failed with exit code {e.returncode}"
                )
                self.terminate_process(self.active_process)
                time.sleep(5)

        if self.cleanup_vmware_direct():
            if self.provider_state_remaining():
                raise RuntimeError(
                    "VMware provider state remains after direct cleanup"
                )
            return True

        if last_error:
            raise RuntimeError(
                "VM cleanup failed after retries with exit code "
                f"{last_error.returncode}"
            ) from last_error
        raise RuntimeError("VM cleanup failed after all available cleanup paths")

    def no_vm_launch_or_state(self):
        return (
            getattr(self, "provider_launch_attempted", None) is False
            and getattr(self, "active_process", None) is None
            and getattr(self, "vmware_run_vmx_path", None) is None
            and ((getattr(self, "vm_work_root", None) is not None
                  and getattr(self, "vmware_state_identity", None) is None)
                 or (not self.vagrant_state_dir.exists() and not self.vagrant_state_dir.is_symlink()))
        )

    def cleanup(self):
        status = None
        cleanup_error = None
        try:
            if self.no_vm_launch_or_state():
                print("[*] No VM launch was attempted and no realization state exists; skipping VM cleanup.")
            else:
                recipe_bundle = getattr(self, "recipe_bundle", None)
                if recipe_bundle is not None and (
                    self.population_inputs_path is None
                    or not self.population_inputs_path.exists()
                ):
                    try:
                        self.write_population_inputs(recipe_bundle["private"]["guest_plan"])
                    except OSError as input_error:
                        try:
                            self.terminate_process(self.active_process)
                            if not self.is_macos or self.provider != "vmware_desktop":
                                raise RuntimeError("direct cleanup is unavailable for this provider")
                            if (self.cleanup_vmware_direct() is not True
                                    or self.provider_state_remaining()):
                                raise RuntimeError("direct VMware cleanup did not confirm destruction")
                            self.remove_vmware_owned_state()
                        except Exception as direct_error:
                            input_error.add_note(
                                "direct cleanup after private-input recovery failure could not be confirmed: "
                                + str(direct_error)
                            )
                        else:
                            input_error.add_note(
                                "direct VMware cleanup confirmed destruction after private-input recovery failure"
                            )
                        raise
                if self.destroy_vm() is not True:
                    raise RuntimeError("VM cleanup did not confirm destruction")
                self.remove_vmware_owned_state()
                status = "destroyed"
        except BaseException as error:
            cleanup_error = error
            if self.population_inputs_path is not None:
                error.add_note(
                    "private host-only generation inputs retained for VM cleanup recovery: "
                    + str(self.population_inputs_path)
                )
        else:
            try:
                self.cleanup_population_inputs()
            except BaseException as error:
                cleanup_error = error

        if cleanup_error is not None:
            raise cleanup_error
        if status is None:
            return None
        return {
            "schema_version": "generation_cleanup.v1",
            "provider": self.provider,
            "status": status,
            "provider_state_remaining": False,
        }

    def run(self):
        pipeline_error = None
        generation_manifest = None
        try:
            if getattr(self, "recipe_bundle", None) is not None:
                with _host_phase("source_recipe_verification"):
                    verified = recipe_support.load_recipe(
                        self.recipe_bundle["directory"], source_root=self.work_dir, tools=self.executed_tools())
                    self.host_record = verified["host"]
            with _host_phase("preflight"):
                self.preflight_checks()
            with _host_phase("population_media"):
                self.prepare_population()
                self.prepare_native_media()
            self.provision_vm()
            with _host_phase("soft_halt"):
                self.vm_backend().halt()
            with _host_phase("disk_discovery_export"):
                source_disk = self.vm_backend().system_disk()
                generation_manifest = self.extract_disk(source_disk)
        except BaseException as error:
            pipeline_error = error
        try:
            with _host_phase("cleanup"):
                cleanup_receipt = self.cleanup()
        except BaseException as cleanup_error:
            if pipeline_error is not None:
                pipeline_error.add_note(f"cleanup also failed: {cleanup_error}")
                raise pipeline_error from cleanup_error
            raise
        if pipeline_error is not None:
            try:
                self.record_post_export_cleanup(cleanup_receipt)
            except BaseException as record_error:
                pipeline_error.add_note(
                    f"recording the post-export cleanup receipt also failed: {record_error}"
                )
            raise pipeline_error
        if cleanup_receipt is None:
            raise RuntimeError("generation never launched a VM; refusing to publish a manifest")
        self.publish_manifest(generation_manifest, cleanup_receipt)
        print("\n[+] Pipeline completed successfully!")
        print(f"[+] Artifacts available in: {self.output_dir}")


    def post_export_directory(self):
        return self.output_dir / POST_EXPORT_DIRECTORY

    def output_relative(self, path):
        path = Path(path)
        try:
            return str(path.resolve().relative_to(self.output_dir.resolve()))
        except ValueError:
            return str(path)

    def post_export_state(self):
        bundle = getattr(self, "recipe_bundle", None)
        return {
            "schema_version": POST_EXPORT_STATE_SCHEMA,
            "provider": self.provider,
            "experiment": self.experiment,
            "scenario": self.scenario,
            "case": self.case,
            "export_format": self.export_format,
            "keep_vm": False,
            "system_image": Path(self.post_export_system_image).name,
            "native_media_source": None,
            "native_media_binding": self.native_media_binding,
            "public_population_manifest": self.public_population_manifest is not None,
            "recipe_directory": bundle["directory"] if bundle is not None else None,
            "guest_plan": self.population_guest_plan,
            "ground_truth": self.ground_truth,
            **({"native_media_sources": [{**row, "path": self.output_relative(row["path"])}
                                         for row in self.native_media_sources]}
               if getattr(self, "native_media_sources", None) else {}),
        }

    def checkpoint_post_export_state(self):
        write_json_replace(self.post_export_directory() / POST_EXPORT_STATE_NAME,
                           self.post_export_state(), private=True)

    def begin_post_export(self, system_image):
        journal = getattr(self, "post_export_journal", None)
        if journal is not None:
            return journal
        self.post_export_system_image = Path(system_image)
        directory = self.post_export_directory()
        directory.mkdir(parents=True, exist_ok=True)
        journal = PostExportJournal(directory, hasher=self.calculate_hash,
                                    checkpoint=self.checkpoint_post_export_state)
        if journal.entries:
            raise RuntimeError(
                f"a post-export journal already exists in {directory}; "
                "resume it with --resume-post-export"
            )
        self.post_export_journal = journal
        self.checkpoint_post_export_state()
        return journal

    def run_post_export_intervention(self, name, image, action, *, read_only=False,
                                     creates_image=False):
        journal = getattr(self, "post_export_journal", None)
        if journal is None:
            return action()
        return journal.run(name, image, action, read_only=read_only, creates_image=creates_image)

    def record_post_export_cleanup(self, cleanup_receipt):
        state_path = self.post_export_directory() / POST_EXPORT_STATE_NAME
        if cleanup_receipt is None or not state_path.is_file():
            return
        if (self.output_dir / "manifest.json").exists():
            return
        write_json_replace(self.post_export_directory() / POST_EXPORT_CLEANUP_NAME, cleanup_receipt)
        print(
            "[!] The post-export stage did not complete; once the cause is fixed, resume "
            f"it with: --resume-post-export {self.output_dir}"
        )

    @classmethod
    def resume_post_export(cls, output_dir):
        output_dir = Path(output_dir).expanduser().resolve()
        state_path = output_dir / POST_EXPORT_DIRECTORY / POST_EXPORT_STATE_NAME
        if not state_path.is_file():
            raise FileNotFoundError(f"no post-export state to resume in {output_dir}")
        if (output_dir / "manifest.json").exists():
            raise FileExistsError(
                f"generation manifest already published in {output_dir}; nothing to resume"
            )
        state = recipe_support.read_json(state_path)
        required = {
            "schema_version", "provider", "experiment", "scenario", "case", "export_format",
            "keep_vm", "system_image", "native_media_source", "native_media_binding",
            "public_population_manifest", "recipe_directory", "guest_plan", "ground_truth",
        }
        if isinstance(state, dict) and (state.get("guest_plan") or {}).get("native_pilot_profile") == "pilot_min.v1":
            required.add("native_media_sources")
        if (not isinstance(state, dict) or set(state) != required
                or state["schema_version"] != POST_EXPORT_STATE_SCHEMA):
            raise ValueError(f"post-export state is malformed: {state_path}")
        if (state["provider"] not in {"vmware_desktop", "qemu"} or state["experiment"] != "full_scale"
                or state["case"] != "positive" or state["export_format"] != "vmdk"
                or state["keep_vm"] is not False or state["native_media_source"] is not None
                or state["guest_plan"].get("native_pilot_profile") != "pilot_min.v1"):
            raise ValueError("resume requires the fixed paper configuration")
        self = cls.__new__(cls)
        self.recipe_bundle = None
        self.provider = state["provider"]
        self.windows_box = None
        self.vmware_bridge = None
        self.case = state["case"]
        self.experiment = state["experiment"]
        self.scenario = state["scenario"]
        self.population_seed = None
        self.export_format = state["export_format"]
        self.keep_vm = bool(state["keep_vm"])
        self.randomize_hw = False
        self.marker_receipt_times = []
        self.clock_block = None
        self.work_dir = Path(__file__).parent.absolute()
        self.vagrant_dir = self.work_dir
        self.output_dir = output_dir
        self.vagrant_state_dir = output_dir / ".vagrant"
        self.vm_work_root = None
        self.vmware_state_identity = None
        self.provider_launch_attempted = True
        self.ground_truth = state["ground_truth"]
        self.native_media_binding = state["native_media_binding"]
        if "native_media_sources" in state:
            self.native_media_sources = []
            for row in state["native_media_sources"]:
                path = Path(row["path"])
                if path.is_absolute() or len(path.parts) != 1:
                    raise ValueError("pilot media source must remain inside its realization directory")
                self.native_media_sources.append({**row, "path": output_dir / path})
        self.public_population_manifest = None
        if state["public_population_manifest"]:
            self.public_population_manifest = recipe_support.read_json(
                output_dir / "population_manifest.json"
            )
        self.private_population_assignment = None
        self.population_guest_plan = state["guest_plan"]
        self.population_inputs_path = None
        self.post_export_journal = None
        self.post_export_system_image = output_dir / state["system_image"]
        if state["recipe_directory"] is not None:
            self.recipe_bundle = recipe_support.load_recipe(
                state["recipe_directory"], source_root=self.work_dir, verify_dependencies=False
            )
            reference = recipe_support.read_json(output_dir / "recipe-reference.json")
            recipe_path = Path(self.recipe_bundle["directory"]) / "recipe.json"
            if (reference.get("recipe_id") != self.recipe_bundle["recipe"]["recipe_id"]
                    or reference.get("recipe_manifest_sha256")
                    != recipe_support.file_digest(recipe_path)):
                raise ValueError("the realization's recipe reference does not match the frozen recipe")
            if self.recipe_bundle["private"]["guest_plan"] != self.population_guest_plan:
                raise ValueError("post-export state guest inputs differ from the frozen recipe")
            self.require_locked_interpreter()
        self._bind_host_runtime()
        self.post_export_journal = PostExportJournal(
            self.post_export_directory(), hasher=self.calculate_hash,
            checkpoint=self.checkpoint_post_export_state,
        )
        return self

    def run_post_export_resume(self):
        print(f"[*] Resuming the post-export stage in {self.output_dir}")
        cleanup_path = self.post_export_directory() / POST_EXPORT_CLEANUP_NAME
        if not cleanup_path.is_file():
            raise RuntimeError(
                "the interrupted run recorded no VM cleanup receipt (its cleanup did not "
                "complete); the realization cannot be published by resuming"
            )
        cleanup_receipt = recipe_support.read_json(cleanup_path)
        journal = self.post_export_journal
        journal.verify_images(self.output_dir)
        print(
            f"[*] Post-export journal verified: {journal.completed_count()} of "
            f"{len(journal.entries)} entries completed"
        )
        generation_manifest = self.complete_export(self.post_export_system_image)
        self.publish_manifest(generation_manifest, cleanup_receipt)
        print("\n[+] Post-export stage completed and the manifest was published.")
        print(f"[+] Artifacts available in: {self.output_dir}")
