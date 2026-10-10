from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from fmb.core.errors import FmbInputError
from fmb.core.hashing import sha256_file
from fmb.core.json_io import load_json_object
from fmb.core.path_policy import is_portable_relative_path
from fmb.core.paths import load_schema_definition_payload
from fmb.index.contract.artifact_declarations import (
    collected_artifact_family_evidence,
    stamp_artifact_family_evidence,
)
from fmb.collection.inputs.source_drive import (
    has_explicit_non_boot_source_drive,
    normalize_source_drive,
)


class ExecutionEnvelopeError(FmbInputError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    return load_json_object(
        path, label="JSON payload", error_type=ExecutionEnvelopeError
    )


def validate_tool_execution_payload(
    payload: dict[str, Any], definition_name: str
) -> None:
    validator = Draft202012Validator(
        load_schema_definition_payload("execution.schema.json", definition_name)
    )
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise ExecutionEnvelopeError(
            f"execution.schema.json#/$defs/{definition_name} validation failed at "
            f"{location}: {errors[0].message}"
        )


def reported_bundle_path(value: str, *, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (base_dir / path).resolve()


def split_csv(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def collection_label(collection: dict[str, Any]) -> str | None:
    parts = []
    for key in ("targets", "modules", "profile"):
        value = collection.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    if parts:
        return ",".join(parts)
    return None


def build_tool_run_request(
    *,
    question_id: str,
    question_text: str,
    collector: str,
    run_id: str,
    collector_config: dict[str, Any],
    expected_artifact_families: list[str] | None = None,
    source_evidence_id: str | None = None,
    source_evidence_sha256: str | None = None,
    request_id: str | None = None,
    expected_platform: str | None = None,
    expected_tool: str | None = None,
    required_capability: str | None = None,
) -> dict[str, Any]:
    if collector != "kape":
        raise ValueError(f"unsupported collector: {collector}")

    path_hint = collector_config.get("source")
    requested_collection = {
        "collector": "kape",
        "targets": collector_config.get("targets") or None,
        "modules": collector_config.get("modules") or None,
        "profile": None,
        "artifacts": [],
        "expected_artifact_families": expected_artifact_families or [],
        "extra_args": collector_config.get("extra_args", []),
        "output_hint": str(collector_config["output"]),
    }
    expected_platform = expected_platform or "windows"
    required_capability = required_capability or "kape_capable_worker"

    payload = {
        "schema_version": "tool_run_request.v1",
        "request_id": request_id or f"{run_id}:{collector}",
        "run_id": run_id,
        "question": {
            "question_id": str(question_id),
            "question_text": str(question_text),
        },
        "collector": collector,
        "expected_execution": {
            "platform": expected_platform,
            "tool": expected_tool or collector,
            "required_capability": required_capability,
        },
        "source_evidence": {
            "evidence_id": source_evidence_id,
            "path_hint": path_hint,
            "sha256": source_evidence_sha256,
        },
        "requested_collection": requested_collection,
        "rule_requests": [],
        "output_contract": {
            "collector_output_hint": str(collector_config["output"]),
            "result_file": "tool_run_result.json",
            "bundle_manifest_file": "tool_bundle_manifest.json",
        },
        "truth_firewall": {
            "ground_truth_allowed": False,
            "instance_level_targets_allowed": False,
            "note": "Portable tool requests are bound to the selected question profile but must not contain ground_truth.json instance-level detector targets.",
        },
    }
    validate_tool_execution_payload(payload, "tool_run_request")
    return payload


def assert_output_artifact_is_within_root(
    path: Path,
    *,
    resolved_output_root: Path,
    relative_path: str,
    message_prefix: str,
) -> Path:
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_output_root)
    except ValueError as error:
        raise ExecutionEnvelopeError(
            f"{message_prefix} escapes output root: {relative_path}"
        ) from error
    return resolved_path


def assert_output_artifact_is_not_symlink(
    path: Path,
    *,
    relative_path: str,
    message_prefix: str,
) -> None:
    if path.is_symlink():
        raise ExecutionEnvelopeError(
            f"{message_prefix} is a symlink, not a regular file: {relative_path}"
        )


def iter_collector_output_files(
    output_root: Path,
    *,
    paths: Iterable[Path],
    symlink_check_before_root_check: bool,
    message_prefix: str,
) -> Iterator[tuple[Path, str]]:
    resolved_output_root = output_root.resolve()
    for path in paths:
        if not path.is_file():
            continue
        relative_path = path.relative_to(output_root).as_posix()
        if symlink_check_before_root_check:
            assert_output_artifact_is_not_symlink(
                path,
                relative_path=relative_path,
                message_prefix=message_prefix,
            )
        assert_output_artifact_is_within_root(
            path,
            resolved_output_root=resolved_output_root,
            relative_path=relative_path,
            message_prefix=message_prefix,
        )
        if not symlink_check_before_root_check:
            assert_output_artifact_is_not_symlink(
                path,
                relative_path=relative_path,
                message_prefix=message_prefix,
            )
        yield path, relative_path


def scan_collector_output(output_root: Path) -> list[dict[str, Any]]:
    records = []
    for path, relative_path in iter_collector_output_files(
        output_root,
        paths=sorted(output_root.rglob("*")),
        symlink_check_before_root_check=True,
        message_prefix="collector output artifact",
    ):
        records.append(
            stamp_artifact_family_evidence(
                {
                    "relative_path": relative_path,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                },
                collected_artifact_family_evidence(),
            )
        )
    return records


def build_tool_bundle_manifest(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    request_path: Path,
    result_path: Path,
    collector_output_root: Path,
) -> dict[str, Any]:
    artifacts = scan_collector_output(collector_output_root)
    payload = {
        "schema_version": "tool_bundle_manifest.v1",
        "request_id": str(request["request_id"]),
        "request_sha256": sha256_file(request_path),
        "result_sha256": sha256_file(result_path),
        "run_id": str(request["run_id"]),
        "question_id": str(request["question"]["question_id"]),
        "collector": str(request["collector"]),
        "collector_output_root": str(collector_output_root),
        "transport_package_sha256": None,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    validate_tool_execution_payload(payload, "tool_bundle_manifest")
    return payload


def validate_manifest_artifact(
    artifact: dict[str, Any],
    *,
    output_root: Path,
    resolved_output_root: Path,
    known_relative_paths: set[str],
) -> tuple[str, dict[str, str]]:
    relative_path = str(artifact["relative_path"])
    if not is_portable_relative_path(relative_path):
        raise ExecutionEnvelopeError(
            f"manifest artifact path is not portable relative: {relative_path}"
        )
    if relative_path in known_relative_paths:
        raise ExecutionEnvelopeError(
            f"manifest contains duplicate artifact path: {relative_path}"
        )

    candidate_path = output_root / relative_path
    artifact_path = assert_output_artifact_is_within_root(
        candidate_path,
        resolved_output_root=resolved_output_root,
        relative_path=relative_path,
        message_prefix="manifest artifact",
    )
    assert_output_artifact_is_not_symlink(
        candidate_path,
        relative_path=relative_path,
        message_prefix="manifest artifact",
    )
    if not artifact_path.is_file():
        raise ExecutionEnvelopeError(
            f"manifest artifact missing from output root: {relative_path}"
        )

    size_bytes = artifact_path.stat().st_size
    if size_bytes != artifact["size_bytes"]:
        raise ExecutionEnvelopeError(
            f"manifest artifact size mismatch for {relative_path}: "
            f"expected {artifact['size_bytes']} observed {size_bytes}"
        )
    observed_sha256 = sha256_file(artifact_path)
    if observed_sha256 != artifact["sha256"]:
        raise ExecutionEnvelopeError(
            f"manifest artifact sha256 mismatch for {relative_path}: "
            f"expected {artifact['sha256']} observed {observed_sha256}"
        )
    return relative_path, {
        "check_id": f"artifact:{relative_path}",
        "status": "pass",
    }


def manifest_artifact_paths(
    manifest: dict[str, Any], output_root: Path
) -> tuple[set[str], list[dict[str, str]]]:
    checks: list[dict[str, str]] = []
    manifest_relative_paths: set[str] = set()
    resolved_output_root = output_root.resolve()
    for artifact in manifest.get("artifacts", []):
        if not isinstance(artifact, dict):
            raise ExecutionEnvelopeError("manifest artifact entry is not an object")
        relative_path, check = validate_manifest_artifact(
            artifact,
            output_root=output_root,
            resolved_output_root=resolved_output_root,
            known_relative_paths=manifest_relative_paths,
        )
        manifest_relative_paths.add(relative_path)
        checks.append(check)
    return manifest_relative_paths, checks


def actual_output_artifact_paths(output_root: Path) -> set[str]:
    actual_relative_paths: set[str] = set()
    for _path, relative_path in iter_collector_output_files(
        output_root,
        paths=output_root.rglob("*"),
        symlink_check_before_root_check=False,
        message_prefix="collector output artifact",
    ):
        actual_relative_paths.add(relative_path)
    return actual_relative_paths


def assert_manifest_covers_output(
    manifest: dict[str, Any], output_root: Path
) -> list[dict[str, str]]:
    manifest_relative_paths, checks = manifest_artifact_paths(manifest, output_root)
    extra_paths = sorted(
        actual_output_artifact_paths(output_root) - manifest_relative_paths
    )
    if extra_paths:
        raise ExecutionEnvelopeError(
            "collector output root contains unmanifested artifact(s): "
            + ", ".join(extra_paths[:10])
        )
    return checks


def platform_matches_request(observed: Any, expected: Any) -> bool:
    observed_text = str(observed or "").strip().lower()
    expected_text = str(expected or "").strip().lower()
    if expected_text == "windows":
        return observed_text in {"windows", "win32"}
    if expected_text == "unix_like":
        return observed_text in {
            "unix_like",
            "linux",
            "darwin",
            "macos",
            "posix",
            "unix",
        }
    return observed_text == expected_text


def strings_from_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def assert_bundle_check(
    checks: list[dict[str, str]],
    condition: bool,
    check_id: str,
    message: str,
) -> None:
    if not condition:
        raise ExecutionEnvelopeError(message)
    checks.append({"check_id": check_id, "status": "pass"})


def load_bundle_documents(
    *,
    request_path: Path,
    result_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    request = load_json(request_path)
    result = load_json(result_path)
    manifest = load_json(manifest_path)
    validate_tool_execution_payload(request, "tool_run_request")
    validate_tool_execution_payload(result, "tool_run_result")
    validate_tool_execution_payload(manifest, "tool_bundle_manifest")
    return request, result, manifest


def assert_bundle_documents_match(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    manifest: dict[str, Any],
    request_sha256: str,
    result_sha256: str,
    checks: list[dict[str, str]],
) -> None:
    assert_bundle_check(
        checks,
        result["request_sha256"] == request_sha256,
        "request_hash_matches_result",
        "tool_run_result request_sha256 does not match request file",
    )
    assert_bundle_check(
        checks,
        manifest["request_sha256"] == request_sha256,
        "request_hash_matches_manifest",
        "tool_bundle_manifest request_sha256 does not match request file",
    )
    assert_bundle_check(
        checks,
        manifest["result_sha256"] == result_sha256,
        "result_hash_matches_manifest",
        "tool_bundle_manifest result_sha256 does not match result file",
    )
    assert_bundle_check(
        checks,
        result["request_id"] == request["request_id"] == manifest["request_id"],
        "request_id_matches",
        "request_id mismatch across request/result/manifest",
    )
    assert_bundle_check(
        checks,
        result["run_id"] == request["run_id"] == manifest["run_id"],
        "run_id_matches",
        "run_id mismatch across request/result/manifest",
    )
    assert_bundle_check(
        checks,
        result["question_id"]
        == request["question"]["question_id"]
        == manifest["question_id"],
        "question_id_matches",
        "question_id mismatch across request/result/manifest",
    )
    assert_bundle_check(
        checks,
        result["collector"] == request["collector"] == manifest["collector"],
        "collector_matches",
        "collector mismatch across request/result/manifest",
    )
    assert_bundle_check(
        checks,
        result["status"]["exit_code"] == 0 and result["status"]["result"] == "success",
        "tool_exit_success",
        "external tool did not report a successful zero-exit run",
    )


def assert_execution_matches_request(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    checks: list[dict[str, str]],
) -> None:
    expected_execution = request["expected_execution"]
    execution_environment = result["execution_environment"]
    tool_identity = result["tool_identity"]
    assert_bundle_check(
        checks,
        tool_identity["name"] == expected_execution["tool"],
        "tool_identity_matches_expected_execution",
        "tool identity does not match expected execution tool",
    )
    assert_bundle_check(
        checks,
        platform_matches_request(
            execution_environment.get("platform"),
            expected_execution.get("platform"),
        ),
        "execution_platform_matches_expected",
        "execution platform does not satisfy expected execution platform",
    )


def assert_collection_matches_request(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    checks: list[dict[str, str]],
) -> None:
    requested = request["requested_collection"]
    executed = result["executed_collection"]
    assert_bundle_check(
        checks,
        executed["collector"] == requested["collector"],
        "executed_collector_matches_request",
        "executed collector does not match request",
    )
    assert_bundle_check(
        checks,
        strings_from_list(executed.get("extra_args"))
        == strings_from_list(requested.get("extra_args")),
        "executed_extra_args_match_request",
        "executed collector extra_args do not match request",
    )
    if request["collector"] == "kape":
        assert_bundle_check(
            checks,
            split_csv(executed.get("targets")) == split_csv(requested.get("targets")),
            "kape_targets_match_request",
            "executed KAPE targets do not match request",
        )
        assert_bundle_check(
            checks,
            split_csv(executed.get("modules")) == split_csv(requested.get("modules")),
            "kape_modules_match_request",
            "executed KAPE modules do not match request",
        )
    elif requested.get("profile"):
        assert_bundle_check(
            checks,
            executed.get("profile") == requested.get("profile"),
            "uac_profile_matches_request",
            "executed UAC profile does not match request",
        )


def assert_source_evidence_boundary(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    checks: list[dict[str, str]],
    require_source_hash_verified: bool,
) -> None:
    requested_source = request["source_evidence"]
    result_source = result["source_evidence"]
    requested_source_sha256 = requested_source.get("sha256")
    reported_source_sha256 = result_source.get("sha256")
    expected_source_sha256 = result_source.get("sha256_expected")
    observed_source_sha256 = result_source.get("sha256_observed")
    if requested_source_sha256 and reported_source_sha256:
        assert_bundle_check(
            checks,
            requested_source_sha256 == reported_source_sha256,
            "source_hash_matches_request",
            "source evidence sha256 differs between request and result",
        )
    if requested_source_sha256 and expected_source_sha256:
        assert_bundle_check(
            checks,
            requested_source_sha256 == expected_source_sha256,
            "expected_source_hash_matches_request",
            "worker-expected source evidence sha256 differs from request",
        )
    if requested_source_sha256 and observed_source_sha256:
        assert_bundle_check(
            checks,
            requested_source_sha256 == observed_source_sha256,
            "observed_source_hash_matches_request",
            "worker-observed source evidence sha256 differs from request",
        )
    if result_source.get("hash_verified") is True:
        assert_bundle_check(
            checks,
            bool(expected_source_sha256) and bool(observed_source_sha256),
            "verified_source_hash_has_expected_and_observed_values",
            "source hash is marked verified without expected and observed hashes",
        )
        assert_bundle_check(
            checks,
            expected_source_sha256 == observed_source_sha256,
            "verified_source_hash_values_match",
            "source hash is marked verified but expected and observed hashes differ",
        )
        if reported_source_sha256:
            assert_bundle_check(
                checks,
                reported_source_sha256 == expected_source_sha256,
                "reported_source_hash_matches_verified_hash",
                "source hash differs from the verified expected/observed hash",
            )
    if requested_source_sha256 and require_source_hash_verified:
        assert_bundle_check(
            checks,
            bool(expected_source_sha256) and bool(observed_source_sha256),
            "requested_source_hash_has_expected_and_observed_values",
            "request pins a source hash but the result lacks expected and observed source hashes",
        )
        assert_bundle_check(
            checks,
            result_source.get("hash_verified") is True,
            "requested_source_hash_marked_verified",
            "request pins a source hash but the worker did not mark it verified",
        )
    if requested_source.get("evidence_id") and result_source.get("evidence_id"):
        assert_bundle_check(
            checks,
            requested_source["evidence_id"] == result_source["evidence_id"],
            "source_evidence_id_matches_request",
            "source evidence id differs between request and result",
        )
    if request["collector"] == "kape":
        assert_bundle_check(
            checks,
            result_source.get("read_only_asserted") is True,
            "kape_source_read_only_asserted",
            "KAPE result did not assert read-only source evidence access",
        )
        source_drive = normalize_source_drive(result_source.get("source_drive"))
        assert_bundle_check(
            checks,
            source_drive is not None,
            "kape_source_drive_recorded",
            "KAPE result did not record a source evidence drive",
        )
        assert_bundle_check(
            checks,
            has_explicit_non_boot_source_drive(
                source_drive, result_source.get("source_drive_not_boot_drive"),
                mount_mode=result_source.get("mount_mode"),
            ),
            "kape_source_drive_not_boot_drive",
            "KAPE result did not prove a non-boot source evidence drive",
        )


def assert_bundle_output_paths(
    *,
    result: dict[str, Any],
    manifest: dict[str, Any],
    result_path: Path,
    manifest_path: Path,
    manifest_sha256: str,
    collector_output_root: Path | None,
    checks: list[dict[str, str]],
) -> Path:
    bundle_dir = result_path.parent
    result_manifest_path = reported_bundle_path(
        result["artifact_manifest"]["path"],
        base_dir=bundle_dir,
    )
    assert_bundle_check(
        checks,
        result_manifest_path == manifest_path,
        "result_manifest_path_matches",
        "result artifact_manifest.path does not point to supplied manifest",
    )
    if result["artifact_manifest"].get("sha256"):
        assert_bundle_check(
            checks,
            result["artifact_manifest"]["sha256"] == manifest_sha256,
            "result_manifest_hash_matches",
            "result artifact_manifest.sha256 does not match supplied manifest",
        )

    result_output_root = reported_bundle_path(
        result["output"]["collector_output_root"],
        base_dir=bundle_dir,
    )
    output_root = (
        Path(collector_output_root)
        if collector_output_root is not None
        else result_output_root
    )
    output_root = output_root.expanduser().resolve()
    assert_bundle_check(
        checks,
        result_output_root == output_root,
        "result_output_root_matches",
        "result collector_output_root does not match imported output root",
    )
    assert_bundle_check(
        checks,
        output_root.exists() and output_root.is_dir(),
        "collector_output_root_exists",
        f"collector output root does not exist or is not a directory: {output_root}",
    )

    manifest_output_root = reported_bundle_path(
        manifest["collector_output_root"],
        base_dir=manifest_path.parent,
    )
    assert_bundle_check(
        checks,
        manifest_output_root == output_root,
        "manifest_output_root_matches",
        "manifest collector_output_root does not match imported output root",
    )
    return output_root


def build_import_provenance(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    manifest: dict[str, Any],
    request_path: Path,
    result_path: Path,
    manifest_path: Path,
    request_sha256: str,
    result_sha256: str,
    manifest_sha256: str,
    output_root: Path,
    checks: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "execution_environment": result["execution_environment"],
        "tool_identity": result["tool_identity"],
        "source_evidence": result["source_evidence"],
        "tool_run_request": {
            "path": str(request_path),
            "sha256": request_sha256,
            "request_id": str(request["request_id"]),
            "requested_collection": request["requested_collection"],
        },
        "requested_collection": request["requested_collection"],
        "tool_run_result": {
            "path": str(result_path),
            "sha256": result_sha256,
            "request_id": str(result["request_id"]),
        },
        "bundle_manifest": {
            "path": str(manifest_path),
            "sha256": manifest_sha256,
            "artifact_count": int(manifest["artifact_count"]),
            "transport_package_sha256": manifest.get("transport_package_sha256"),
            "artifacts": manifest["artifacts"],
        },
        "bundle_validation": {
            "status": "passed",
            "checks": checks,
        },
        "collector_output_root": str(output_root),
        "target_or_profile": collection_label(result["executed_collection"]),
        "command_line": str(result["command"]["command_line"]),
    }


def validate_external_tool_bundle(
    *,
    request_path: Path,
    result_path: Path,
    manifest_path: Path,
    collector_output_root: Path | None = None,
    require_source_hash_verified: bool = True,
) -> dict[str, Any]:
    request_path, result_path, manifest_path = (
        Path(path).expanduser().resolve() for path in (request_path, result_path, manifest_path)
    )
    request, result, manifest = load_bundle_documents(
        request_path=request_path,
        result_path=result_path,
        manifest_path=manifest_path,
    )
    request_sha256 = sha256_file(request_path)
    result_sha256 = sha256_file(result_path)
    manifest_sha256 = sha256_file(manifest_path)
    checks: list[dict[str, str]] = []

    assert_bundle_documents_match(
        request=request,
        result=result,
        manifest=manifest,
        request_sha256=request_sha256,
        result_sha256=result_sha256,
        checks=checks,
    )
    assert_execution_matches_request(request=request, result=result, checks=checks)
    assert_collection_matches_request(request=request, result=result, checks=checks)
    assert_source_evidence_boundary(
        request=request,
        result=result,
        checks=checks,
        require_source_hash_verified=require_source_hash_verified,
    )
    output_root = assert_bundle_output_paths(
        result=result,
        manifest=manifest,
        result_path=result_path,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        collector_output_root=collector_output_root,
        checks=checks,
    )
    checks.extend(assert_manifest_covers_output(manifest, output_root))
    assert_bundle_check(
        checks,
        manifest["artifact_count"] == len(manifest["artifacts"]),
        "manifest_artifact_count_matches",
        "manifest artifact_count does not match artifacts length",
    )

    provenance = build_import_provenance(
        request=request,
        result=result,
        manifest=manifest,
        request_path=request_path,
        result_path=result_path,
        manifest_path=manifest_path,
        request_sha256=request_sha256,
        result_sha256=result_sha256,
        manifest_sha256=manifest_sha256,
        output_root=output_root,
        checks=checks,
    )
    return {
        "request": request,
        "result": result,
        "manifest": manifest,
        "collector_output_root": output_root,
        "execution_envelope": provenance,
    }
