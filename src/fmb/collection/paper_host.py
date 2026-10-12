from __future__ import annotations

from argparse import Namespace
from pathlib import Path
import os
import time

from fmb.collection.run.lock import acquire_evidence_image_run_lock
from fmb.collection.tools.host.backend import (
    preflight_host_collector_backend,
    run_host_collector_extraction,
    validate_host_collector_bundle,
)
from fmb.collection.tools.import_bundle import (
    EvidenceIndexImportInput,
    import_tool_bundle,
    write_import_outputs,
)
from fmb.collection.tools.host.validation import required_artifact_globs
from fmb.core.background import Background
from fmb.core.errors import FmbInputError
from fmb.core.hashing import sha256_file
from fmb.core.paths import default_current_root
from fmb.core.sealed_records import write_json, now


# On Linux and macOS any write updates the change time, which programs cannot set, so a second full hash of a
# multi-GB image is not needed to see that it changed during collection. On Windows st_ctime is the creation time
# and a writer can restore the last-write time, so there only a second hash shows that the bytes are unchanged.
REHASH_AFTER_COLLECTION = os.name == "nt"
IDENTITY_FIELDS = ("device", "inode", "size", "modification time", "change time")


def file_identity(path: Path) -> tuple[int, ...]:
    status = path.stat()
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def evidence_change(path: Path, identity: tuple[int, ...], sha256: str) -> str | None:
    """None while the image is the one hashed at the start of collection, otherwise what changed."""
    changed = [name for name, before, after in zip(IDENTITY_FIELDS, identity, file_identity(path)) if before != after]
    if changed != [] and changed != ["change time"]:
        return ", ".join(changed)
    # A change time alone also moves on chmod, a new hard link or a backup tool, so only the bytes can tell.
    if (changed or REHASH_AFTER_COLLECTION) and sha256_file(path) != sha256:
        return "content"
    return None


def parse_logfiles_early(collector_output_root: Path, normalized_output_dir: Path) -> None:
    # The import parses each collected $LogFile with dfir_ntfs and keeps the document under normalized_output_dir;
    # parsing it here, while the host parsers and the parser VM run, lets the import find that document ready.
    # A failure is left for the import, which parses again and reports it.
    from fmb.index.adapters.logfile import _logfile_document, raw_logfile_files

    for path in raw_logfile_files(collector_output_root.expanduser().resolve()):
        try:
            _logfile_document(path, normalized_output_dir=normalized_output_dir)
        except Exception:
            return


def scan_mft_early(collector_output_root: Path) -> None:
    # The import scans the MFTECmd $MFT CSV twice (its presence context and its rows); scanning it here, while the
    # parser VM works, lets the import find both scans cached. A failure is left for the import, which scans again.
    from fmb.index.adapters.mft import prescan_mftecmd_mft_csvs

    try:
        prescan_mftecmd_mft_csvs(collector_output_root.expanduser().resolve())
    except Exception:
        return


def collection_args(
    *,
    profile: dict,
    evidence: Path | None,
    windows_parsers: Path | None,
    host_toolchain_root: Path | None = None,
    vm_work_root: Path | None = None,
) -> Namespace:
    from fmb.core.case_contract import QIDS
    from fmb.analysis.mft_comparison import POOL_QUESTIONS

    from fmb.collection.tools.host.parser_appliance import parser_runtime

    questions = [q["question_id"] for q in profile["questions"]]
    provider, windows_box = parser_runtime()
    return Namespace(
        evidence=str(evidence) if evidence else None,
        windows_parsers=str(windows_parsers.expanduser().resolve()) if windows_parsers else None,
        selected_modules=(profile["collection_declaration"]["collection"]["kape"]["module_names"]
                          if questions != list(QIDS) else None),
        require_registry=bool(set(questions) & set(POOL_QUESTIONS)),
        require_logfile="ntfs.logfile" in profile["artifact_families"],
        expected_definitions_sha256=profile["collection_declaration"]["kape_definitions"]["tree_sha256"],
        host_toolchain_root=host_toolchain_root,
        vm_work_root=vm_work_root,
        collection_provider=provider,
        windows_box=windows_box,
    )


def preflight(*, profile: dict, windows_parsers: Path | None,
              host_toolchain_root: Path | None = None) -> dict:
    args = collection_args(
        profile=profile,
        evidence=None,
        windows_parsers=windows_parsers,
        host_toolchain_root=host_toolchain_root,
    )
    host = preflight_host_collector_backend(args)
    return {"status": "passed" if host["available"] else "failed", "host": host}


def collect_host(
    *,
    profile: dict,
    evidence: Path,
    output: Path,
    run_id: str,
    windows_parsers: Path | None,
    expected_sha256: str,
    bounded_content_subject_limit: int | None,
    bounded_i30_directory_paths: tuple[str, ...] | None,
    host_toolchain_root: Path | None = None,
    vm_work_root: Path | None = None,
) -> dict:
    if output.exists():
        raise FileExistsError("collection output already exists: " + str(output))
    args = collection_args(
        profile=profile,
        evidence=evidence,
        windows_parsers=windows_parsers,
        host_toolchain_root=host_toolchain_root,
        vm_work_root=vm_work_root,
    )
    args.run_id = run_id
    declared = profile["collection_declaration"]
    selection = declared["collection"]["kape"]
    stage = output / "execution/01-collection"
    extracted = stage / "extracted"
    normalized = output / "execution/02-normalization"
    clock_started = time.monotonic()
    receipt = {
        "status": "running",
        "started_utc": now(),
        "run_id": run_id,
        "evidence": str(evidence),
        "truth_sources_used": [],
        "provider_calls": 0,
    }
    with acquire_evidence_image_run_lock(
        current_root=default_current_root(), requested_run_id=run_id
    ):
        output.mkdir(parents=True, exist_ok=False)
        write_json(output / "collection.json", receipt)
        primary_error = None
        try:
            checks = preflight(
                profile=profile, windows_parsers=windows_parsers,
                host_toolchain_root=host_toolchain_root
            )
            write_json(output / "preflight.json", checks)
            if checks["status"] != "passed":
                raise FmbInputError(
                    "paper collection prerequisites are unavailable: "
                    + str(checks["host"]["missing"])
                )
            # The full hash of a multi-GB image runs alongside the extraction, which only reads the image; the
            # extraction result is written only once the hash matched the public generation manifest.
            hashing = Background(sha256_file, evidence, name="fmb-evidence-sha256")

            def confirm_evidence() -> None:
                if hashing.result() != expected_sha256:
                    raise FmbInputError(
                        "evidence image does not match the public generation manifest"
                    )
                receipt["evidence_sha256"] = expected_sha256

            parser_kinds = set(profile["parser_outputs"]) if args.selected_modules is not None else None
            early_parses: list[Background] = []

            def after_extraction(collector_output_root: Path) -> None:
                if parser_kinds is None or "ntfs_logfile" in parser_kinds:
                    early_parses.append(Background(
                        parse_logfiles_early, collector_output_root, normalized / "parser-normalized",
                        name="fmb-logfile-early"))

            def after_host_modules(collector_output_root: Path) -> None:
                if parser_kinds is None or "ntfs_mft" in parser_kinds:
                    early_parses.append(Background(scan_mft_early, collector_output_root, name="fmb-mft-scan"))

            write_json(output / "collection-profile.json", declared)
            try:
                receipt["extraction"] = run_host_collector_extraction(
                    args=args,
                    stage_dir=stage,
                    extracted_dir=extracted,
                    targets=selection["target_names"],
                    modules=selection["module_names"],
                    question_id=declared["question_id"],
                    question_text=declared["question_text"],
                    evidence_sha256=expected_sha256,
                    run_id=run_id,
                    after_extraction=after_extraction,
                    after_host_modules=after_host_modules,
                    confirm_evidence=confirm_evidence,
                )
            except Exception:
                if hashing.result() != expected_sha256:  # a wrong image fails as one, not as what it broke
                    raise FmbInputError(
                        "evidence image does not match the public generation manifest"
                    ) from None
                receipt["evidence_sha256"] = expected_sha256
                raise
            confirm_evidence()
            for parse in early_parses:
                parse.result()
            inputs = dict(
                request_path=stage / "tool_run_request.json",
                result_path=extracted / "tool_run_result.json",
                manifest_path=extracted / "tool_bundle_manifest.json",
                collector_output_root=extracted / "kape-output",
            )
            validation = validate_host_collector_bundle(
                **inputs,
                required_artifact_globs=required_artifact_globs(
                    selection["target_names"], selection["module_names"], []
                ),
            )
            write_json(stage / "validation.json", validation)
            if validation["status"] != "passed":
                raise FmbInputError("native collection validation failed")
            imported = import_tool_bundle(
                EvidenceIndexImportInput(
                    **inputs,
                    output_dir=normalized,
                    require_source_hash_verified=True,
                    bounded_content_subject_limit=bounded_content_subject_limit,
                    bounded_i30_directory_paths=bounded_i30_directory_paths,
                    parser_kinds=set(profile["parser_outputs"]) if args.selected_modules is not None else None,
                )
            )
            index_path, _ = write_import_outputs(normalized, imported)
            receipt.update(
                status="completed", evidence_index_sha256=sha256_file(index_path)
            )
            return imported["evidence_index"]
        except BaseException as error:
            primary_error = error
            receipt.update(
                status="failed", error_type=type(error).__name__, error=str(error)
            )
            raise
        finally:
            receipt.update(
                finished_utc=now(), elapsed_seconds=time.monotonic() - clock_started
            )
            try:
                write_json(output / "collection.json", receipt)
            except BaseException as record_error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"Failed to write final host collection record {output / 'collection.json'}: "
                    f"{type(record_error).__name__}: {record_error}"
                )
