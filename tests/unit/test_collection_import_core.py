from __future__ import annotations
import json


from pathlib import Path


import pytest


from fmb.collection.tools import envelope as execution_envelope


from fmb.index.adapters import event_log as event_log_adapters
from fmb.index.adapters import execution as execution_adapters
from fmb.index.adapters import mft as mft_adapters
from fmb.index.adapters import ntfs_files as ntfs_files_adapters
from fmb.index.adapters import parser_output as parser_output_adapters
from fmb.index.adapters import usn as usn_adapters
import fmb.index.support.windows_artifacts as windows_artifacts
import fmb.index.support.windows_identity as windows_identity


from fmb.index.contract import artifact_declarations, constants, evidence_index


from fmb.index.kape import discovery as kape_parser_discovery


from fmb.index.kape import sources as kape_parser_sources


from fmb.core.hashing import sha256_file


from fmb.core.json_io import write_json


def test_execution_envelope_builds_and_validates_a_kape_bundle(tmp_path: Path) -> None:
    output_root = tmp_path / "collector-output"
    output_root.mkdir()
    artifact = output_root / "Targets" / "file.txt"
    artifact.parent.mkdir()
    artifact.write_text("evidence", encoding="utf-8")
    request_path = tmp_path / "tool_run_request.json"
    result_path = tmp_path / "tool_run_result.json"
    manifest_path = tmp_path / "tool_bundle_manifest.json"

    request = execution_envelope.build_tool_run_request(
        question_id="Q-1",
        question_text="What happened?",
        collector="kape",
        run_id="run-1",
        collector_config={
            "source": "E:",
            "targets": "FileSystem",
            "modules": "Amcache",
            "output": output_root,
        },
        source_evidence_id="case",
        source_evidence_sha256="a" * 64,
    )
    write_json(request_path, request)
    result = {
        "schema_version": "tool_run_result.v1",
        "request_id": request["request_id"],
        "request_sha256": sha256_file(request_path),
        "run_id": "run-1",
        "question_id": "Q-1",
        "collector": "kape",
        "execution_environment": {
            "platform": "windows",
            "os": "Windows",
            "architecture": "x64",
        },
        "tool_identity": {
            "name": "kape",
            "executable_path": "KAPE.exe",
            "version": "1",
            "executable_sha256": None,
        },
        "source_evidence": {
            "evidence_id": "case",
            "path_seen_by_worker": "E:",
            "sha256": "a" * 64,
            "sha256_expected": "a" * 64,
            "sha256_observed": "a" * 64,
            "hash_verified": True,
            "mount_mode": "read_only",
            "read_only_asserted": True,
            "source_drive": "E:",
            "source_drive_not_boot_drive": True,
        },
        "executed_collection": {
            "collector": "kape",
            "targets": "FileSystem",
            "modules": "Amcache",
        },
        "command": {"command_line": "KAPE.exe --target FileSystem"},
        "output": {"collector_output_root": str(output_root)},
        "artifact_manifest": {"path": str(manifest_path)},
        "status": {"exit_code": 0, "result": "success"},
    }
    write_json(result_path, result)
    manifest = execution_envelope.build_tool_bundle_manifest(
        request=request,
        result=result,
        request_path=request_path,
        result_path=result_path,
        collector_output_root=output_root,
    )
    write_json(manifest_path, manifest)

    validated = execution_envelope.validate_external_tool_bundle(
        request_path=request_path,
        result_path=result_path,
        manifest_path=manifest_path,
    )

    assert (
        execution_envelope.collection_label(result["executed_collection"])
        == "FileSystem,Amcache"
    )
    assert validated["execution_envelope"]["bundle_validation"]["status"] == "passed"
    assert validated["execution_envelope"]["target_or_profile"] == "FileSystem,Amcache"
    assert validated["collector_output_root"] == output_root.resolve()

    result["execution_environment"]["platform"] = "linux"
    write_json(result_path, result)
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="expected execution platform"
    ):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
        )
    result["execution_environment"]["platform"] = "windows"
    result["executed_collection"]["extra_args"] = ["--unexpected"]
    write_json(result_path, result)
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)
    with pytest.raises(execution_envelope.ExecutionEnvelopeError, match="extra_args"):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
        )
    result["executed_collection"]["extra_args"] = []
    write_json(result_path, result)
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)

    unmanifested = output_root / "unmanifested.txt"
    unmanifested.write_text("not in manifest", encoding="utf-8")
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="unmanifested artifact"
    ):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
        )
    unmanifested.unlink()

    outside_output = tmp_path / "outside-output.txt"
    outside_output.write_text("outside", encoding="utf-8")
    escaped_link = output_root / "escaped-link.txt"
    try:
        escaped_link.symlink_to(outside_output)
    except (NotImplementedError, OSError):
        pass
    else:
        with pytest.raises(
            execution_envelope.ExecutionEnvelopeError, match="escapes output root"
        ):
            execution_envelope.validate_external_tool_bundle(
                request_path=request_path,
                result_path=result_path,
                manifest_path=manifest_path,
            )
        escaped_link.unlink()

    internal_link_target = output_root / "internal-link-target.txt"
    internal_link_target.write_text("inside", encoding="utf-8")
    internal_link = output_root / "internal-link.txt"
    try:
        internal_link.symlink_to(internal_link_target)
    except (NotImplementedError, OSError):
        internal_link_target.unlink()
    else:
        with pytest.raises(execution_envelope.ExecutionEnvelopeError, match="symlink"):
            execution_envelope.scan_collector_output(output_root)
        internal_link.unlink()
        internal_link_target.unlink()

    result["output"]["collector_output_root"] = str(tmp_path / "other-output")
    write_json(result_path, result)
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="result collector_output_root"
    ):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
            collector_output_root=output_root,
        )
    result["output"]["collector_output_root"] = str(output_root)
    write_json(result_path, result)
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)

    duplicate_manifest = {
        **manifest,
        "artifacts": [manifest["artifacts"][0], manifest["artifacts"][0]],
    }
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="duplicate artifact path"
    ):
        execution_envelope.assert_manifest_covers_output(
            duplicate_manifest, output_root
        )

    manifest["artifacts"][0]["relative_path"] = "../escape.txt"
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="not portable relative"
    ):
        execution_envelope.assert_manifest_covers_output(manifest, output_root)
    manifest["artifacts"][0]["relative_path"] = "Targets/file.txt:ads"
    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError, match="not portable relative"
    ):
        execution_envelope.assert_manifest_covers_output(manifest, output_root)
    with pytest.raises(ValueError, match="unsupported collector"):
        execution_envelope.build_tool_run_request(
            question_id="Q",
            question_text="Q",
            collector="bad",
            run_id="r",
            collector_config={"output": "out"},
        )


def test_execution_envelope_rejects_unproven_kape_source_claims(tmp_path: Path) -> None:
    request_path, result_path, manifest_path, output_root = write_appliance_bundle(
        tmp_path,
        source_drive="E:",
        source_drive_not_boot_drive=True,
        hash_verified=False,
    )

    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError,
        match="worker did not mark it verified",
    ):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
            collector_output_root=output_root,
        )

    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["source_evidence"]["hash_verified"] = True
    result["source_evidence"]["source_drive_not_boot_drive"] = False
    write_json(result_path, result)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_sha256"] = sha256_file(result_path)
    write_json(manifest_path, manifest)

    with pytest.raises(
        execution_envelope.ExecutionEnvelopeError,
        match="non-boot source evidence drive",
    ):
        execution_envelope.validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
            collector_output_root=output_root,
        )


def write_appliance_bundle(
    tmp_path: Path,
    *,
    source_drive: str | None,
    source_drive_not_boot_drive: bool | None,
    hash_verified: bool | None = True,
) -> tuple[Path, Path, Path, Path]:
    output_root = tmp_path / "collector-output"
    output_root.mkdir()
    artifact = output_root / "artifact.txt"
    artifact.write_text("evidence", encoding="utf-8")
    request_path = tmp_path / "tool_run_request.json"
    result_path = tmp_path / "tool_run_result.json"
    manifest_path = tmp_path / "tool_bundle_manifest.json"
    source_sha256 = "a" * 64

    request = execution_envelope.build_tool_run_request(
        question_id="Q-1",
        question_text="What happened?",
        collector="kape",
        run_id="run-1",
        collector_config={
            "source": "E:",
            "targets": "FileSystem",
            "modules": "Amcache",
            "output": output_root,
        },
        source_evidence_id="case",
        source_evidence_sha256=source_sha256,
    )
    write_json(request_path, request)
    source_evidence = {
        "evidence_id": "case",
        "path_seen_by_worker": "E:",
        "sha256": source_sha256,
        "sha256_expected": source_sha256,
        "sha256_observed": source_sha256,
        "mount_mode": "read_only",
        "read_only_asserted": True,
    }
    if hash_verified is not None:
        source_evidence["hash_verified"] = hash_verified
    if source_drive is not None:
        source_evidence["source_drive"] = source_drive
    if source_drive_not_boot_drive is not None:
        source_evidence["source_drive_not_boot_drive"] = source_drive_not_boot_drive
    result = {
        "schema_version": "tool_run_result.v1",
        "request_id": request["request_id"],
        "request_sha256": sha256_file(request_path),
        "run_id": "run-1",
        "question_id": "Q-1",
        "collector": "kape",
        "execution_environment": {
            "platform": "windows",
            "os": "Windows",
            "architecture": "x64",
        },
        "tool_identity": {
            "name": "kape",
            "executable_path": "KAPE.exe",
            "version": "1",
            "executable_sha256": None,
        },
        "source_evidence": source_evidence,
        "executed_collection": {
            "collector": "kape",
            "targets": "FileSystem",
            "modules": "Amcache",
        },
        "command": {"command_line": "KAPE.exe --target FileSystem"},
        "output": {"collector_output_root": str(output_root)},
        "artifact_manifest": {"path": str(manifest_path)},
        "status": {"exit_code": 0, "result": "success"},
    }
    write_json(result_path, result)
    manifest = execution_envelope.build_tool_bundle_manifest(
        request=request,
        result=result,
        request_path=request_path,
        result_path=result_path,
        collector_output_root=output_root,
    )
    write_json(manifest_path, manifest)
    return request_path, result_path, manifest_path, output_root


def test_stamp_artifact_family_evidence_rejects_non_object_declaration() -> None:
    with pytest.raises(ValueError, match="artifact declaration is not an object"):
        artifact_declarations.stamp_artifact_family_evidence(
            {
                "relative_path": "artifact.txt",
                "size_bytes": 1,
                "sha256": "a" * 64,
            },
            ["not-a-declaration"],
        )


def test_index_constants_stay_aligned_with_schema_and_artifact_reference() -> None:
    schema = json.loads(
        Path("src/fmb/contracts/schemas/evidence.schema.json").read_text(encoding="utf-8")
    )
    artifact_reference = json.loads(
        Path("src/fmb/contracts/reference/artifact_families.json").read_text(encoding="utf-8")
    )
    definitions = schema["$defs"]

    assert (
        tuple(definitions["collectorRun"]["properties"]["collector"]["enum"])
        == constants.COLLECTION_TOOLS
    )
    assert (
        tuple(definitions["ruleRun"]["properties"]["engine"]["enum"])
        == constants.RULE_ENGINES
    )
    assert (
        tuple(definitions["parserRun"]["properties"]["parser"]["enum"])
        == constants.PARSER_TOOLS
    )
    assert tuple(
        definitions["parserRun"]["properties"]["parser_kind"]["enum"]
    ) == tuple(constants.PARSER_ARTIFACT_FAMILIES_BY_KIND)
    assert tuple(
        definitions["parserObservation"]["properties"]["observation_type"]["enum"]
    ) == (constants.PARSER_OBSERVATION_TYPES)

    known_artifact_families = set(artifact_reference["artifact_families"])
    declared_parser_families = {
        family
        for families in constants.PARSER_ARTIFACT_FAMILIES_BY_KIND.values()
        for family in families
    }
    assert declared_parser_families <= known_artifact_families
    assert constants.artifact_families_for_parser_kind("ntfs_mft", label="parser") == {
        "ntfs.mft"
    }


def test_parser_adapter_small_helpers_rank_and_dedupe(tmp_path: Path) -> None:
    assert windows_artifacts.parse_int("0x10") == 16
    assert windows_artifacts.parse_int("10.0") == 10
    assert windows_artifacts.parse_int("bad") is None
    assert windows_artifacts.parse_bool("YES") is True
    assert windows_artifacts.parse_bool("", default=True) is True
    assert evidence_index.canonical_parser_tool_name("MFTECmd") == "mftecmd"
    with pytest.raises(ValueError, match="unsupported parser tool"):
        evidence_index.parser_tool_for_contract("MFTECmd.exe", label="parser")
    with pytest.raises(ValueError, match="unsupported parser tool"):
        evidence_index.parser_tool_for_contract("LECmd.exe", label="parser")
    assert windows_identity.split_ntfs_file_reference((7 << 48) + 123) == (123, 7)
    assert windows_identity.split_ntfs_file_reference(-1) is None
    assert windows_identity.split_ntfs_file_reference(1 << 64) is None
    assert windows_identity.ntfs_reference_from_row(
        {"EntryNumber": "5", "SequenceNumber": "2"},
        entry_keys=("EntryNumber",),
        sequence_keys=("SequenceNumber",),
    ) == (5, 2)
    assert (
        windows_identity.normalize_windows_compare_path(r"C:/Users/A/File.txt")
        == r"users\a\file.txt"
    )
    assert (
        windows_artifacts.join_windows_path(r"C:\Users", "file.txt")
        == r"C:\Users\file.txt"
    )
    assert (
        usn_adapters.usn_observation_type("File_Delete|Close") == "usn_file_delete"
    )
    assert (
        usn_adapters.usn_observation_type("Rename_Old_Name") == "usn_rename_old_name"
    )
    assert (
        usn_adapters.usn_observation_type("Basic_Info_Change")
        == "usn_basic_info_change"
    )
    assert (
        ntfs_files_adapters.ads_stream_name_from_path(r"C:\a\b.txt:secret:$DATA")
        == "secret"
    )
    assert (
        ntfs_files_adapters.ads_subject_ref(r"C:\a\b.txt", "secret") == r"C:\a\b.txt:secret"
    )
    assert (
        ntfs_files_adapters.ads_subject_ref(r"C:\a\b.txt:secret:$DATA", "secret")
        == r"C:\a\b.txt:secret:$DATA"
    )

    row = {
        "Name": "evidence.txt",
        "UpdateReasons": "FileDelete Close",
        "UpdateTimestamp": "2026-01-01 00:00:00",
    }
    assert usn_adapters.usn_row_score(row, purpose="usn_delete") > 150

    root = tmp_path / "root"
    (root / "MFTECmd_Output").mkdir(parents=True)
    mft = root / "MFTECmd_Output" / "MFTECmd_Output.csv"
    usn = root / "MFTECmd_Output" / "MFTECmd_$J_Output.csv"
    raw_j = root / "$Extend" / "$J"
    raw_j.parent.mkdir(parents=True)
    mft.write_text("FileName\nx\n", encoding="utf-8")
    usn.write_text("Name\nx\n", encoding="utf-8")
    raw_j.write_bytes(b"journal")
    assert mft_adapters.mftecmd_mft_csv_files(root) == [mft]
    assert usn_adapters.mftecmd_usn_csv_files(root) == [usn]
    assert usn_adapters.raw_usn_journal_files(root) == [raw_j]

    collision_a = tmp_path / "case-a" / "Output.csv"
    collision_b = tmp_path / "case-b" / "Output.csv"
    collision_a.parent.mkdir()
    collision_b.parent.mkdir()
    collision_a.write_text("a\n", encoding="utf-8")
    collision_b.write_text("a\n", encoding="utf-8")
    assert parser_output_adapters.normalized_output_path(
        tmp_path / "normalized", collision_a, "rows.json"
    ) != (
        parser_output_adapters.normalized_output_path(
            tmp_path / "normalized", collision_b, "rows.json"
        )
    )

    artifact_index = {
        str(mft.resolve()): (10, "same"),
        str(usn.resolve()): (10, "same"),
    }
    assert parser_output_adapters.dedupe_exact_parser_outputs([mft, usn], artifact_index) == [
        mft
    ]
    assert (
        mft_adapters.mft_row_full_path(
            {"ParentPath": r"C:\Users", "FileName": "a.txt"}
        )
        == r"C:\Users\a.txt"
    )
    assert mft_adapters.mft_row_is_active({"InUse": "false"}) is False
    assert (
        mft_adapters.mft_row_is_directory({"FileAttributes": "Archive Directory"})
        is True
    )

    size_csv = root / "MFTECmd_Output" / "MFTECmd_Size_Output.csv"
    size_csv.write_text(
        "ParentPath,FileName,LogicalSize,AllocatedSize\n"
        r"C:\Users\alice,evidence.bin,100,4096"
        "\n",
        encoding="utf-8",
    )
    size_run = ntfs_files_adapters.mftecmd_size_parser_run(
        csv_path=size_csv,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert size_run["observation_families"] == ["ntfs.file_size_allocation"]
    assert size_run["observations"][0]["artifact_family"] == "ntfs.file_size_allocation"

    ads_csv = root / "MFTECmd_Output" / "MFTECmd_ADS_Output.csv"
    ads_csv.write_text(
        "FullPath,StreamName,StreamSize\n"
        r"C:\Users\alice\file.txt,secret,5"
        "\n",
        encoding="utf-8",
    )
    ads_run = ntfs_files_adapters.mftecmd_ads_parser_run(
        csv_path=ads_csv,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert (
        ads_run["observations"][0]["subject_ref"] == r"C:\Users\alice\file.txt:secret"
    )

    lecmd_csv = tmp_path / "LECmd_Output.csv"
    lecmd_csv.write_text(
        "Path,Timestamp\n"
        r"C:\Users\alice\Recent\evidence.lnk,2026-01-01 00:00:00"
        "\n",
        encoding="utf-8",
    )
    jump_run = execution_adapters.jump_list_parser_run(
        csv_path=lecmd_csv,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert jump_run["parser"] == "lecmd"
    assert jump_run["source_module"] == "LECmd"
    assert jump_run["observation_families"] == ["windows.jump_list"]


def test_kape_parser_discovery_skips_unusable_collectors_and_dedupes_raw_usn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_root = tmp_path / "missing"

    parser_runs = kape_parser_discovery.discover_kape_parser_runs(
        [
            {"collector": "uac", "output_root": str(tmp_path)},
            {"collector": "kape", "output_root": str(missing_root)},
        ],
        normalized_output_dir=tmp_path / "normalized",
    )

    assert parser_runs == []

    root = tmp_path / "kape-root"
    first_journal = root / "a" / "$Extend" / "$J"
    second_journal = root / "b" / "$UsnJrnl" / "$J"
    first_journal.parent.mkdir(parents=True)
    second_journal.parent.mkdir(parents=True)
    first_journal.write_bytes(b"same raw usn bytes")
    second_journal.write_bytes(first_journal.read_bytes())
    called_paths: list[Path] = []

    def fake_raw_usn_journal_parser_run(**kwargs: object) -> dict[str, object]:
        journal_path = kwargs["journal_path"]
        assert isinstance(journal_path, Path)
        called_paths.append(journal_path)
        return {"source": str(journal_path)}

    monkeypatch.setattr(
        kape_parser_sources, "build_mft_presence_context", lambda root: {}
    )
    monkeypatch.setattr(
        kape_parser_sources,
        "raw_usn_journal_parser_run",
        fake_raw_usn_journal_parser_run,
    )

    runs = kape_parser_sources.scan_kape_output_root(
        root=root,
        collector_run={
            "collector": "kape",
            "artifacts": [
                {
                    "path": str(first_journal),
                    "size_bytes": first_journal.stat().st_size,
                    "sha256": sha256_file(first_journal),
                },
                {
                    "path": str(second_journal),
                    "size_bytes": second_journal.stat().st_size,
                    "sha256": sha256_file(second_journal),
                },
            ],
        },
        normalized_output_dir=tmp_path / "normalized",
    )

    assert runs == [{"source": str(first_journal)}]
    assert called_paths == [first_journal]


def test_kape_parser_discovery_routes_setupapi_logs_with_log_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "kape-root"
    log_path = root / "C" / "Windows" / "INF" / "setupapi.dev.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("usb device install\n", encoding="utf-8")
    called_paths: list[Path] = []

    def fake_setupapi_parser_run(**kwargs: object) -> dict[str, object]:
        assert "csv_path" not in kwargs
        path = kwargs["log_path"]
        assert isinstance(path, Path)
        called_paths.append(path)
        return {"source": str(path)}

    monkeypatch.setattr(
        kape_parser_sources, "build_mft_presence_context", lambda root: {}
    )
    monkeypatch.setattr(
        kape_parser_sources,
        "setupapi_parser_run",
        fake_setupapi_parser_run,
    )

    runs = kape_parser_sources.scan_kape_output_root(
        root=root,
        collector_run={"collector": "kape", "artifacts": []},
        normalized_output_dir=tmp_path / "normalized",
    )

    assert runs == [{"source": str(log_path)}]
    assert called_paths == [log_path]


def test_evtxecmd_gap_detection_is_scoped_by_source_file(tmp_path: Path) -> None:
    csv_path = tmp_path / "EvtxECmd_Output.csv"
    csv_path.write_text(
        "\n".join(
            [
                "EventId,EventRecordId,Channel,SourceFile",
                r"1,1,Security,C:\case1\Security.evtx",
                r"1,2,Security,C:\case1\Security.evtx",
                r"1,100,Security,C:\case2\Security.evtx",
                r"1,101,Security,C:\case2\Security.evtx",
                "",
            ]
        ),
        encoding="utf-8",
    )
    parser_run = event_log_adapters.evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert parser_run["parser"] == "evtxecmd"
    assert parser_run["observation_count"] == 2
    assert parser_run["observation_families"] == [
        "windows.event_log.record_sequence"
    ]
    scope_observations = [
        observation
        for observation in parser_run["observations"]
        if observation["observation_type"] == "event_log_scope_seen"
    ]
    assert len(scope_observations) == 2
    assert {
        observation["fields"]["source_file"]
        for observation in scope_observations
    } == {
        r"C:\case1\Security.evtx",
        r"C:\case2\Security.evtx",
    }
    assert len(
        {
            observation["fields"]["event_log_scope_id"]
            for observation in scope_observations
        }
    ) == 2

    csv_path.write_text(
        "\n".join(
            [
                "EventId,EventRecordId,Channel,SourceFile",
                r"1,1,Security,C:\case1\Security.evtx",
                r"1,3,Security,C:\case1\Security.evtx",
                "",
            ]
        ),
        encoding="utf-8",
    )
    parser_run = event_log_adapters.evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert parser_run["observation_count"] == 2
    observation = next(
        observation
        for observation in parser_run["observations"]
        if observation["observation_type"] == "event_record_id_gap"
    )
    assert observation["artifact_family"] == "windows.event_log.record_sequence"
    assert observation["fields"]["source_file"] == r"C:\case1\Security.evtx"


def test_evtxecmd_gap_grouping_normalizes_one_log_identity(tmp_path: Path) -> None:
    csv_path = tmp_path / "EvtxECmd_Output.csv"
    csv_path.write_text(
        "EventId,EventRecordId,Channel,SourceFile\n"
        r"1,1,Security,C:\Case\Security.evtx"
        "\n"
        "1,3,security,C:/case/SECURITY.EVTX\n",
        encoding="utf-8",
    )

    parser_run = event_log_adapters.evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )

    gaps = [
        item
        for item in parser_run["observations"]
        if item["observation_type"] == "event_record_id_gap"
    ]
    assert len(gaps) == 1
    assert gaps[0]["fields"]["previous_record_id"] == 1
    assert gaps[0]["fields"]["next_record_id"] == 3


