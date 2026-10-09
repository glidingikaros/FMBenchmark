from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from fmb.index.adapters.i30 import bounded_i30_parser_run
from fmb.index.adapters.event_log import (
    evtxecmd_csv_files,
    evtxecmd_parser_run,
)
from fmb.index.adapters.execution import (
    jump_list_csv_files,
    jump_list_parser_run,
    pecmd_csv_files,
    pecmd_prefetch_parser_run,
    registry_path_csv_files,
    registry_path_parser_run,
)
from fmb.index.adapters.logfile import (
    logfile_csv_files,
    logfile_parser_run,
    raw_logfile_files,
    raw_logfile_parser_run,
)
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    mftecmd_mft_context_csv_files,
    mftecmd_mft_csv_files,
    mftecmd_mft_parser_run,
    raw_mft_path_for_root,
)
from fmb.index.adapters.ntfs_files import (
    mftecmd_ads_parser_run,
    mftecmd_size_parser_run,
    q_file_parser_runs,
)
from fmb.index.adapters.parser_output import (
    ParserRunAdapterResult,
    apply_host_processor_status,
    collector_artifact_identity_index,
    dedupe_exact_parser_outputs,
)
from fmb.index.adapters.registry import (
    registry_mru_csv_files,
    setupapi_log_files,
    setupapi_parser_run,
    shellbag_csv_files,
    shellbag_parser_run,
    typed_paths_parser_run,
    usbstor_csv_files,
    usbstor_parser_run,
)
from fmb.index.adapters.usn import (
    mftecmd_usn_csv_files,
    mftecmd_usn_parser_run,
    raw_usn_journal_files,
    raw_usn_journal_parser_run,
)

_ParserOutputBuilder = Callable[[Path], ParserRunAdapterResult]


def _iter_deduped_parser_outputs(
    paths: list[Path],
    artifact_identity_index: dict[str, tuple[int | None, str | None]],
    builder: _ParserOutputBuilder,
    collector_run: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    for path in dedupe_exact_parser_outputs(paths, artifact_identity_index):
        built = builder(path)
        for run in built if isinstance(built, list) else [built]:
            yield apply_host_processor_status(run, collector_run)


def _parser_output_sources(
    *,
    root: Path,
    collector_run: dict[str, Any],
    normalized_output_dir: Path,
    mft_context: dict[str, Any],
    parser_kinds: set[str] | None = None,
) -> list[tuple[list[Path], _ParserOutputBuilder]]:
    common = {"normalized_output_dir": normalized_output_dir, "collector_run": collector_run}
    with_mft = {**common, "mft_context": mft_context}
    raw_mft_path = raw_mft_path_for_root(root)
    def mft_outputs(path):
        return [builder() for kind, builder in (
            ("ntfs_mft", lambda: mftecmd_mft_parser_run(csv_path=path, raw_mft_path=raw_mft_path, **common)),
            ("ntfs_ads", lambda: mftecmd_ads_parser_run(csv_path=path, **common)),
            ("ntfs_file_size_allocation", lambda: mftecmd_size_parser_run(csv_path=path, **common)),
        ) if parser_kinds is None or kind in parser_kinds]

    sources = [
        (
            {"ntfs_mft", "ntfs_ads", "ntfs_file_size_allocation"},
            mftecmd_mft_csv_files(root),
            mft_outputs,
        ),
        ({"ntfs_usn"}, mftecmd_usn_csv_files(root), lambda path: mftecmd_usn_parser_run(csv_path=path, **with_mft)),
        ({"ntfs_usn"}, raw_usn_journal_files(root), lambda path: raw_usn_journal_parser_run(journal_path=path, **with_mft)),
        (
            {"ntfs_logfile"},
            raw_logfile_files(root),
            lambda path: raw_logfile_parser_run(logfile_path=path, raw_mft_path=raw_mft_path, **with_mft),
        ),
        ({"ntfs_logfile"}, logfile_csv_files(root), lambda path: logfile_parser_run(csv_path=path, **common)),
        ({"windows_evtx_security"}, evtxecmd_csv_files(root), lambda path: evtxecmd_parser_run(csv_path=path, **common)),
        ({"windows_prefetch"}, pecmd_csv_files(root), lambda path: pecmd_prefetch_parser_run(csv_path=path, **with_mft)),
        ({"windows_shellbag"}, shellbag_csv_files(root), lambda path: shellbag_parser_run(csv_path=path, **with_mft)),
        ({"windows_typed_paths"}, registry_mru_csv_files(root), lambda path: typed_paths_parser_run(csv_path=path, **with_mft)),
        ({"windows_jump_list"}, jump_list_csv_files(root), lambda path: jump_list_parser_run(csv_path=path, **with_mft)),
        ({"windows_usbstor"}, usbstor_csv_files(root), lambda path: usbstor_parser_run(csv_path=path, **common)),
        ({"windows_registry_paths"}, registry_path_csv_files(root), lambda path: registry_path_parser_run(csv_path=path, **with_mft)),
        ({"windows_setupapi"}, setupapi_log_files(root), lambda path: setupapi_parser_run(log_path=path, **common)),
    ]
    return [(paths, builder) for kinds, paths, builder in sources if parser_kinds is None or kinds & parser_kinds]


def scan_kape_output_root(
    *,
    root: Path,
    collector_run: dict[str, Any],
    normalized_output_dir: Path,
    bounded_content_subject_limit: int | None = None,
    bounded_i30_directory_paths: tuple[str, ...] | None = (),
    parser_kinds: set[str] | None = None,
) -> list[dict[str, Any]]:
    parser_runs: list[dict[str, Any]] = []
    artifact_identity_index = collector_artifact_identity_index(collector_run)
    mft_context = build_mft_presence_context(root) if parser_kinds is None or "ntfs_mft" in parser_kinds else {}
    for paths, builder in _parser_output_sources(
        root=root,
        collector_run=collector_run,
        normalized_output_dir=normalized_output_dir,
        mft_context=mft_context,
        parser_kinds=parser_kinds,
    ):
        parser_runs.extend(
            _iter_deduped_parser_outputs(
                paths, artifact_identity_index, builder, collector_run
            )
        )
    file_runs = q_file_parser_runs(
        root=root,
        collector_run=collector_run,
        normalized_output_dir=normalized_output_dir,
        bounded_content_subject_limit=bounded_content_subject_limit,
    ) if parser_kinds is None or parser_kinds & {"ntfs_file_size_allocation", "materialized_file_content"} else []
    if file_runs:
        parser_runs = [
            item
            for item in parser_runs
            if item.get("parser_kind") != "ntfs_file_size_allocation"
        ]
        parser_runs.extend(file_runs)
    if bounded_i30_directory_paths != ():
        raw_mft_path = raw_mft_path_for_root(root)
        mft_csv_paths = mftecmd_mft_context_csv_files(root)
        if raw_mft_path is None or len(mft_csv_paths) != 1:
            raise ValueError(
                "raw-$MFT I30 analysis requires exactly one raw $MFT and one "
                "complete MFTECmd MFT CSV"
            )
        parser_runs = [
            item for item in parser_runs if item.get("parser_kind") != "ntfs_i30"
        ]
        parser_runs.append(
            bounded_i30_parser_run(
                mft_csv_path=mft_csv_paths[0],
                raw_mft_path=raw_mft_path,
                directory_paths=bounded_i30_directory_paths,
                normalized_output_dir=normalized_output_dir,
                collector_run=collector_run,
            )
        )
    return parser_runs


__all__ = ["scan_kape_output_root"]
