from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.index.kape.sources import scan_kape_output_root


def discover_kape_parser_runs(
    collector_runs: list[dict[str, Any]],
    *,
    normalized_output_dir: Path,
    bounded_content_subject_limit: int | None = None,
    bounded_i30_directory_paths: tuple[str, ...] | None = (),
    parser_kinds: set[str] | None = None,
) -> list[dict[str, Any]]:
    parser_runs: list[dict[str, Any]] = []
    for collector_run in collector_runs:
        output_root = collector_run.get("output_root")
        if (
            collector_run.get("collector") != "kape"
            or not isinstance(output_root, str)
            or not output_root
        ):
            continue
        root = Path(output_root).expanduser()
        if not root.exists():
            continue
        parser_runs.extend(
            scan_kape_output_root(
                root=root,
                collector_run=collector_run,
                normalized_output_dir=normalized_output_dir,
                bounded_content_subject_limit=bounded_content_subject_limit,
                bounded_i30_directory_paths=bounded_i30_directory_paths,
                parser_kinds=parser_kinds,
            )
        )
    return parser_runs
