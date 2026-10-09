from __future__ import annotations

import csv
import hashlib
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.index.scanners.mft import DEFAULT_MFT_RECORD_SIZE, parse_mft_record


MAX_CONTENT_SUBJECTS = 64
MAX_CONTENT_BYTES_PER_SUBJECT = 16 * 1024 * 1024
MAX_CONTENT_BYTES_TOTAL = 64 * 1024 * 1024


@dataclass(frozen=True)
class _CollectedBMP:
    source_ref: str
    suffix: str
    volume_id: str
    representative_path: Path
    content: bytes


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _subject_ref(row: Mapping[str, Any]) -> str:
    full_path = str(row.get("FullPath", "") or "").strip()
    if full_path:
        return full_path
    parent = str(row.get("ParentPath", "") or "").rstrip("\\/")
    name = str(row.get("FileName", "") or "").strip()
    if parent and name:
        return f"{parent}\\{name}"
    return name or parent or "<unknown>"


def _subject_suffix(value: str) -> str:
    normalized = str(value).strip().replace("/", "\\")
    if normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized[2:]
    normalized = normalized.lstrip("\\")
    if normalized.startswith(".\\"):
        normalized = normalized[2:]
    return normalized.casefold()


def _bounded_bmp_source(value: Any) -> tuple[str, str, str] | None:

    source_ref = str(value or "").strip().replace("/", "\\")
    if source_ref.startswith("\\\\?\\"):
        source_ref = source_ref[4:]
    if len(source_ref) < 3 or source_ref[1:3] != ":\\":
        return None
    volume = source_ref[0].casefold()
    if not volume.isalpha():
        return None
    parts = tuple(part for part in source_ref[3:].split("\\") if part)
    if (
        len(parts) < 4
        or any(part in {".", ".."} for part in parts)
        or parts[0].casefold() != "users"
        or not parts[1]
        or parts[2].casefold() not in {"desktop", "documents", "downloads", "pictures"}
        or not parts[-1].casefold().endswith(".bmp")
    ):
        return None
    suffix = "\\".join(parts).casefold()
    return volume, suffix, source_ref


def _content_subject_limit(max_subjects: int | None) -> int:
    subject_limit = MAX_CONTENT_SUBJECTS if max_subjects is None else max_subjects
    if (
        isinstance(subject_limit, bool)
        or not isinstance(subject_limit, int)
        or not 1 <= subject_limit <= 500
    ):
        raise ValueError("materialized content subject bound must be from 1 to 500")
    return subject_limit


def _sha1_from_log(row: Mapping[str, Any], *, log_name: str) -> str:
    digest = str(row.get("SourceFileSha1", "") or "").strip().casefold()
    if len(digest) != 40 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError(f"{log_name} has an invalid source SHA-1")
    return digest


def _bounded_bmp_sources(
    root: Path,
    *,
    max_subjects: int | None,
) -> list[_CollectedBMP]:

    subject_limit = _content_subject_limit(max_subjects)

    physical_paths = collected_bmp_paths(root, max_subjects=500)
    if not physical_paths:
        return []

    target_root = root / "targets"
    physical_by_source: dict[tuple[str, str], tuple[Path, bytes]] = {}
    sources: dict[tuple[str, str], _CollectedBMP] = {}
    for path in physical_paths:
        relative = path.relative_to(target_root)
        volume = relative.parts[0].casefold()
        relative_suffix = "\\".join(relative.parts[1:])
        suffix = relative_suffix.casefold()
        source_ref = f"{relative.parts[0]}:\\{relative_suffix}"
        content = path.read_bytes()
        source_key = (volume, suffix)
        physical_by_source[source_key] = (path, content)
        sources[source_key] = _CollectedBMP(
            source_ref=source_ref,
            suffix=suffix,
            volume_id=volume,
            representative_path=path,
            content=content,
        )

    representative_by_sha1: dict[str, tuple[Path, bytes]] = {}
    copy_logs = sorted(target_root.glob("*_CopyLog.csv"))
    for log_path in copy_logs:
        with log_path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                source = _bounded_bmp_source(row.get("SourceFile"))
                if source is None:
                    continue
                volume, suffix, source_ref = source
                source_key = (volume, suffix)
                physical = physical_by_source.get(source_key)
                if physical is None:
                    raise ValueError(
                        "KAPE CopyLog bounded BMP has no collected destination bytes"
                    )
                path, content = physical
                logged_sha1 = _sha1_from_log(row, log_name="KAPE CopyLog")
                actual_sha1 = hashlib.sha1(content).hexdigest()
                if logged_sha1 != actual_sha1:
                    raise ValueError(
                        "KAPE CopyLog SHA-1 does not match collected bytes"
                    )
                logged_size = _integer(row.get("FileSize"))
                if logged_size is not None and logged_size != len(content):
                    raise ValueError("KAPE CopyLog size does not match collected bytes")
                existing = representative_by_sha1.get(logged_sha1)
                if existing is None or str(path) < str(existing[0]):
                    representative_by_sha1[logged_sha1] = (path, content)
                sources[source_key] = _CollectedBMP(
                    source_ref=source_ref,
                    suffix=suffix,
                    volume_id=volume,
                    representative_path=path,
                    content=content,
                )

    skip_logs = sorted(target_root.glob("*_SkipLog.csv*"))
    for log_path in skip_logs:
        with log_path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if str(row.get("Reason", "") or "").strip().casefold() != "deduped":
                    continue
                source = _bounded_bmp_source(row.get("SourceFile"))
                if source is None:
                    continue
                volume, suffix, source_ref = source
                source_key = (volume, suffix)
                logged_sha1 = _sha1_from_log(row, log_name="KAPE SkipLog")
                representative = representative_by_sha1.get(logged_sha1)
                if representative is None:
                    raise ValueError(
                        "KAPE SkipLog deduplicated BMP has no exact CopyLog SHA-1 "
                        "representative"
                    )
                path, content = representative
                existing = sources.get(source_key)
                if existing is not None and existing.content != content:
                    raise ValueError("KAPE logs disagree on bounded BMP source content")
                sources[source_key] = _CollectedBMP(
                    source_ref=source_ref,
                    suffix=suffix,
                    volume_id=volume,
                    representative_path=path,
                    content=content,
                )

    selected = [sources[source_key] for source_key in sorted(sources)]
    if len(selected) > subject_limit:
        raise ValueError("materialized content subject count exceeds its bound")
    total_size = 0
    for item in selected:
        size = len(item.content)
        if size > MAX_CONTENT_BYTES_PER_SUBJECT:
            raise ValueError("materialized file exceeds its byte bound")
        total_size += size
        if total_size > MAX_CONTENT_BYTES_TOTAL:
            raise ValueError("materialized content exceeds its aggregate byte bound")
    return selected


def _base_data_attribute(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates = [
        item
        for item in record.get("data_attributes", [])
        if isinstance(item, Mapping)
        and not item.get("is_named_stream")
        and item.get("lowest_vcn", 0) in (0, None)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _has_nonbase_extent(record: Mapping[str, Any]) -> bool:
    return any(
        isinstance(item, Mapping)
        and not item.get("is_named_stream")
        and item.get("lowest_vcn") not in (0, None)
        for item in record.get("data_attributes", [])
    )


def storage_observation(
    *,
    row: Mapping[str, Any],
    raw_record: Mapping[str, Any],
    volume_id: str,
) -> dict[str, Any] | None:

    data = _base_data_attribute(raw_record)
    row_entry = _integer(row.get("EntryNumber"))
    row_sequence = _integer(row.get("SequenceNumber"))
    raw_entry = _integer(raw_record.get("mft_entry"))
    raw_sequence = _integer(raw_record.get("sequence_number"))
    attribute_id = _integer(data.get("attribute_id")) if data is not None else None
    if (
        data is None
        or not volume_id
        or row_entry is None
        or row_sequence is None
        or raw_entry is None
        or raw_sequence is None
        or attribute_id is None
        or (row_entry, row_sequence) != (raw_entry, raw_sequence)
    ):
        return None

    fields = {
        "volume_id": volume_id,
        "mft_entry": raw_entry,
        "sequence_number": raw_sequence,
        "attribute_id": attribute_id,
        "stream_name": data.get("stream_name"),
        "resident_status": data.get("resident_status"),
        "attribute_flags": data.get("attribute_flags"),
        "is_sparse": data.get("is_sparse"),
        "is_compressed": data.get("is_compressed"),
        "is_encrypted": data.get("is_encrypted"),
        "logical_size": data.get("logical_size"),
        "allocated_size": data.get("allocated_size"),
        "valid_data_length": data.get("valid_data_length"),
        "lowest_vcn": data.get("lowest_vcn", 0),
        "highest_vcn": data.get("highest_vcn"),
        "data_run_count": data.get("data_run_count"),
        "allocated_cluster_count": data.get("allocated_cluster_count"),
        "sparse_cluster_count": data.get("sparse_cluster_count"),
        "runlist_complete": data.get("runlist_complete"),
        "attribute_parse_error_count": _integer(
            raw_record.get("attribute_parse_error_count")
        ),
        "attribute_chain_complete": (
            raw_record.get("attribute_list_present") is False
            and _integer(raw_record.get("attribute_parse_error_count")) == 0
            and not _has_nonbase_extent(raw_record)
        ),
        "mftecmd_file_size": _integer(row.get("FileSize")),
        "mftecmd_identity_match": True,
    }
    return {
        "observation_id": (
            f"obs:file-storage:{volume_id}:{raw_entry:06d}:"
            f"{raw_sequence:04d}:{attribute_id:04d}"
        ),
        "artifact_family": "ntfs.file_size_allocation",
        "observation_type": "logical_allocated_size_record",
        "subject_ref": _subject_ref(row),
        "fields": fields,
        "source_record_ref": (
            f"volume={volume_id};mft_entry={raw_entry};"
            f"sequence={raw_sequence};attribute={attribute_id}"
        ),
    }


def bmp_content_observation(
    *,
    content: bytes,
    subject_ref: str,
    volume_id: str,
    mft_entry: int,
    sequence_number: int,
) -> dict[str, Any]:

    if len(content) < 54 or content[:2] != b"BM":
        raise ValueError("materialized content is not a BMP with a complete header")
    declared_end = struct.unpack_from("<I", content, 2)[0]
    reserved1, reserved2 = struct.unpack_from("<HH", content, 6)
    pixel_offset = struct.unpack_from("<I", content, 10)[0]
    dib_size = struct.unpack_from("<I", content, 14)[0]
    width = struct.unpack_from("<i", content, 18)[0]
    height = struct.unpack_from("<i", content, 22)[0]
    planes = struct.unpack_from("<H", content, 26)[0]
    bits_per_pixel = struct.unpack_from("<H", content, 28)[0]
    compression = struct.unpack_from("<I", content, 30)[0]
    image_size = struct.unpack_from("<I", content, 34)[0]
    colors_used = struct.unpack_from("<I", content, 46)[0]
    row_size = ((width * bits_per_pixel + 31) // 32) * 4 if width > 0 else 0
    computed_image_size = row_size * abs(height)
    if (
        declared_end < 54
        or reserved1 != 0 or reserved2 != 0
        or pixel_offset != 54
        or dib_size != 40
        or width <= 0
        or height == 0
        or planes != 1
        or bits_per_pixel != 24
        or compression != 0
        or colors_used != 0
        or computed_image_size <= 0
        or image_size not in (0, computed_image_size)
        or declared_end != pixel_offset + computed_image_size
    ):
        raise ValueError("unsupported or internally inconsistent BMP header")

    materialized_size = len(content)
    trailing_bytes = max(0, materialized_size - declared_end)
    missing_bytes = max(0, declared_end - materialized_size)
    if trailing_bytes:
        relation = "materialized_exceeds_declared"
    elif missing_bytes:
        relation = "materialized_below_declared"
    else:
        relation = "equal"
    digest = hashlib.sha256(content).hexdigest()
    return {
        "observation_id": (
            f"obs:file-content:{volume_id}:{mft_entry:06d}:{sequence_number:04d}"
        ),
        "artifact_family": "collected.file.content",
        "observation_type": "materialized_file_content_record",
        "subject_ref": subject_ref,
        "fields": {
            "volume_id": volume_id,
            "mft_entry": mft_entry,
            "sequence_number": sequence_number,
            "materialized_size": materialized_size,
            "sha256": digest,
            "format_id": "bmp",
            "header_parse_status": "complete",
            "signature": "BM", "reserved1": reserved1, "reserved2": reserved2,
            "pixel_offset": pixel_offset, "dib_size": dib_size,
            "width": width, "height": height, "planes": planes,
            "bits_per_pixel": bits_per_pixel, "compression": compression,
            "image_size": image_size, "colors_used": colors_used,
            "declared_content_end": declared_end,
            "bmp_header_file_size": declared_end,
            "content_length_relation": relation,
            "trailing_bytes": trailing_bytes,
            "missing_bytes": missing_bytes,
            "structure_validation": (
                "consistent" if relation == "equal" else "declared_length_mismatch"
            ),
        },
        "source_record_ref": f"materialized-content:sha256={digest}",
    }


def collected_bmp_paths(
    root: Path,
    *,
    max_subjects: int | None = None,
) -> list[Path]:

    subject_limit = _content_subject_limit(max_subjects)
    target_root = root / "targets"
    if not target_root.is_dir():
        return []
    selected: list[Path] = []
    total_size = 0
    for path in sorted(target_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        parts = path.relative_to(target_root).parts
        if len(parts) < 5:
            continue
        if parts[1].casefold() != "users" or not parts[2]:
            continue
        if parts[3].casefold() not in {
            "desktop",
            "documents",
            "downloads",
            "pictures",
        }:
            continue
        if not parts[-1].casefold().endswith(".bmp"):
            continue
        if len(selected) >= subject_limit:
            raise ValueError("materialized content subject count exceeds its bound")
        size = path.stat().st_size
        if size > MAX_CONTENT_BYTES_PER_SUBJECT:
            raise ValueError("materialized file exceeds its byte bound")
        total_size += size
        if total_size > MAX_CONTENT_BYTES_TOTAL:
            raise ValueError("materialized content exceeds its aggregate byte bound")
        selected.append(path)
    return selected


def build_file_observations(
    *,
    root: Path,
    mftecmd_csv_path: Path,
    record_size: int = DEFAULT_MFT_RECORD_SIZE,
    max_subjects: int | None = None,
) -> dict[str, Any] | None:

    sources = _bounded_bmp_sources(root, max_subjects=max_subjects)
    if not sources:
        return None
    volumes = {item.volume_id for item in sources}
    if len(volumes) != 1:
        raise ValueError("bounded content spans more than one volume")
    volume_id = next(iter(volumes))
    volume_dirs = {
        path.name.casefold(): path
        for path in (root / "targets").iterdir()
        if path.is_dir()
    }
    volume_dir = volume_dirs.get(volume_id)
    if volume_dir is None:
        raise ValueError("bounded content has no same-volume target directory")
    mft_path = volume_dir / "$MFT"
    if not mft_path.is_file():
        raise ValueError("bounded content has no same-volume raw $MFT")

    content_by_suffix = {item.suffix: item for item in sources}
    selected_rows: dict[str, Mapping[str, Any]] = {}
    with mftecmd_csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for csv_row in csv.DictReader(handle):
            suffix = _subject_suffix(_subject_ref(csv_row))
            if suffix not in content_by_suffix:
                continue
            if suffix in selected_rows:
                raise ValueError("MFTECmd output has duplicate bounded subject rows")
            selected_rows[suffix] = csv_row

    storage: list[dict[str, Any]] = []
    content: list[dict[str, Any]] = []
    with mft_path.open("rb") as handle:
        for suffix, source in content_by_suffix.items():
            selected_row = selected_rows.get(suffix)
            if selected_row is None:
                continue
            entry = _integer(selected_row.get("EntryNumber"))
            if entry is None or entry < 0:
                continue
            handle.seek(entry * record_size)
            raw = handle.read(record_size)
            parsed = parse_mft_record(
                raw,
                record_offset=entry * record_size,
                record_size=record_size,
            )
            if parsed is None:
                continue
            storage_item = storage_observation(
                row=selected_row,
                raw_record=parsed,
                volume_id=volume_id,
            )
            if storage_item is None:
                continue
            fields = storage_item["fields"]
            try:
                content_item = bmp_content_observation(
                    content=source.content,
                    subject_ref=str(storage_item["subject_ref"]),
                    volume_id=volume_id,
                    mft_entry=int(fields["mft_entry"]),
                    sequence_number=int(fields["sequence_number"]),
                )
            except (OSError, TypeError, ValueError):
                continue
            storage.append(storage_item)
            content.append(content_item)

    return {
        "volume_id": volume_id,
        "mft_path": mft_path,
        "mftecmd_csv_path": mftecmd_csv_path,
        "content_paths": sorted(
            {item.representative_path for item in sources}, key=str
        ),
        "storage_observations": storage,
        "content_observations": content,
        "candidate_count": len(sources),
        "matched_count": len(content),
        "complete": len(content) == len(sources),
        "truth_sources_used": [],
    }


__all__ = [
    "MAX_CONTENT_SUBJECTS",
    "bmp_content_observation",
    "build_file_observations",
    "collected_bmp_paths",
    "storage_observation",
]
