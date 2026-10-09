from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from fmb.index.adapters import file_content


def bmp_bytes(*, trailing: bytes = b"") -> bytes:
    payload = bytearray(58)
    payload[:2] = b"BM"
    struct.pack_into("<I", payload, 2, 58)
    struct.pack_into("<I", payload, 10, 54)
    struct.pack_into("<I", payload, 14, 40)
    struct.pack_into("<i", payload, 18, 1)
    struct.pack_into("<i", payload, 22, 1)
    struct.pack_into("<H", payload, 26, 1)
    struct.pack_into("<H", payload, 28, 24)
    struct.pack_into("<I", payload, 30, 0)
    struct.pack_into("<I", payload, 34, 4)
    return bytes(payload) + trailing


def raw_mft_record() -> dict[str, object]:
    return {
        "mft_entry": 42,
        "sequence_number": 3,
        "attribute_list_present": False,
        "attribute_parse_error_count": 0,
        "data_attributes": [
            {
                "attribute_id": 7,
                "stream_name": "",
                "is_named_stream": False,
                "resident_status": "nonresident",
                "attribute_flags": 0,
                "is_sparse": False,
                "is_compressed": False,
                "is_encrypted": False,
                "logical_size": 58,
                "allocated_size": 4096,
                "valid_data_length": 58,
                "lowest_vcn": 0,
                "highest_vcn": 0,
                "data_run_count": 1,
                "allocated_cluster_count": 1,
                "sparse_cluster_count": 0,
                "runlist_complete": True,
            }
        ],
    }


def test_storage_and_content_share_volume_bound_object_identity() -> None:
    row = {
        "FullPath": r"C:\Users\alice\Documents\PhotoArchive\sample.bmp",
        "EntryNumber": "42",
        "SequenceNumber": "3",
        "FileSize": "58",
    }

    storage = file_content.storage_observation(
        row=row, raw_record=raw_mft_record(), volume_id="volume-c"
    )
    content = file_content.bmp_content_observation(
        content=bmp_bytes(),
        subject_ref=row["FullPath"],
        volume_id="volume-c",
        mft_entry=42,
        sequence_number=3,
    )

    assert storage is not None
    assert storage["fields"]["logical_size"] == 58
    assert storage["fields"]["attribute_chain_complete"] is True
    assert content["fields"]["content_length_relation"] == "equal"
    assert content["fields"]["structure_validation"] == "consistent"
    assert (
        storage["fields"]["volume_id"],
        storage["fields"]["mft_entry"],
        storage["fields"]["sequence_number"],
    ) == (
        content["fields"]["volume_id"],
        content["fields"]["mft_entry"],
        content["fields"]["sequence_number"],
    )


def test_bmp_trailing_bytes_are_structural_length_mismatch() -> None:
    result = file_content.bmp_content_observation(
        content=bmp_bytes(trailing=b"padding"),
        subject_ref=r"C:\Users\alice\Documents\PhotoArchive\sample.bmp",
        volume_id="volume-c",
        mft_entry=42,
        sequence_number=3,
    )

    assert result["fields"]["content_length_relation"] == (
        "materialized_exceeds_declared"
    )
    assert result["fields"]["trailing_bytes"] == 7
    assert result["fields"]["declared_content_end"] == 58
    assert result["fields"]["materialized_size"] == 65
    assert result["fields"]["header_parse_status"] == "complete"
    assert result["fields"]["structure_validation"] == ("declared_length_mismatch")


def test_build_file_observations_is_bounded_and_exactly_joined(
    tmp_path: Path, monkeypatch
) -> None:
    volume = tmp_path / "targets" / "C"
    target = volume / "Users" / "alice" / "Documents" / "PhotoArchive"
    target.mkdir(parents=True)
    (target / "sample.bmp").write_bytes(bmp_bytes(trailing=b"padding"))
    (volume / "$MFT").write_bytes(bytes(43 * 1024))
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber,FileSize\n"
        r"C:\Users\alice\Documents\PhotoArchive\sample.bmp,42,3,65"
        "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        file_content, "parse_mft_record", lambda *args, **kwargs: raw_mft_record()
    )

    bundle = file_content.build_file_observations(
        root=tmp_path, mftecmd_csv_path=csv_path
    )

    assert bundle is not None
    assert bundle["candidate_count"] == 1
    assert bundle["matched_count"] == 1
    assert bundle["complete"] is True
    assert len(bundle["storage_observations"]) == 1
    assert len(bundle["content_observations"]) == 1
    assert bundle["truth_sources_used"] == []


def test_build_file_observations_reconstructs_kape_deduplicated_bmp_sources(
    tmp_path: Path, monkeypatch
) -> None:
    volume = tmp_path / "targets" / "F"
    target = volume / "Users" / "alice" / "Documents"
    target.mkdir(parents=True)
    representative = target / "representative.bmp"
    content = bmp_bytes(trailing=b"padding")
    representative.write_bytes(content)
    sha1 = hashlib.sha1(content).hexdigest().upper()
    (volume / "$MFT").write_bytes(bytes(44 * 1024))
    (tmp_path / "targets" / "run_CopyLog.csv").write_text(
        "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,"
        "DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\n"
        f"2026-01-01,F:\\Users\\alice\\Documents\\representative.bmp,"
        "C:\\KAPE\\targets\\F\\Users\\alice\\Documents\\representative.bmp,"
        f"{len(content)},{sha1},False,,,,\n",
        encoding="utf-8",
    )
    (tmp_path / "targets" / "run_SkipLog.csv.csv").write_text(
        "SourceFile,SourceFileSha1,Reason\n"
        f"F:\\Users\\alice\\Documents\\duplicate.bmp,{sha1},Deduped\n",
        encoding="utf-8",
    )
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "ParentPath,FileName,EntryNumber,SequenceNumber,FileSize\n"
        r".\Users\alice\Documents,representative.bmp,42,3,65"
        "\n"
        r".\Users\alice\Documents,duplicate.bmp,43,4,65"
        "\n",
        encoding="utf-8",
    )

    def parse_record(_raw: bytes, *, record_offset: int, record_size: int):
        record = raw_mft_record()
        entry = record_offset // record_size
        record["mft_entry"] = entry
        record["sequence_number"] = 3 if entry == 42 else 4
        return record

    monkeypatch.setattr(file_content, "parse_mft_record", parse_record)

    bundle = file_content.build_file_observations(
        root=tmp_path,
        mftecmd_csv_path=csv_path,
        max_subjects=2,
    )

    assert bundle is not None
    assert bundle["candidate_count"] == 2
    assert bundle["matched_count"] == 2
    assert bundle["complete"] is True
    assert bundle["content_paths"] == [representative]
    assert [item["fields"]["mft_entry"] for item in bundle["content_observations"]] == [
        43,
        42,
    ]
    assert {item["fields"]["sha256"] for item in bundle["content_observations"]} == {
        hashlib.sha256(content).hexdigest()
    }

    with pytest.raises(ValueError, match="subject count exceeds"):
        file_content.build_file_observations(
            root=tmp_path,
            mftecmd_csv_path=csv_path,
            max_subjects=1,
        )


def test_build_file_observations_rejects_unverified_copylog_representative(
    tmp_path: Path,
) -> None:
    target = tmp_path / "targets" / "F" / "Users" / "alice" / "Documents"
    target.mkdir(parents=True)
    representative = target / "representative.bmp"
    representative.write_bytes(bmp_bytes())
    (tmp_path / "targets" / "F" / "$MFT").write_bytes(bytes(43 * 1024))
    (tmp_path / "targets" / "run_CopyLog.csv").write_text(
        "SourceFile,SourceFileSha1\n"
        "F:\\Users\\alice\\Documents\\representative.bmp,"
        "0000000000000000000000000000000000000000\n",
        encoding="utf-8",
    )
    (tmp_path / "targets" / "run_SkipLog.csv.csv").write_text(
        "SourceFile,SourceFileSha1,Reason\n"
        "F:\\Users\\alice\\Documents\\duplicate.bmp,"
        "1111111111111111111111111111111111111111,Deduped\n",
        encoding="utf-8",
    )
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text("FullPath,EntryNumber,SequenceNumber,FileSize\n")

    with pytest.raises(ValueError, match="does not match collected bytes"):
        file_content.build_file_observations(
            root=tmp_path,
            mftecmd_csv_path=csv_path,
        )


def test_build_file_observations_rejects_skiplog_without_exact_sha1_mapping(
    tmp_path: Path,
) -> None:
    target = tmp_path / "targets" / "F" / "Users" / "alice" / "Documents"
    target.mkdir(parents=True)
    representative = target / "representative.bmp"
    content = bmp_bytes()
    representative.write_bytes(content)
    (tmp_path / "targets" / "F" / "$MFT").write_bytes(bytes(43 * 1024))
    (tmp_path / "targets" / "run_CopyLog.csv").write_text(
        "SourceFile,SourceFileSha1\n"
        "F:\\Users\\alice\\Documents\\representative.bmp,"
        f"{hashlib.sha1(content).hexdigest()}\n",
        encoding="utf-8",
    )
    (tmp_path / "targets" / "run_SkipLog.csv.csv").write_text(
        "SourceFile,SourceFileSha1,Reason\n"
        "F:\\Users\\alice\\Documents\\duplicate.bmp,"
        "1111111111111111111111111111111111111111,Deduped\n",
        encoding="utf-8",
    )
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text("FullPath,EntryNumber,SequenceNumber,FileSize\n")

    with pytest.raises(ValueError, match="no exact CopyLog SHA-1 representative"):
        file_content.build_file_observations(
            root=tmp_path,
            mftecmd_csv_path=csv_path,
        )


def test_storage_requires_a_clean_raw_attribute_parse() -> None:
    row = {
        "FullPath": r"C:\Users\alice\Pictures\sample.bmp",
        "EntryNumber": "42",
        "SequenceNumber": "3",
        "FileSize": "58",
    }
    for parse_error_count in (None, 1, True):
        record = raw_mft_record()
        if parse_error_count is None:
            record.pop("attribute_parse_error_count")
        else:
            record["attribute_parse_error_count"] = parse_error_count

        result = file_content.storage_observation(
            row=row,
            raw_record=record,
            volume_id="volume-c",
        )

        assert result is not None
        assert result["fields"]["attribute_chain_complete"] is False


def test_collected_bmp_paths_accepts_only_standard_user_content_folders(
    tmp_path: Path,
) -> None:
    target_root = tmp_path / "targets" / "C" / "Users" / "alice"
    accepted = [
        target_root / "Desktop" / "desktop.bmp",
        target_root / "Documents" / "nested" / "document.bmp",
        target_root / "Downloads" / "download.bmp",
        target_root / "Pictures" / "picture.bmp",
    ]
    rejected = [
        target_root / "AppData" / "hidden.bmp",
        tmp_path / "targets" / "C" / "Temp" / "outside.bmp",
    ]
    for path in accepted + rejected:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bmp_bytes())

    assert file_content.collected_bmp_paths(tmp_path) == sorted(accepted)


def test_verified_population_bound_can_expand_the_content_subject_limit(
    tmp_path: Path,
) -> None:
    target = tmp_path / "targets" / "C" / "Users" / "alice" / "Documents"
    target.mkdir(parents=True)
    for index in range(file_content.MAX_CONTENT_SUBJECTS + 1):
        (target / f"candidate-{index:03d}.bmp").write_bytes(bmp_bytes())

    with pytest.raises(ValueError, match="subject count exceeds"):
        file_content.collected_bmp_paths(tmp_path)

    selected = file_content.collected_bmp_paths(tmp_path, max_subjects=190)
    assert len(selected) == file_content.MAX_CONTENT_SUBJECTS + 1
