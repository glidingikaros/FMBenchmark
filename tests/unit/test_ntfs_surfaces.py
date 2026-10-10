from __future__ import annotations

import importlib.util
import shutil
import struct
from pathlib import Path

import pytest

from fmb.collection.ntfs_surfaces import collect_ntfs_surfaces
from fmb.index.adapters.i30 import FULL_I30_SURFACE, bounded_i30_parser_run
from fmb.index.adapters.ntfs_allocation import (
    load_native_surfaces,
    ntfs_allocation_parser_run,
)
from fmb.index.scanners.mft import parse_mapping_pairs, parse_mft_record
from fmb.index.scanners.ntfs import (
    parse_boot_sector,
    parse_index_allocation,
    read_nonresident_stream,
)


needs_tsk = pytest.mark.skipif(
    not all(importlib.util.find_spec(name) for name in ("pytsk3", "pyvmdk")),
    reason="pytsk3 and libvmdk-python are required for image reads",
)


def _fn(name: str, parent: int = 20, sequence: int = 3) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    struct.pack_into("<Q", value, 0, parent | sequence << 48)
    value[64:66] = bytes((len(name), 1))
    value[66:] = encoded
    return bytes(value)


def _resident(kind: int, value: bytes, *, name: str = "", identity: int = 1) -> bytes:
    encoded = name.encode("utf-16le")
    start = (24 + len(encoded) + 7) & ~7
    result = bytearray((start + len(value) + 7) & ~7)
    struct.pack_into("<II", result, 0, kind, len(result))
    result[9] = len(name)
    struct.pack_into("<H", result, 10, 24)
    struct.pack_into("<H", result, 14, identity)
    struct.pack_into("<IH", result, 16, len(value), start)
    result[24 : 24 + len(encoded)] = encoded
    result[start : start + len(value)] = value
    return bytes(result)


def _nonresident(
    kind: int,
    *,
    lcn: int = 50,
    count: int = 2,
    logical: int = 4097,
    name: str = "",
    identity: int = 2,
    allocated: int | None = None,
) -> bytes:
    encoded = name.encode("utf-16le")
    mapping = (64 + len(encoded) + 7) & ~7
    result = bytearray((mapping + 4 + 7) & ~7)
    struct.pack_into("<II", result, 0, kind, len(result))
    result[8] = 1
    result[9] = len(name)
    struct.pack_into("<H", result, 10, 64)
    struct.pack_into("<H", result, 14, identity)
    struct.pack_into("<QQH", result, 16, 0, count - 1, mapping)
    struct.pack_into(
        "<QQQ",
        result,
        40,
        count * 4096 if allocated is None else allocated,
        logical,
        logical,
    )
    result[64 : 64 + len(encoded)] = encoded
    result[mapping : mapping + 4] = bytes((0x11, count, lcn, 0))
    return bytes(result)


def _protect(
    value: bytearray, *, magic: bytes, usa: int, first: int | None = None
) -> bytes:
    value[:4] = magic
    count = len(value) // 512 + 1
    struct.pack_into("<HH", value, 4, usa, count)
    struct.pack_into("<H", value, usa, 0xBBAA)
    for sector in range(count - 1):
        end = (sector + 1) * 512 - 2
        value[usa + 2 + sector * 2 : usa + 4 + sector * 2] = value[end : end + 2]
        value[end : end + 2] = b"\xaa\xbb"
    return bytes(value)


def _record(
    entry: int, attributes: list[bytes], *, sequence: int = 1, flags: int = 1
) -> bytes:
    result = bytearray(1024)
    struct.pack_into("<HHH", result, 16, sequence, 1, 56)
    struct.pack_into("<H", result, 22, flags)
    struct.pack_into("<I", result, 28, 1024)
    struct.pack_into("<I", result, 44, entry)
    offset = 56
    for attr in attributes:
        result[offset : offset + len(attr)] = attr
        offset += len(attr)
    struct.pack_into("<I", result, offset, 0xFFFFFFFF)
    struct.pack_into("<I", result, 24, offset + 8)
    return _protect(result, magic=b"FILE", usa=48)


def _entry(name: str, entry: int, sequence: int = 1) -> bytes:
    key = _fn(name)
    result = bytearray((16 + len(key) + 7) & ~7)
    struct.pack_into("<QHH", result, 0, entry | sequence << 48, len(result), len(key))
    result[16 : 16 + len(key)] = key
    return bytes(result)


def _index() -> bytes:
    live = _entry("ordinary.bin", 30)
    removed = _entry("removed.bin", 31, 7)
    result = bytearray(4096)
    struct.pack_into("<Q", result, 16, 0)
    used = 40 + len(live) + 16
    struct.pack_into("<III", result, 24, 40, used, 4096 - 24)
    result[64 : 64 + len(live)] = live
    struct.pack_into("<HH", result, 64 + len(live) + 8, 16, 0)
    struct.pack_into("<H", result, 64 + len(live) + 12, 2)
    result[24 + used : 24 + used + len(removed)] = removed
    return _protect(result, magic=b"INDX", usa=40)


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    image = bytearray(128 * 4096)
    image[3:11] = b"NTFS    "
    struct.pack_into("<H", image, 11, 512)
    image[13] = 8
    struct.pack_into("<QQQ", image, 40, 1024, 4, 2)
    struct.pack_into("<b", image, 64, -10)
    struct.pack_into("<b", image, 68, -12)
    struct.pack_into("<Q", image, 72, 0x1122334455667788)
    image[510:512] = b"\x55\xaa"
    mft = bytearray(40 * 1024)
    root_value = bytearray(48)
    struct.pack_into("<III", root_value, 0, 0x30, 1, 4096)
    struct.pack_into("<III", root_value, 16, 16, 32, 32)
    struct.pack_into("<HH", root_value, 40, 16, 0)
    struct.pack_into("<H", root_value, 44, 2)
    records = {
        0: _record(
            0,
            [
                _resident(0x30, _fn("$MFT", 5, 1)),
                _nonresident(0x80, lcn=4, count=10, logical=len(mft)),
            ],
        ),
        3: _record(
            3,
            [
                _resident(0x30, _fn("$Volume", 5, 1)),
                _resident(0x70, bytes(8) + bytes((3, 1, 0, 0)), identity=2),
            ],
        ),
        5: _record(
            5,
            [
                _resident(0x30, _fn(".", 5, 1)),
                _resident(0x90, bytes(root_value), name="$I30", identity=2),
            ],
            flags=3,
        ),
        6: _record(
            6,
            [
                _resident(0x30, _fn("$Bitmap", 5, 1)),
                _nonresident(0x80, lcn=127, count=1, logical=16),
            ],
        ),
        20: _record(
            20,
            [
                _resident(0x30, _fn("Cases", 5, 1)),
                _resident(0x90, bytes(root_value), name="$I30", identity=2),
                _nonresident(
                    0xA0, lcn=60, count=1, logical=4096, name="$I30", identity=3
                ),
                _resident(0xB0, b"\x01", name="$I30", identity=4),
            ],
            sequence=3,
            flags=3,
        ),
        30: _record(
            30,
            [
                _resident(0x30, _fn("ordinary.bin")),
                _nonresident(0x80),
                _resident(
                    0x80,
                    b"[ZoneTransfer]\r\nZoneId=3",
                    name="Zone.Identifier",
                    identity=3,
                ),
            ],
        ),
        31: _record(
            31,
            [_resident(0x30, _fn("removed.bin")), _nonresident(0x80, lcn=53)],
            sequence=7,
            flags=0,
        ),
        32: _record(
            32,
            [
                _resident(0x30, _fn("preallocated.bin")),
                _nonresident(0x80, lcn=55, count=3),
            ],
        ),
    }
    for entry, record in records.items():
        mft[entry * 1024 : (entry + 1) * 1024] = record
    image[4 * 4096 : 4 * 4096 + len(mft)] = mft
    image[50 * 4096 : 50 * 4096 + 4097] = b"z" * 4097
    image[60 * 4096 : 61 * 4096] = _index()
    image[127 * 4096 : 127 * 4096 + 16] = b"\xff" * 16
    path = tmp_path / "source.raw"
    path.write_bytes(image)
    mft_path = tmp_path / "$MFT"
    mft_path.write_bytes(mft)
    csv = tmp_path / "mft.csv"
    csv.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n20,3,True,.,Cases,True\n",
        encoding="utf-8",
    )
    return path, mft_path, csv


def test_runlist_decodes_signed_lcn_deltas_and_sparse_runs() -> None:
    raw = bytes((0x11, 3, 100, 0x01, 2, 0x11, 1, 246, 0))
    facts = parse_mapping_pairs(raw, start=0, end=len(raw), expected_cluster_count=6)
    assert facts["runlist_complete"] is True
    assert facts["data_runs"] == [
        {"vcn": 0, "lcn": 100, "cluster_count": 3},
        {"vcn": 3, "lcn": None, "cluster_count": 2},
        {"vcn": 5, "lcn": 90, "cluster_count": 1},
    ]
    assert (
        parse_mapping_pairs(
            bytes((0x11, 1, 255, 0)), start=0, end=4, expected_cluster_count=1
        )["runlist_complete"]
        is False
    )


def test_index_allocation_retains_distinct_active_and_slack_surfaces() -> None:
    result = parse_index_allocation(
        _index(),
        bitmap=b"\x01",
        block_size=4096,
        sector_size=512,
        cluster_size=4096,
        parent_entry=20,
        parent_sequence=3,
    )
    assert result["index_allocation_parsed"] is True
    assert [(item["name"], item["residue_surface"]) for item in result["entries"]] == [
        ("ordinary.bin", "index_allocation_active"),
        ("removed.bin", "index_allocation_slack"),
    ]
    inactive = parse_index_allocation(
        _index(),
        bitmap=b"\x00",
        block_size=4096,
        sector_size=512,
        cluster_size=4096,
        parent_entry=20,
        parent_sequence=3,
    )
    assert {item["residue_surface"] for item in inactive["entries"]} == {
        "index_allocation_unallocated_buffer"
    }
    corrupt = bytearray(_index())
    corrupt[510] ^= 1
    failed = parse_index_allocation(
        bytes(corrupt),
        bitmap=b"\x01",
        block_size=4096,
        sector_size=512,
        cluster_size=4096,
        parent_entry=20,
        parent_sequence=3,
    )
    assert failed["index_allocation_parsed"] is False
    assert failed["entries"] == []
    with pytest.raises(ValueError, match="bitmap"):
        parse_index_allocation(
            _index(),
            bitmap=b"",
            block_size=4096,
            sector_size=512,
            cluster_size=4096,
            parent_entry=20,
            parent_sequence=3,
        )


@needs_tsk
def test_native_disk_binding_stream_collection_and_allocation_facts(
    tmp_path: Path,
) -> None:
    image, mft, csv = _fixture(tmp_path)
    manifest = collect_ntfs_surfaces(
        evidence_image=image,
        raw_mft_path=mft,
        output_dir=tmp_path / "native",
        records=[
            {
                "mft_entry": 20,
                "sequence_number": 3,
                "subject_ref": r"C:\Cases",
                "kind": "directory",
            },
            {
                "mft_entry": 30,
                "sequence_number": 1,
                "subject_ref": r"C:\Cases\ordinary.bin",
                "kind": "file",
            },
            {
                "mft_entry": 32,
                "sequence_number": 1,
                "subject_ref": r"C:\Cases\preallocated.bin",
                "kind": "file",
            },
        ],
    )
    allocation = ntfs_allocation_parser_run(
        native_manifest_path=manifest,
        raw_mft_path=mft,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape"},
        filesystem_scope_id="mft-source:csv-id",
    )
    assert allocation["coverage_status"] == "complete"
    ordinary, preallocated = [item["fields"] for item in allocation["observations"]]
    assert ordinary["logical_size"] == 4097 and ordinary["allocated_size"] == 8192
    assert (
        preallocated["logical_size"] == 4097 and preallocated["allocated_size"] == 12288
    )
    for fields in (ordinary, preallocated):
        assert (
            fields["allocated_size"]
            == fields["allocated_cluster_count"] * fields["bytes_per_cluster"]
        )
        assert (
            fields["attribute_chain_complete"]
            and fields["native_identity_verified"]
            and fields["runlist_in_volume"]
        )
        assert fields["mft_volume_id"] == "mft-source:csv-id"
    run = bounded_i30_parser_run(
        mft_csv_path=csv,
        raw_mft_path=mft,
        directory_paths=(r"C:\Cases",),
        normalized_output_dir=tmp_path / "i30",
        collector_run={"collector": "kape"},
        native_manifest_path=manifest,
    )
    assert run["coverage_status"] == "complete"
    scan, residue = run["observations"]
    assert scan["fields"]["supported_surface"] == FULL_I30_SURFACE
    assert scan["fields"]["index_allocation_parsed"] is True
    assert residue["fields"]["entry_name"] == "removed.bin"
    assert residue["fields"]["mft_active_presence_status"] == "active_mft_absent"
    missing = bounded_i30_parser_run(
        mft_csv_path=csv,
        raw_mft_path=mft,
        directory_paths=(r"C:\Cases",),
        normalized_output_dir=tmp_path / "missing",
        collector_run={"collector": "kape"},
    )
    assert missing["coverage_status"] == "partial"
    assert missing["observations"][0]["fields"]["scan_complete"] is False
    raw = bytearray(mft.read_bytes())
    raw[30 * 1024 + 500] ^= 1
    mft.write_bytes(raw)
    with pytest.raises(ValueError, match="bind"):
        load_native_surfaces(manifest, mft)


@pytest.mark.skipif(shutil.which("qemu-io") is None, reason="QEMU unavailable")
def test_generation_intervention_preserves_content_and_changes_only_allocation_header(
    tmp_path: Path,
) -> None:
    image, _mft, _csv = _fixture(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "native_generation_test",
        Path(__file__).parents[2] / "src/fmb/generation" / "ntfs_surface_injection.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    transformed = module.transform_native_file(
        image,
        r"C:\Cases\ordinary.bin",
        lambda value: (b"a" + value[1:], {"test": True}),
    )
    assert transformed["postcondition_verified"] and transformed["metadata_unchanged"]
    assert image.read_bytes()[50 * 4096 : 50 * 4096 + 2] == b"az"
    before = image.read_bytes()
    receipt = module.mutate_allocation_headers(
        image,
        [r"C:\Cases\ordinary.bin"],
        validation_paths=[r"C:\Cases\ordinary.bin", r"C:\Cases\preallocated.bin"],
    )
    assert receipt["postcondition_verified"] and receipt["operation_count"] == 1
    after = image.read_bytes()
    base = 4 * 4096 + 30 * 1024
    assert (
        before[:base] == after[:base] and before[base + 1024 :] == after[base + 1024 :]
    )
    data = parse_mft_record(after[base : base + 1024], record_size=1024)[
        "data_attributes"
    ][0]
    assert data["allocated_size"] == 12288 and data["allocated_cluster_count"] == 2
    assert data["logical_size"] == 4097
    with pytest.raises(ValueError, match="sizes disagree"):
        module.transform_native_file(
            image,
            r"C:\Cases\ordinary.bin",
            lambda _: pytest.fail("inconsistent allocation must fail before callback"),
        )


def test_native_stream_bounds_and_sparse_materialization(tmp_path: Path) -> None:
    image, _mft, _csv = _fixture(tmp_path)
    geometry = parse_boot_sector(image.read_bytes()[:512])
    attr = {
        "runlist_complete": True,
        "lowest_vcn": 0,
        "logical_size": 8192,
        "valid_data_length": 8192,
        "data_runs": [{"vcn": 0, "lcn": None, "cluster_count": 2}],
    }
    assert read_nonresident_stream(
        lambda *_: pytest.fail("sparse run must not read disk"), attr, geometry
    ) == bytes(8192)
    attr["data_runs"][0]["lcn"] = geometry["total_clusters"] - 1
    with pytest.raises(ValueError, match="outside"):
        read_nonresident_stream(lambda *_: b"", attr, geometry)


@pytest.mark.skipif(shutil.which("qemu-io") is None, reason="QEMU unavailable")
def test_usb_history_intervention_preserves_identity_and_sparse_journal_holes(
    tmp_path: Path,
) -> None:
    from fmb.index.scanners.usb_volume import parse_retained_journal

    image, _mft, _csv = _fixture(tmp_path)
    data = bytearray(image.read_bytes())
    journal_attr = bytearray(
        _nonresident(0x80, lcn=90, count=2, logical=8192, name="$J")
    )
    struct.pack_into("<H", journal_attr, 12, 0x8000)
    mapping = struct.unpack_from("<H", journal_attr, 32)[0]
    journal_attr[mapping : mapping + 6] = bytes((0x01, 1, 0x11, 1, 90, 0))
    maximum = struct.pack("<QQQQ", 65536, 4096, 123, 0)
    records = {
        31: _record(
            31,
            [_resident(0x30, _fn("removed.bin")), _nonresident(0x80, lcn=53)],
            sequence=8,
            flags=0,
        ),
        24: _record(24, [_resident(0x30, _fn("$Extend", 5, 1))], flags=3),
        25: _record(
            25,
            [
                _resident(0x30, _fn("$UsnJrnl", 24, 1)),
                bytes(journal_attr),
                _resident(0x80, maximum, name="$Max", identity=3),
            ],
        ),
    }
    for entry, value in records.items():
        offset = 4 * 4096 + entry * 1024
        data[offset : offset + 1024] = value
    usn = bytearray(88)
    reference = 31 | 7 << 48
    name = "removed.bin".encode("utf-16le")
    struct.pack_into(
        "<IHHQQqQIIIIHH",
        usn,
        0,
        len(usn),
        2,
        0,
        reference,
        20 | 3 << 48,
        4096,
        133000000000000000,
        0x80000200,
        0,
        0,
        0,
        len(name),
        60,
    )
    usn[60 : 60 + len(name)] = name
    data[90 * 4096 : 90 * 4096 + len(usn)] = usn
    image.write_bytes(data)
    spec = importlib.util.spec_from_file_location(
        "native_usb_generation_test",
        Path(__file__).parents[2] / "src/fmb/generation" / "ntfs_surface_injection.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError, match="inactive immediate successor"):
        module.rewrite_usb_history_names(
            image,
            file_reference_number=31 | 9 << 48,
            original_name="removed.bin",
            replacement_name="changed.bin",
        )
    assert image.read_bytes() == data
    receipt = module.rewrite_usb_history_names(
        image,
        file_reference_number=reference,
        original_name="removed.bin",
        replacement_name="changed.bin",
    )
    after = image.read_bytes()
    changed = {
        i for i, pair in enumerate(zip(data, after, strict=True)) if pair[0] != pair[1]
    }
    permitted = {
        i
        for patch in receipt["written_ranges"]
        for i in range(
            patch["physical_offset"], patch["physical_offset"] + patch["size_bytes"]
        )
    }
    assert changed and changed <= permitted
    assert receipt["postcondition_verified"] and receipt["object_activity_preserved"]
    mft_offset = 4 * 4096 + 31 * 1024
    native = parse_mft_record(after[mft_offset : mft_offset + 1024], record_size=1024)
    assert native["sequence_number"] == 8 and native["file_record_flags"] == 0
    assert native["file_name_attributes"][0]["name"] == "changed.bin"
    history = parse_retained_journal(
        bytes(4096) + after[90 * 4096 : 91 * 4096], maximum
    )
    row = history["records"][0]
    assert history["scan_complete"] and row["file_name"] == "changed.bin"
    assert row["file_reference_number"] == reference and row["reason"] == 0x80000200
    assert row["timestamp_filetime"] == 133000000000000000 and row["usn"] == 4096


@needs_tsk
def test_post_kape_hook_collects_public_rosters_and_preserves_native_stream_content(
    tmp_path: Path,
) -> None:
    from fmb.collection.alignment import add_native_population_surfaces
    from fmb.core.hashing import sha256_file
    from fmb.core.json_io import load_json

    image, old_mft, old_csv = _fixture(tmp_path)
    root = tmp_path / "kape-output"
    raw_mft = root / "targets" / "F" / "$MFT"
    raw_mft.parent.mkdir(parents=True)
    raw_mft.write_bytes(old_mft.read_bytes())
    csv = root / "modules" / "FileSystem" / "MFTECmd_$MFT_Output.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text(
        old_csv.read_text()
        + "30,1,True,.\\Cases,ordinary.bin,False\n32,1,True,.\\Cases,preallocated.bin,False\n"
    )
    index = {
        "collector_runs": [{"collector": "kape", "output_root": str(root)}],
        "parser_runs": [
            {"parser_kind": "ntfs_mft", "raw_outputs": [{"path": str(raw_mft)}]}
        ],
    }
    scenarios = {}
    for technique, subject in (
        ("i30_directory_residue", r"C:\Cases"),
        ("alternate_data_stream", r"C:\Cases\ordinary.bin"),
        ("ntfs_allocation_inconsistency", r"C:\Cases\preallocated.bin"),
    ):
        scenarios[technique] = {
            "technique_id": technique,
            "members": [{"subject_ref": subject, "identity_hint": {}}],
        }
    output = add_native_population_surfaces(
        index,
        manifest={"scenarios": scenarios},
        evidence_image=image,
        evidence_sha256=sha256_file(image),
        output_dir=tmp_path / "prepared",
    )
    runs = output["parser_runs"]
    assert len(runs) == 4
    assert [run["coverage_status"] for run in runs[1:]] == ["complete"] * 3
    ads = next(run for run in runs if run["parser_kind"] == "ntfs_ads")
    assert len(ads["observations"]) == 1
    fields = ads["observations"][0]["fields"]
    assert fields["content_complete"] is True
    assert fields["stream_name"] == "Zone.Identifier"
    assert fields["pe_structure_status"] == "not_pe"
    for run in runs[1:]:
        normalized = run["normalized_output"]
        normalized_path = Path(normalized["path"])
        payload = load_json(normalized_path)
        assert payload["parser_kind"] == run["parser_kind"]
        assert (
            payload["record_count"]
            == run["observation_count"]
            == len(run["observations"])
        )
        assert normalized["record_count"] == payload["record_count"]
        assert payload["observations"] == run["observations"]
        assert (
            payload["truth_sources_used"]
            == run["provenance"]["truth_sources_used"]
            == []
        )
        assert normalized["sha256"] == sha256_file(normalized_path)
        assert normalized["size_bytes"] == normalized_path.stat().st_size
        manifests = []
        for raw_output in run["raw_outputs"]:
            raw_path = Path(raw_output["path"])
            assert raw_output["sha256"] == sha256_file(raw_path)
            assert raw_output["size_bytes"] == raw_path.stat().st_size
            if raw_path.suffix == ".json":
                source = load_json(raw_path)
                if source.get("schema_version") == "native_ntfs_surfaces.v1":
                    manifests.append(source)
        assert len(manifests) == 1
        assert manifests[0]["raw_mft_sha256"] == sha256_file(raw_mft)


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="QEMU unavailable")
def test_generation_transform_honours_valid_data_length(tmp_path: Path) -> None:
    image, _mft, _csv = _fixture(tmp_path)
    raw = bytearray(image.read_bytes())
    record_offset = 4 * 4096 + 32 * 1024
    initialized_offset = record_offset + 184 + 56
    assert struct.unpack_from("<Q", raw, initialized_offset)[0] == 4097
    struct.pack_into("<Q", raw, initialized_offset, 4096)
    image.write_bytes(bytes(raw))
    spec = importlib.util.spec_from_file_location(
        "native_generation_vdl_test",
        Path(__file__).parents[2] / "src/fmb/generation" / "ntfs_surface_injection.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    seen = {}

    def probe(value: bytes) -> tuple[bytes, dict]:
        seen["length"] = len(value)
        seen["tail"] = value[4096:]
        return value, {"probe": True}

    receipt = module.transform_native_file(image, r"C:\Cases\preallocated.bin", probe)
    assert seen["length"] == 4097 and seen["tail"] == b"\x00"
    assert receipt["initialized_bytes"] == 4096 and receipt["size_bytes"] == 4097
    assert receipt["written_ranges"] == []
    with pytest.raises(ValueError, match="beyond the initialized"):
        module.transform_native_file(
            image, r"C:\Cases\preallocated.bin", lambda value: (value[:4096] + b"x", {})
        )
    written = module.transform_native_file(
        image, r"C:\Cases\preallocated.bin", lambda value: (b"q" + value[1:], {})
    )
    assert [row["byte_count"] for row in written["written_ranges"]] == [4096]
    disk = image.read_bytes()
    assert disk[55 * 4096] == ord("q") and disk[55 * 4096 + 4096] == 0


@needs_tsk
def test_native_manifest_records_the_supplied_image_path_not_a_symlink_target(tmp_path: Path) -> None:
    import json

    image, mft, _csv = _fixture(tmp_path)
    supplied = tmp_path / "generation" / "full_scale.vmdk"
    supplied.parent.mkdir()
    supplied.symlink_to(image)
    manifest = collect_ntfs_surfaces(
        evidence_image=supplied,
        raw_mft_path=mft,
        output_dir=tmp_path / "native",
        records=[{"mft_entry": 30, "sequence_number": 1, "subject_ref": r"C:\Cases\ordinary.bin", "kind": "file"}],
    )
    assert json.loads(Path(manifest).read_text())["evidence_image"] == str(supplied.absolute())
