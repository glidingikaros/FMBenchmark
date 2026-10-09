from __future__ import annotations

import importlib.util
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLUSTER = 4096
BASE = 20
BASE_REF = BASE | (7 << 48)
PATH = r"C:\Windows\INF\setupapi.dev.log"


def resident(kind, value, identity, name=b""):
    start = (24 + len(name) + 7) & ~7
    raw = bytearray((start + len(value) + 7) & ~7)
    struct.pack_into(
        "<IIBBHHH", raw, 0, kind, len(raw), 0, len(name) // 2, 24, 0, identity
    )
    struct.pack_into("<IH", raw, 16, len(value), start)
    raw[24 : 24 + len(name)] = name
    raw[start : start + len(value)] = value
    return raw


def data(
    low, lcn, *, count=1, logical=3 * CLUSTER + 17, allocated=4 * CLUSTER, identity=4
):
    raw = bytearray(80)
    struct.pack_into("<IIBBHHH", raw, 0, 0x80, len(raw), 1, 0, 64, 0, identity)
    struct.pack_into("<QQH", raw, 16, low, low + count - 1, 64)
    struct.pack_into("<QQQ", raw, 40, allocated, logical, logical)
    raw[64:68] = bytes((0x11, count, lcn, 0))
    return raw


def list_entry(kind, identity, ref=BASE_REF, low=0, name=b""):
    raw = bytearray((26 + len(name) + 7) & ~7)
    struct.pack_into(
        "<IHBBQQH",
        raw,
        0,
        kind,
        len(raw),
        len(name) // 2,
        26 if name else 0,
        low,
        ref,
        identity,
    )
    raw[26 : 26 + len(name)] = name
    return raw


def record(number, attrs, *, sequence=9, base=BASE_REF, flags=1):
    raw = bytearray(1024)
    raw[:4] = b"FILE"
    struct.pack_into("<HH", raw, 4, 48, 3)
    struct.pack_into("<HHHHIIQ", raw, 16, sequence, 1, 56, flags, 0, 1024, base)
    struct.pack_into("<I", raw, 44, number)
    cursor = 56
    for attr in attrs:
        raw[cursor : cursor + len(attr)] = attr
        cursor += len(attr)
    struct.pack_into("<I", raw, cursor, 0xFFFFFFFF)
    struct.pack_into("<I", raw, 24, cursor + 8)
    raw[48:50] = b"\xab\xcd"
    for sector in range(2):
        end = (sector + 1) * 512 - 2
        raw[50 + sector * 2 : 52 + sector * 2] = raw[end : end + 2]
        raw[end : end + 2] = raw[48:50]
    return raw


class MemoryImage:
    format = "raw"
    path = Path("owned-constructed.raw")

    def __init__(self, records):
        self.content = bytearray(128 * CLUSTER)
        for number, raw in records.items():
            start = 4 * CLUSTER + number * 1024
            self.content[start : start + 1024] = raw
        for index, lcn in enumerate((80, 90, 82, 95)):
            self.content[lcn * CLUSTER : (lcn + 1) * CLUSTER] = (
                bytes([65 + index]) * CLUSTER
            )

    def read_at(self, offset, length):
        assert 0 <= offset <= offset + length <= len(self.content)
        return bytes(self.content[offset : offset + length])


def fixture(monkeypatch, *, defect=None):
    spec = importlib.util.spec_from_file_location(
        "native_chain_test", ROOT / "src/fmb/generation/ntfs_surface_injection.py"
    )
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    geometry = {
        "mft_record_size": 1024,
        "bytes_per_sector": 512,
        "bytes_per_cluster": CLUSTER,
        "total_clusters": 128,
        "volume_size_bytes": 128 * CLUSTER,
    }
    mft = {
        "lowest_vcn": 0,
        "runlist_complete": True,
        "attribute_flags": 0,
        "logical_size": 64 * 1024,
        "valid_data_length": 64 * 1024,
        "allocated_size": 64 * 1024,
        "data_runs": [{"vcn": 0, "lcn": 4, "cluster_count": 16}],
    }
    base_attrs = [
        resident(0x10, b"information", 0),
        resident(0x30, b"long name", 1),
        resident(0x30, b"DOS name", 2),
    ]
    entries = [list_entry(a, i) for i, a in enumerate((0x10, 0x30, 0x30))]
    ext_attrs = {21 + i: [data(i, lcn)] for i, lcn in enumerate((80, 90, 82, 95))}
    entries += [list_entry(0x80, 4, n | (9 << 48), i) for i, n in enumerate(ext_attrs)]
    ext_options = {}
    base_options = {"sequence": 7, "base": 0}
    trailing = b""
    if defect == "duplicate_entry":
        entries.append(entries[-1])
    elif defect == "omitted_resident":
        entries.pop(0)
    elif defect == "omitted_last_extent":
        entries.pop()
    elif defect == "extra_extension_attribute":
        ext_attrs[21].append(resident(0x10, b"extra", 8))
    elif defect == "duplicate_attribute_id":
        ext_attrs[21].append(resident(0x10, b"extra", 4))
    elif defect == "nested_list":
        ext_attrs[21].append(resident(0x20, entries[0], 8))
    elif defect == "wrong_sequence":
        struct.pack_into("<Q", entries[3], 16, 21 | (10 << 48))
    elif defect == "alias_sequence":
        entries.append(list_entry(0x80, 4, 21 | (10 << 48), 0))
    elif defect == "wrong_base_ref":
        ext_options[21] = {"base": BASE_REF + 1}
    elif defect == "wrong_base_sequence":
        ext_options[21] = {"base": BASE_REF + (1 << 48)}
    elif defect == "inactive":
        ext_options[21] = {"flags": 0}
    elif defect == "directory":
        ext_options[21] = {"flags": 3}
    elif defect == "nonbase_target":
        base_options["base"] = BASE_REF
    elif defect == "out_of_mft":
        struct.pack_into("<Q", entries[3], 16, 64 | (9 << 48))
    elif defect == "wrong_type":
        struct.pack_into("<I", entries[3], 0, 0x90)
    elif defect == "wrong_id":
        struct.pack_into("<H", entries[3], 24, 6)
    elif defect == "wrong_name":
        entries[3] = list_entry(0x80, 4, 21 | (9 << 48), 0, b"X\0")
    elif defect == "resident_vcn":
        struct.pack_into("<Q", entries[0], 8, 1)
    elif defect == "partial_list":
        trailing = bytes(8)
    elif defect == "nonzero_padding":
        entries[0][-1] = 1
    elif defect == "oversized_entry":
        entries[0].extend(bytes(8))
        struct.pack_into("<H", entries[0], 4, 40)
    elif defect == "short_entry":
        struct.pack_into("<H", entries[0], 4, 24)
    elif defect == "unaligned_entry":
        struct.pack_into("<H", entries[0], 4, 31)
    elif defect == "list_name_bounds":
        entries[0][6:8] = bytes((1, 31))
    elif defect == "list_bad_utf16":
        entries[0] = list_entry(0x10, 0, name=b"\x00\xd8")
    elif defect == "vcns_gap":
        struct.pack_into("<QQ", ext_attrs[22][0], 16, 2, 2)
        struct.pack_into("<Q", entries[4], 8, 2)
    elif defect == "vcns_overlap":
        struct.pack_into("<QQ", ext_attrs[22][0], 16, 0, 0)
        struct.pack_into("<Q", entries[4], 8, 0)
    elif defect == "list_vcn_mismatch":
        struct.pack_into("<Q", entries[4], 8, 2)
    elif defect == "physical_overlap":
        ext_attrs[24][0][66] = 80
    elif defect == "mft_overlap":
        ext_attrs[24][0][66] = 5
    elif defect == "out_of_volume":
        ext_attrs[24][0][64:69] = bytes((0x21, 1, 128, 0, 0))
    elif defect == "invalid_allocated_tail":
        struct.pack_into("<QQ", ext_attrs[21][0], 48, CLUSTER, CLUSTER)
        ext_attrs[24][0][64:69] = bytes((0x21, 1, 128, 0, 0))
    elif defect == "wrong_allocated":
        struct.pack_into("<Q", ext_attrs[21][0], 40, 5 * CLUSTER)
    elif defect == "uninitialized":
        struct.pack_into("<Q", ext_attrs[21][0], 56, CLUSTER)
    elif defect == "logical_too_long":
        struct.pack_into("<QQ", ext_attrs[21][0], 48, 5 * CLUSTER, 5 * CLUSTER)
    elif defect == "over_byte_bound":
        struct.pack_into(
            "<QQ", ext_attrs[21][0], 48, 65 * 1024 * 1024, 65 * 1024 * 1024
        )
    elif defect in ("sparse_flag", "compressed", "encrypted"):
        struct.pack_into(
            "<H",
            ext_attrs[22][0],
            12,
            {"sparse_flag": 0x8000, "compressed": 1, "encrypted": 0x4000}[defect],
        )
    elif defect == "compression_unit":
        struct.pack_into("<H", ext_attrs[22][0], 34, 4)
    elif defect == "sparse_run":
        ext_attrs[22][0][64:68] = bytes((1, 1, 0, 0))
    elif defect == "zero_run":
        ext_attrs[22][0][65] = 0
    elif defect == "run_count_mismatch":
        ext_attrs[22][0][65] = 2
    elif defect == "missing_terminator":
        ext_attrs[22][0][67:] = bytes([0x11]) * 13
    elif defect == "resident_data":
        ext_attrs[22][0] = resident(0x80, b"contents", 4)
    elif defect == "attribute_bad_name":
        ext_attrs[22][0][9] = 1
        struct.pack_into("<H", ext_attrs[22][0], 10, 79)
    elif defect == "nonresident_list":
        base_attrs.append(data(0, 100, identity=3))
        struct.pack_into("<I", base_attrs[-1], 0, 0x20)
    elif defect == "same_record_data":
        base_attrs.extend(ext_attrs.pop(21))
        struct.pack_into("<Q", entries[3], 16, BASE_REF)
    elif defect == "valid_allocated_tail":
        struct.pack_into("<QQ", ext_attrs[21][0], 48, CLUSTER, CLUSTER)
    elif defect == "negative_lcn_delta":
        struct.pack_into("<Q", ext_attrs[21][0], 24, 1)
        struct.pack_into(
            "<QQQ",
            ext_attrs[21][0],
            40,
            5 * CLUSTER,
            4 * CLUSTER + 17,
            4 * CLUSTER + 17,
        )
        ext_attrs[21][0][64:71] = bytes((0x11, 1, 80, 0x11, 1, 254, 0))
        for index in range(1, 4):
            struct.pack_into("<QQ", ext_attrs[21 + index][0], 16, index + 1, index + 1)
            struct.pack_into("<Q", entries[3 + index], 8, index + 1)
    if defect != "nonresident_list":
        base_attrs.append(resident(0x20, b"".join(entries) + trailing, 3))
    records = {BASE: record(BASE, base_attrs, **base_options)}
    records.update(
        {n: record(n, a, **ext_options.get(n, {})) for n, a in ext_attrs.items()}
    )
    if defect == "bad_usa_count":
        struct.pack_into("<H", records[21], 6, 2)
    elif defect == "bad_usa_offset":
        struct.pack_into("<H", records[21], 4, 32)
    elif defect == "bad_usa_trailer":
        records[21][510] ^= 1
    elif defect == "missing_end":
        struct.pack_into("<I", records[21], 24, 56 + 80)
    elif defect == "short_end":
        struct.pack_into("<I", records[21], 24, 56 + 80 + 4)
    elif defect == "oversized_end":
        struct.pack_into("<I", records[21], 24, 56 + 80 + 16)
    elif defect == "nonzero_padding":
        records[21][56 + 80 + 4 : 56 + 80 + 8] = b"PAD!"
    image = MemoryImage(records)
    monkeypatch.setattr(native, "QemuImageReader", lambda _: image)
    monkeypatch.setattr(
        native,
        "_locate",
        lambda *_: (
            0,
            geometry,
            mft,
            {
                native._canonical_path(PATH): {
                    "mft_entry": BASE,
                    "sequence_number": 7,
                    "raw": bytes(records[BASE]),
                }
            },
        ),
    )
    return native, image, records


def test_four_extension_native_shape_roundtrip_preserves_all_other_bytes(monkeypatch):
    native, image, _records = fixture(monkeypatch)
    before = bytes(image.content)
    calls, seen = [], []

    def writer(argv, **kwargs):
        assert argv[:4] == ["qemu-io", "-f", "raw", "-c"]
        _, _, filename, start, size = argv[4].split()
        payload = (Path(kwargs["cwd"]) / filename).read_bytes()
        assert len(payload) == int(size)
        image.content[int(start) : int(start) + int(size)] = payload
        calls.append((int(start), int(size)))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(native.subprocess, "run", writer)
    monkeypatch.setattr(native, "QEMU_IO_PAYLOADS_ARE_BINARY", True)

    def transform(raw):
        seen.append(raw)
        return bytes(value ^ 0x20 for value in raw), {"constructed_control": True}

    receipt = native.transform_native_file(image.path, PATH, transform)
    original = b"A" * CLUSTER + b"B" * CLUSTER + b"C" * CLUSTER + b"D" * 17
    assert seen == [original]
    assert len(calls) == 4
    expected = bytearray(before)
    for lcn, length in ((80, CLUSTER), (90, CLUSTER), (82, CLUSTER), (95, 17)):
        expected[lcn * CLUSTER : lcn * CLUSTER + length] = bytes(
            v ^ 0x20 for v in before[lcn * CLUSTER : lcn * CLUSTER + length]
        )
    assert image.content == expected
    assert receipt["attribute_chain"]["record_count"] == 5
    assert receipt["attribute_chain"]["attribute_list_entry_count"] == 7
    assert receipt["attribute_chain"]["data_extent_count"] == 4
    assert receipt["metadata_unchanged"] is True
    assert receipt["postcondition_verified"] is True


@pytest.mark.parametrize(
    "defect",
    [
        "duplicate_entry",
        "omitted_resident",
        "omitted_last_extent",
        "extra_extension_attribute",
        "duplicate_attribute_id",
        "nested_list",
        "wrong_sequence",
        "alias_sequence",
        "wrong_base_ref",
        "wrong_base_sequence",
        "inactive",
        "directory",
        "nonbase_target",
        "out_of_mft",
        "wrong_type",
        "wrong_id",
        "wrong_name",
        "resident_vcn",
        "partial_list",
        "oversized_entry",
        "short_entry",
        "unaligned_entry",
        "list_name_bounds",
        "list_bad_utf16",
        "vcns_gap",
        "vcns_overlap",
        "list_vcn_mismatch",
        "physical_overlap",
        "mft_overlap",
        "out_of_volume",
        "invalid_allocated_tail",
        "wrong_allocated",
        "logical_too_long",
        "over_byte_bound",
        "sparse_flag",
        "compressed",
        "encrypted",
        "compression_unit",
        "sparse_run",
        "zero_run",
        "run_count_mismatch",
        "missing_terminator",
        "resident_data",
        "attribute_bad_name",
        "nonresident_list",
        "bad_usa_count",
        "bad_usa_offset",
        "bad_usa_trailer",
        "missing_end",
        "short_end",
        "oversized_end",
    ],
)
def test_incomplete_or_ambiguous_chain_never_invokes_callback_or_writer(
    monkeypatch, defect
):
    native, image, _ = fixture(monkeypatch, defect=defect)
    before = bytes(image.content)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("invalid chain reached writer"),
    )
    with pytest.raises(ValueError):
        native.transform_native_file(
            image.path, PATH, lambda _: pytest.fail("invalid chain reached callback")
        )
    assert image.content == before


def test_uninitialized_tail_is_zero_filled_and_never_written(monkeypatch):
    native, image, _ = fixture(monkeypatch, defect="uninitialized")
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("identity callback caused write"),
    )
    seen = {}

    def probe(raw):
        seen["raw"] = raw
        return raw, {}

    receipt = native.transform_native_file(image.path, PATH, probe)
    assert receipt["initialized_bytes"] < receipt["size_bytes"] == len(seen["raw"])
    assert not any(seen["raw"][receipt["initialized_bytes"]:])
    assert receipt["written_ranges"] == []
    with pytest.raises(ValueError, match="beyond the initialized"):
        native.transform_native_file(
            image.path, PATH, lambda raw: (raw[:-1] + bytes([raw[-1] ^ 1]), {})
        )


def test_base_and_extension_data_extents_are_combined(monkeypatch):
    native, image, _ = fixture(monkeypatch, defect="same_record_data")
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("identity callback caused write"),
    )
    receipt = native.transform_native_file(image.path, PATH, lambda raw: (raw, {}))
    assert receipt["attribute_chain"]["record_count"] == 4
    assert receipt["attribute_chain"]["data_extent_count"] == 4
    assert receipt["written_ranges"] == []


@pytest.mark.parametrize(
    "shape", ["nonzero_padding", "valid_allocated_tail", "negative_lcn_delta"]
)
def test_valid_alignment_preallocation_and_signed_extent_mapping(monkeypatch, shape):
    native, image, _ = fixture(monkeypatch, defect=shape)
    before = bytes(image.content)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("identity callback caused write"),
    )
    seen = []

    def identity(raw):
        seen.append(raw)
        return raw, {}

    receipt = native.transform_native_file(image.path, PATH, identity)
    expected = b"A" * CLUSTER + b"B" * CLUSTER + b"C" * CLUSTER + b"D" * 17
    if shape == "valid_allocated_tail":
        expected = b"A" * CLUSTER
    elif shape == "negative_lcn_delta":
        expected = (
            b"A" * CLUSTER
            + bytes(CLUSTER)
            + b"B" * CLUSTER
            + b"C" * CLUSTER
            + b"D" * 17
        )
    assert seen == [expected]
    assert receipt["written_ranges"] == []
    assert image.content == before


def test_metadata_change_in_callback_refuses_before_first_write(monkeypatch):
    native, image, _ = fixture(monkeypatch)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("changed metadata reached writer"),
    )

    def transform(raw):
        image.content[4 * CLUSTER + 21 * 1024 + 8] ^= 1
        return b"z" + raw[1:], {}

    with pytest.raises(ValueError, match="changed during"):
        native.transform_native_file(image.path, PATH, transform)


def test_length_change_refuses_before_first_write(monkeypatch):
    native, image, _ = fixture(monkeypatch)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("length change reached writer"),
    )
    with pytest.raises(ValueError, match="equal-length"):
        native.transform_native_file(image.path, PATH, lambda raw: (raw + b"x", {}))
