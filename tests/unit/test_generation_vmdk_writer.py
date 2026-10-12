from __future__ import annotations

import errno
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from fmb.generation import vmdk_writer
from fmb.generation.pipeline import GenerationPipeline
from fmb.generation.vmdk_writer import GRAIN, HEADER, SECTOR, SparseDisk, Unsupported

GIB = 1 << 30
QEMU = shutil.which("qemu-img") is not None and shutil.which("qemu-io") is not None
needs_qemu = pytest.mark.skipif(not QEMU, reason="qemu-img and qemu-io build the VMware sparse disks")
needs_writer = pytest.mark.skipif(not all(hasattr(os, name) for name in ("pread", "pwrite", "writev")),
                                  reason="fmb's VMDK writer needs positional and vectored file writes")

# A 2 GiB + 1 MiB + 3 sectors disk: two extents, the second ending three sectors into its last grain.
SIZE = 2 * GIB + 2**20 + 3 * SECTOR
WRITES = [
    "write -P 0x11 0 64k",
    "write -P 0x22 1m 9m",  # longer than one 8 MiB read
    "write -P 0 20m 1m",  # grains the source holds that contain only zeros
    "write -P 0x33 30m 512",  # one sector at the start of a grain, one at the end of another
    f"write -P 0x44 {30 * 2**20 + 4 * GRAIN - SECTOR} 512",
    f"write -P 0x55 {2 * GIB - GRAIN} 128k",  # across the two extents
    "write -P 0x66 100m 64k",  # written first, so the source's grains are out of disk order
    "write -P 0x77 50m 64k",
    f"write -P 0x88 {2 * GIB + 2**20} {3 * SECTOR}",  # the last grain, which the disk ends inside
]
WRITTEN_GRAINS = 1 + 144 + 1 + 1 + 2 + 1 + 1 + 1


def sparse_disk(directory: Path, writes: list[str], options: str = "subformat=twoGbMaxExtentSparse") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "box.vmdk"
    subprocess.run(["qemu-img", "create", "-q", "-f", "vmdk", "-o", options, str(source), str(SIZE)], check=True)
    commands = [part for write in writes for part in ("-c", write)]
    if commands:
        subprocess.run(["qemu-io", "-f", "vmdk", *commands, str(source)], check=True, capture_output=True)
    return source


def spoil_past_the_end(source: Path) -> None:
    """Non-zero bytes in the source's last grain behind the end of the disk, where QEMU never reads."""
    with SparseDisk(source) as disk:
        entry = disk.extents[-1].entries[-1]
    assert entry > 1
    with source.with_name("box-s002.vmdk").open("r+b") as handle:
        handle.seek(entry * SECTOR + 3 * SECTOR)
        handle.write(b"\xa5" * (GRAIN - 3 * SECTOR))


def masked(path: Path) -> tuple[bytes, bytes]:
    """The VMDK with its random CID masked, and what follows the descriptor's text in the descriptor's sectors (qemu-img
    leaves the end of the old text there when the CID it writes is shorter)."""
    data = path.read_bytes()
    offset, size = HEADER.unpack_from(data)[5:7]
    text, _, rest = data[offset * SECTOR:(offset + size) * SECTOR].partition(b"\0")
    text = re.sub(rb"(?m)^CID=[0-9a-f]+$", b"CID=*", text)
    return data[:offset * SECTOR] + text + data[(offset + size) * SECTOR:], rest


def qemu_img_convert(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["qemu-img", "convert", "-O", "vmdk", str(source), str(target)], check=True, capture_output=True)
    return target


def writer_convert(source: Path, target: Path) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    with SparseDisk(source) as disk:
        subprocess.run(["qemu-img", "create", "-q", "-f", "vmdk", str(target), str(disk.size)], check=True)
        return disk.write_vmdk(target)


def assert_same_as_qemu_img(expected: Path, actual: Path, source: Path) -> None:
    """Same file name in another folder: the descriptor names its file."""
    (want, _), (got, rest) = masked(expected), masked(actual)
    assert expected.name == actual.name and got == want
    assert rest.strip(b"\0") == b""
    check = subprocess.run(["qemu-img", "check", str(actual)], capture_output=True, text=True)
    assert check.returncode == 0 and "No errors were found on the image." in check.stdout
    compare = subprocess.run(["qemu-img", "compare", str(source), str(actual)], capture_output=True, text=True)
    assert compare.returncode == 0, compare.stdout + compare.stderr


@needs_qemu
@needs_writer
@pytest.mark.parametrize("options, extra", [
    ("subformat=twoGbMaxExtentSparse", []),
    # Zeroed grains: a whole-grain zero write leaves a grain table entry of 1 instead of a grain.
    ("subformat=twoGbMaxExtentSparse,zeroed_grain=on", ["write -z 40m 256k"]),
])
def test_the_writer_writes_the_vmdk_qemu_img_convert_writes(tmp_path, options, extra):
    source = sparse_disk(tmp_path / "box", WRITES + extra, options)
    spoil_past_the_end(source)
    expected = qemu_img_convert(source, tmp_path / "qemu-img" / "full_scale.vmdk")
    actual = tmp_path / "fmb" / "full_scale.vmdk"
    assert writer_convert(source, actual) == WRITTEN_GRAINS
    assert_same_as_qemu_img(expected, actual, source)


@needs_qemu
@needs_writer
def test_a_last_grain_with_data_only_past_the_end_of_the_disk_is_not_copied(tmp_path):
    source = sparse_disk(tmp_path / "box", ["write -P 0x11 0 64k", f"write -P 0 {2 * GIB + 2**20} {3 * SECTOR}"])
    spoil_past_the_end(source)
    expected = qemu_img_convert(source, tmp_path / "qemu-img" / "full_scale.vmdk")
    actual = tmp_path / "fmb" / "full_scale.vmdk"
    assert writer_convert(source, actual) == 1
    assert_same_as_qemu_img(expected, actual, source)


@needs_qemu
@needs_writer
def test_an_empty_disk_gets_the_empty_vmdk(tmp_path):
    source = sparse_disk(tmp_path / "box", [])
    expected = qemu_img_convert(source, tmp_path / "qemu-img" / "full_scale.vmdk")
    actual = tmp_path / "fmb" / "full_scale.vmdk"
    assert writer_convert(source, actual) == 0
    assert_same_as_qemu_img(expected, actual, source)


@needs_qemu
@needs_writer
@pytest.mark.parametrize("options", ["subformat=twoGbMaxExtentSparse", "zeroed_grain=on", "subformat=streamOptimized"])
def test_the_writer_fills_only_the_default_vmdk_qemu_img_creates(tmp_path, options):
    source = sparse_disk(tmp_path / "box", ["write -P 0x11 0 64k"])
    target = tmp_path / "full_scale.vmdk"
    with SparseDisk(source) as disk:
        subprocess.run(["qemu-img", "create", "-q", "-f", "vmdk", "-o", options, str(target), str(disk.size)],
                       check=True)
        before = target.read_bytes()
        with pytest.raises(Unsupported, match="qemu-img's new VMDK"):
            disk.write_vmdk(target)
    assert target.read_bytes() == before


@needs_qemu
@needs_writer
def test_convert_and_publish_writes_the_same_image_with_and_without_the_writer(tmp_path, monkeypatch, capsys):
    source = sparse_disk(tmp_path / "box", WRITES)
    # The .partial name is in the descriptor; the same name in both makes the images comparable.
    monkeypatch.setattr("fmb.generation.pipeline.secrets.token_hex", lambda size: "0" * 2 * size)
    images, commands = [], []
    for name, writer in (("fmb", True), ("qemu-img", False)):
        instance = GenerationPipeline.__new__(GenerationPipeline)
        instance.run_command = lambda command, **_: (commands.append(command[1]),
                                                     subprocess.run(command, check=True, capture_output=True))
        if not writer:
            instance.copy_vmware_disk = lambda *_: False
        (tmp_path / name).mkdir()
        images.append(instance.convert_and_publish(source, tmp_path / name / "full_scale.vmdk", "vmdk"))
        assert not list((tmp_path / name).glob("*.partial"))
    assert commands == ["create", "info", "convert", "info"]
    assert "[*] Copying box.vmdk with fmb's VMDK writer" in capsys.readouterr().out
    assert_same_as_qemu_img(images[1], images[0], source)


# Fallback decisions, without QEMU: hand-made VMware descriptors and hosted sparse extents.

def extent_file(path: Path, sectors: int, grains: dict[int, bytes] | None = None, *,
                entries: dict[int, int] | None = None, missing_tables: tuple[int, ...] = (), **fields: int) -> None:
    """A hosted sparse extent laid out as VMware lays one out: header, redundant and primary grain directories and
    tables, then the grains in the order given."""
    tables = -(-sectors // (vmdk_writer.GRAIN_SECTORS * vmdk_writer.TABLE_ENTRIES))
    directory_sectors = -(-tables * 4 // SECTOR)
    rgd = 1
    gd = rgd + directory_sectors + tables * 4
    grain_offset = -(-(gd + directory_sectors + tables * 4) // 128) * 128
    header = dict(version=1, flags=3, capacity=sectors, granularity=128, table_entries=512, rgd=rgd, gd=gd,
                  grain_offset=grain_offset, unclean=0, compression=0) | fields
    table = [0] * (tables * vmdk_writer.TABLE_ENTRIES)
    data = bytearray(grain_offset * SECTOR)
    for index, grain in (grains or {}).items():
        table[index] = len(data) // SECTOR
        data += grain
    for index, entry in (entries or {}).items():
        table[index] = entry
    data[:HEADER.size] = HEADER.pack(b"KDMV", header["version"], header["flags"], header["capacity"],
                                     header["granularity"], 0, 0, header["table_entries"], header["rgd"], header["gd"],
                                     header["grain_offset"], header["unclean"], b"\n \r\n", header["compression"])
    raw_tables = b"".join(entry.to_bytes(4, "little") for entry in table)
    for start in (rgd, gd):
        first_table = start + directory_sectors
        directory = b"".join((0 if i in missing_tables else first_table + i * 4).to_bytes(4, "little")
                             for i in range(tables))
        data[start * SECTOR:start * SECTOR + len(directory)] = directory
        data[first_table * SECTOR:first_table * SECTOR + len(raw_tables)] = raw_tables
    path.write_bytes(bytes(data))


DESCRIPTOR = """# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=6f1c2a3b
parentCID=ffffffff
createType="twoGbMaxExtentSparse"

# Extent description
{extents}

# The Disk Data Base
#DDB

ddb.adapterType = "lsilogic"
ddb.virtualHWVersion = "21"
"""
SECTORS = (4192256, 1024 + 3)  # one of VMware's 2047 MiB extents, and a last one ending inside a grain


def vmware_disk(directory: Path, *, first: dict | None = None, last: dict | None = None) -> Path:
    """A two-extent VMware disk with a grain at the start of each extent and one in the last, partial grain."""
    directory.mkdir(parents=True, exist_ok=True)
    extent_file(directory / "disk-s001.vmdk", SECTORS[0], **(first or {"grains": {0: b"\x01" * GRAIN}}))
    extent_file(directory / "disk-s002.vmdk", SECTORS[1], {0: b"\x02" * GRAIN, 8: b"\x03" * GRAIN}, **(last or {}))
    lines = "\n".join(f'RW {sectors} SPARSE "disk-s00{number}.vmdk"' for number, sectors in enumerate(SECTORS, 1))
    descriptor = directory / "disk.vmdk"
    descriptor.write_text(DESCRIPTOR.format(extents=lines), encoding="ascii")
    return descriptor


@needs_qemu
@needs_writer
@pytest.mark.parametrize("zeroed", [{}, {"flags": 7, "version": 2, "entries": {5: 1}}])
def test_the_writer_copies_a_disk_laid_out_as_vmware_lays_it_out_as_qemu_img_does(tmp_path, zeroed):
    """VMware's 2047 MiB extents, grains stored out of disk order, a grain table never allocated, zeroed grains."""
    def grain(byte, zeros=0):
        return bytes([byte]) * (GRAIN - zeros) + bytes(zeros)

    grains = {32751: grain(9), 700: grain(3), 0: grain(1), 701: bytes(GRAIN), 702: grain(4, GRAIN // 2), 1: grain(2),
              1600: grain(6, GRAIN - SECTOR)}
    descriptor = vmware_disk(tmp_path / "box", first={"grains": grains, "missing_tables": (2,), **zeroed})
    expected = qemu_img_convert(descriptor, tmp_path / "qemu-img" / "full_scale.vmdk")
    actual = tmp_path / "fmb" / "full_scale.vmdk"
    assert writer_convert(descriptor, actual) == 6 + 2
    assert_same_as_qemu_img(expected, actual, descriptor)


@needs_writer
def test_a_hand_made_vmware_disk_opens(tmp_path):
    with SparseDisk(vmware_disk(tmp_path)) as disk:
        assert disk.size == sum(SECTORS) * SECTOR
        assert [extent.grains for extent in disk.extents] == [32752, 9]
        assert [sum(1 for entry in extent.entries if entry) for extent in disk.extents] == [1, 2]


@needs_writer
@pytest.mark.parametrize("change, reason", [
    (lambda text: text.replace("twoGbMaxExtentSparse", "monolithicFlat"), "not a twoGbMaxExtentSparse disk"),
    (lambda text: text.replace('SPARSE "disk-s002.vmdk"', 'FLAT "disk-s002.vmdk" 0'), "other than a writable sparse"),
    (lambda text: text.replace("RW 1027", "RDONLY 1027"), "other than a writable sparse"),
    (lambda text: text.replace('"disk-s002.vmdk"', '"disk-s002.vmdk" 0'), "other than a writable sparse"),
    (lambda text: text.replace("RW 1027", " RW 1027"), "other than a writable sparse"),
    (lambda text: text.replace("parentCID=ffffffff", "parentCID=1234abcd"), "has a parent disk"),
    (lambda text: text + 'parentFileNameHint="base.vmdk"\n', "has a parent disk"),
    (lambda text: "\n" + text, "not a VMware descriptor file"),  # QEMU would read it as a raw disk
    (lambda text: text.replace("version=1", "version=2"), "not a VMware descriptor file"),
    (lambda text: text.replace("\n", "\r\n"), "not a VMware descriptor file"),
    (lambda text: text.replace("disk-s002.vmdk", "missing.vmdk"), "cannot open the extent missing.vmdk"),
    (lambda text: "\n".join(line for line in text.splitlines() if not line.startswith("RW")), "lists no extent"),
])
def test_a_descriptor_the_writer_cannot_vouch_for_goes_to_qemu_img(tmp_path, change, reason):
    descriptor = vmware_disk(tmp_path)
    descriptor.write_bytes(change(descriptor.read_text()).encode("ascii"))
    with pytest.raises(Unsupported, match=reason):
        SparseDisk(descriptor)


@needs_writer
def test_the_end_of_an_old_descriptor_after_a_nul_is_not_read(tmp_path):
    descriptor = vmware_disk(tmp_path)
    descriptor.write_bytes(descriptor.read_bytes() + b"\0\0e = \"21\"\n")
    with SparseDisk(descriptor) as disk:
        assert disk.size == sum(SECTORS) * SECTOR


@needs_writer
@pytest.mark.parametrize("fields, reason", [
    (dict(flags=3 | 1 << 16), "compressed, streamed or unknown"),  # compressed grains
    (dict(flags=3 | 1 << 17), "compressed, streamed or unknown"),  # grain markers
    (dict(flags=3 | 1 << 3), "compressed, streamed or unknown"),  # a flag nobody defined
    (dict(version=3), "compressed, streamed or unknown"),
    (dict(compression=1), "compressed, streamed or unknown"),
    (dict(granularity=64), "grains or grain tables of another size"),
    (dict(table_entries=256), "grains or grain tables of another size"),
    (dict(capacity=1024), "differs from its descriptor line"),
    (dict(unclean=1), "not closed cleanly"),
    (dict(gd=0xFFFFFFFFFFFFFFFF), "no usable grain directory"),
    (dict(gd=4096), "no usable grain directory"),
    (dict(gd=383), "beyond the end of the file"),  # its last sector, where a grain table offset would be
    (dict(entries={1: 1}), "points outside the grains"),  # a zeroed grain without the ZERO_GRAIN flag
    (dict(entries={1: 2}), "points outside the grains"),  # into the grain tables
    (dict(entries={1: 1 << 20}), "points outside the grains"),  # past the end of the extent
])
def test_an_extent_the_writer_cannot_vouch_for_goes_to_qemu_img(tmp_path, fields, reason):
    with pytest.raises(Unsupported, match=reason):
        SparseDisk(vmware_disk(tmp_path, last=fields))


@needs_writer
def test_only_the_last_extent_may_end_inside_a_grain(tmp_path):
    descriptor = vmware_disk(tmp_path)
    extent_file(tmp_path / "disk-s001.vmdk", SECTORS[0] - 3)
    descriptor.write_text(descriptor.read_text().replace(f"RW {SECTORS[0]} ", f"RW {SECTORS[0] - 3} "),
                          encoding="ascii")
    with pytest.raises(Unsupported, match="ends inside a grain"):
        SparseDisk(descriptor)


@needs_writer
def test_a_zeroed_grain_entry_reads_as_zeros_with_the_zero_grain_flag(tmp_path):
    with SparseDisk(vmware_disk(tmp_path, last=dict(flags=7, version=2, entries={1: 1}))) as disk:
        assert disk.extents[-1].entries[1] == 1 and disk.extents[-1].zero_grain


@needs_writer
@pytest.mark.parametrize("content, reason", [
    (b"", "not a VMware descriptor file"),
    (b"QFI\xfb\x00\x00\x00\x03" + bytes(4096), "not a VMware descriptor file"),  # qcow2
    (bytes(2 << 20), "not a VMware descriptor file"),  # a raw disk
    (b"KDMV\x01\x00\x00\x00" + bytes(4096), "single-file sparse VMDK"),  # monolithicSparse
    (None, "cannot read system.img"),
], ids=["empty", "qcow2", "raw", "monolithic-sparse", "missing"])  # Windows refuses a test name of megabytes
def test_a_disk_that_is_no_vmware_descriptor_goes_to_qemu_img(tmp_path, content, reason):
    source = tmp_path / "system.img"
    if content is not None:
        source.write_bytes(content)
    with pytest.raises(Unsupported, match=reason):
        SparseDisk(source)


@needs_writer
def test_a_source_that_cannot_be_read_goes_to_qemu_img(tmp_path, monkeypatch):
    descriptor = vmware_disk(tmp_path)

    def failing(*_):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(vmdk_writer, "read_header", failing)
    with pytest.raises(Unsupported, match=r"cannot read disk.vmdk: \[Errno 5\] Input/output error"):
        SparseDisk(descriptor)


def test_a_host_without_vectored_writes_goes_to_qemu_img(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "writev", raising=False)
    with pytest.raises(Unsupported, match="no positional and vectored file writes"):
        SparseDisk(tmp_path / "disk.vmdk")


class FakeDisk:
    """Stands in for SparseDisk in the pipeline."""

    opens = True
    failure: BaseException | None = None

    def __init__(self, source):
        if not FakeDisk.opens:
            raise Unsupported(f"{Path(source).name} is not a VMware descriptor file")
        self.size = 4 * GIB

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def write_vmdk(self, path):
        if FakeDisk.failure is not None:
            Path(path).write_bytes(b"half a vmdk")
            raise FakeDisk.failure
        Path(path).write_bytes(b"written by fmb")
        return 1


def fake_qemu_img(calls):
    def run_command(command, **_):
        calls.append(command[1])
        if command[1] in ("create", "convert"):
            target = Path(command[-2] if command[1] == "create" else command[-1])
            assert not target.exists()
            target.write_bytes(b"made by qemu-img")
    return run_command


@pytest.mark.parametrize("source, opens, failure, kinds, said", [
    ("disk.vmdk", True, None, ["create", "info"], "[*] Copying disk.vmdk with fmb's VMDK writer"),
    ("system.qcow2", False, None, ["convert", "info"], None),  # a QEMU image, as on Linux and Windows
    ("media.vmdk", False, None, ["convert", "info"],
     "[*] media.vmdk is not a VMware descriptor file; converting with qemu-img"),
    ("disk.vmdk", True, Unsupported("qemu-img's new VMDK has another layout"), ["create", "convert", "info"],
     "[*] qemu-img's new VMDK has another layout; converting with qemu-img"),
    ("disk.vmdk", True, OSError(errno.EIO, "Input/output error"), ["create", "convert", "info"],
     "[!] Warning: fmb's VMDK writer failed ([Errno 5] Input/output error); converting with qemu-img"),
])
def test_convert_and_publish_leaves_what_the_writer_cannot_do_to_qemu_img(tmp_path, monkeypatch, capsys, source,
                                                                          opens, failure, kinds, said):
    monkeypatch.setattr(vmdk_writer, "SparseDisk", FakeDisk)
    monkeypatch.setattr(FakeDisk, "opens", opens)
    monkeypatch.setattr(FakeDisk, "failure", failure)
    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []
    instance.run_command = fake_qemu_img(calls)
    final = tmp_path / "full_scale.vmdk"
    assert instance.convert_and_publish(tmp_path / source, final, "vmdk") == final
    assert calls == kinds
    assert final.read_bytes() == (b"written by fmb" if kinds == ["create", "info"] else b"made by qemu-img")
    out = capsys.readouterr().out
    assert re.search(r"\[\*\] Converted full_scale\.vmdk in \d+s", out)
    if said is None:
        assert "converting with qemu-img" not in out and "VMDK writer" not in out
    else:
        assert said in out
    assert not list(tmp_path.glob("*.partial"))


def test_a_full_disk_fails_the_copy_without_converting_again(tmp_path, monkeypatch):
    monkeypatch.setattr(vmdk_writer, "SparseDisk", FakeDisk)
    monkeypatch.setattr(FakeDisk, "failure", OSError(errno.ENOSPC, "No space left on device"))
    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []
    instance.run_command = fake_qemu_img(calls)
    with pytest.raises(RuntimeError, match=r"copying the VMware disk failed: \[Errno 28\] No space left on device"):
        instance.convert_and_publish(tmp_path / "disk.vmdk", tmp_path / "full_scale.vmdk", "vmdk")
    assert calls == ["create"]
    assert not list(tmp_path.glob("*.partial"))


def test_a_failed_qemu_img_create_leaves_the_disk_to_qemu_img_convert(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(vmdk_writer, "SparseDisk", FakeDisk)
    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []

    def run_command(command, **_):
        if command[1] == "create":
            calls.append("create")
            raise subprocess.CalledProcessError(1, command, "", "qemu-img: Could not create: Permission denied")
        fake_qemu_img(calls)(command)

    instance.run_command = run_command
    final = tmp_path / "full_scale.vmdk"
    instance.convert_and_publish(tmp_path / "disk.vmdk", final, "vmdk")
    assert calls == ["create", "convert", "info"] and final.read_bytes() == b"made by qemu-img"
    assert "fmb's VMDK writer failed (qemu-img: Could not create: Permission denied)" in capsys.readouterr().out


def test_only_a_vmdk_export_uses_the_writer(tmp_path, monkeypatch):
    monkeypatch.setattr(vmdk_writer, "SparseDisk", lambda source: pytest.fail("only -O vmdk may use the writer"))
    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []
    instance.run_command = fake_qemu_img(calls)
    instance.convert_and_publish(tmp_path / "disk.vmdk", tmp_path / "full_scale.qcow2", "qcow2")
    assert calls == ["convert", "info"]
