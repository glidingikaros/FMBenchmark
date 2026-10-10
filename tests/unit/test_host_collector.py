from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from fmb.collection.tools.host import backend as host_backend
from fmb.collection.tools.host.bundle import (
    build_host_result,
    host_execution_environment,
    parser_appliance_request_args,
    write_host_bundle_documents,
)
from fmb.collection.tools.host.definitions import (
    KapeDefinitionError,
    KapeDefinitions,
    TargetRule,
    split_file_masks,
)
from fmb.collection.tools.host.extractor import (
    SKIP_REASON_DESTINATION_EXISTS,
    SKIP_REASON_UNSAFE_PATH,
    declared_components,
    extract_targets,
)
from fmb.collection.tools.host.ntfs_index import (
    ROOT_ENTRY,
    NtfsIndexError,
    UnsupportedStreamError,
    VolumeIndex,
)
from fmb.collection.tools.host.modules import (
    HostModuleError,
    render_arguments,
    run_module_processors,
)
from fmb.collection.tools.host.parser_appliance import (
    ParserApplianceError,
    build_input_package,
    render_guest_arguments,
)
from fmb.collection.tools.host.toolchain import HostToolchain, HostToolchainError, tree_sha256
from fmb.collection.tools.envelope import build_tool_run_request
from fmb.core.json_io import write_json
from fmb.core.ntfs_time import filetime_to_utc_iso

QEMU_AVAILABLE = shutil.which("qemu-img") is not None
needs_tsk = pytest.mark.skipif(
    not all(importlib.util.find_spec(name) for name in ("pytsk3", "pyvmdk")),
    reason="pytsk3 and libvmdk-python are required for image reads",
)


def _fn(name: str, parent: int, sequence: int = 1, namespace: int = 1) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    struct.pack_into("<Q", value, 0, parent | sequence << 48)
    value[64:66] = bytes((len(name), namespace))
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


def _mapping(runs: list[tuple[int, int | None]]) -> bytes:
    out = bytearray()
    previous = 0
    for count, lcn in runs:
        if lcn is None:
            out += bytes((0x01, count))
        else:
            delta = lcn - previous
            out += bytes((0x21, count)) + struct.pack("<h", delta)
            previous = lcn
    out += b"\x00"
    return bytes(out)


def _nonresident(
    kind: int,
    runs: list[tuple[int, int | None]],
    *,
    logical: int,
    valid: int | None = None,
    name: str = "",
    identity: int = 2,
    flags: int = 0,
) -> bytes:
    encoded = name.encode("utf-16le")
    mapping_offset = (64 + len(encoded) + 7) & ~7
    mapping = _mapping(runs)
    result = bytearray((mapping_offset + len(mapping) + 7) & ~7)
    total = sum(count for count, _ in runs)
    struct.pack_into("<II", result, 0, kind, len(result))
    result[8] = 1
    result[9] = len(name)
    struct.pack_into("<H", result, 10, 64)
    struct.pack_into("<H", result, 12, flags)
    struct.pack_into("<H", result, 14, identity)
    struct.pack_into("<QQH", result, 16, 0, total - 1, mapping_offset)
    struct.pack_into("<QQQ", result, 40, total * 4096, logical, logical if valid is None else valid)
    result[64 : 64 + len(encoded)] = encoded
    result[mapping_offset : mapping_offset + len(mapping)] = mapping
    return bytes(result)


def _protect(value: bytearray, *, magic: bytes, usa: int) -> bytes:
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
    entry: int, attributes: list[bytes], *, sequence: int = 1, flags: int = 1, base: int = 0
) -> bytes:
    if not base:
        attributes = [_resident(0x10, bytes(72), identity=0), *attributes]
    result = bytearray(1024)
    struct.pack_into("<HHH", result, 16, sequence, 1, 56)
    struct.pack_into("<H", result, 22, flags)
    struct.pack_into("<I", result, 28, 1024)
    struct.pack_into("<Q", result, 32, base)
    struct.pack_into("<I", result, 44, entry)
    offset = 56
    for attribute in attributes:
        result[offset : offset + len(attribute)] = attribute
        offset += len(attribute)
    struct.pack_into("<I", result, offset, 0xFFFFFFFF)
    struct.pack_into("<I", result, 24, offset + 8)
    return _protect(result, magic=b"FILE", usa=48)


def _index_root(*children: tuple[int, bytes]) -> bytes:
    entries = b"".join(
        struct.pack("<QHHB3x", reference, (16 + len(value) + 7) & ~7, len(value), 0)
        + value.ljust((len(value) + 7) & ~7, b"\x00")
        for reference, value in children
    ) + struct.pack("<QHHB3x", 0, 16, 0, 2)
    header = struct.pack("<IIIB3x", 0x30, 1, 4096, 1)
    return header + struct.pack("<IIII", 16, 16 + len(entries), 16 + len(entries), 0) + entries


def _directory(entry: int, name: str, parent: int, *children: tuple[int, bytes]) -> bytes:
    return _record(
        entry,
        [_resident(0x30, _fn(name, parent)), _resident(0x90, _index_root(*children), name="$I30", identity=2)],
        flags=3,
    )


def _list_entry(kind: int, identity: int, reference: int, *, lowest_vcn: int = 0, name: str = "") -> bytes:
    encoded = name.encode("utf-16le")
    raw = bytearray((26 + len(encoded) + 7) & ~7)
    struct.pack_into("<IHBBQQH", raw, 0, kind, len(raw), len(name), 26 if name else 0, lowest_vcn, reference, identity)
    raw[26 : 26 + len(encoded)] = encoded
    return bytes(raw)


def _reference(entry: int, sequence: int) -> int:
    return entry | (sequence << 48)


def _volume(
    records: dict[int, bytes], clusters: dict[int, bytes] | None = None, *, image_clusters: int = 128
) -> bytes:
    image = bytearray(image_clusters * 4096)
    image[3:11] = b"NTFS    "
    struct.pack_into("<H", image, 11, 512)
    image[13] = 8
    struct.pack_into("<QQQ", image, 40, 1024, 4, 2)
    struct.pack_into("<b", image, 64, -10)
    struct.pack_into("<b", image, 68, -12)
    struct.pack_into("<Q", image, 72, 0x1122334455667788)
    image[510:512] = b"\x55\xaa"
    system = {
        0: _record(0, [_resident(0x30, _fn("$MFT", 5)), _nonresident(0x80, [(12, 4)], logical=48 * 1024)]),
        3: _record(3, [_resident(0x30, _fn("$Volume", 5)), _resident(0x70, bytes(8) + bytes((3, 1, 0, 0)), identity=2)]),
        5: _directory(5, ".", 5),
        6: _record(6, [_resident(0x30, _fn("$Bitmap", 5)), _nonresident(0x80, [(1, 127)], logical=16)]),
    }
    for entry, record in {**system, **records}.items():
        image[4 * 4096 + entry * 1024 : 4 * 4096 + (entry + 1) * 1024] = record
    for lcn, data in {127: b"\xff" * 16, **(clusters or {})}.items():
        image[lcn * 4096 : lcn * 4096 + len(data)] = data
    return bytes(image)


def _index(
    tmp_path: Path, records: dict[int, bytes], clusters: dict[int, bytes] | None = None, **volume: int
) -> VolumeIndex:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "volume.raw"
    path.write_bytes(_volume(records, clusters, **volume))
    return VolumeIndex(path)


def _path_of(index: VolumeIndex, entry: int) -> str | None:
    parts: list[str] = []
    for _ in range(512):
        if entry == ROOT_ENTRY:
            return "\\" + "\\".join(reversed(parts))
        record = index.entries.get(entry)
        if record is None or not record.names:
            return None
        parts.append(record.names[0].name)
        entry = record.names[0].parent_entry
    return None


def _rule(path: str, mask: str, *, recursive: bool = False, save_as: str | None = None) -> TargetRule:
    return TargetRule("Public", "fixture", "fixture", "Public", "Public", path, mask, recursive, save_as, False)


def _image(tmp_path: Path) -> tuple[Path, bytes]:
    records = {
        5: _directory(5, ".", 5, (_reference(20, 1), _fn("Windows", 5))),
        11: _directory(11, "$Extend", 5),
        20: _directory(20, "Windows", 5),
        21: _directory(21, "Prefetch", 20),
        22: _directory(22, "System32", 20),
        23: _directory(23, "winevt", 22),
        24: _directory(24, "Logs", 23),
        30: _record(30, [_resident(0x30, _fn("A.pf", 21)), _nonresident(0x80, [(2, 50)], logical=4097)]),
        31: _record(31, [_resident(0x30, _fn("B.pf", 21)), _nonresident(0x80, [(2, 52)], logical=4097)]),
        32: _record(
            32,
            [
                _resident(0x30, _fn("Security.evtx", 24)),
                _nonresident(0x80, [(2, 55)], logical=8192, valid=4096),
            ],
        ),
        40: _record(
            40,
            [
                _resident(0x30, _fn("$UsnJrnl", 11)),
                _nonresident(0x80, [(2, None), (1, 60)], logical=12288, name="$J", identity=3, flags=0x8000),
                _resident(0x80, bytes(range(32)), name="$Max", identity=4),
            ],
        ),
    }
    image = _volume(records, {50: b"A" * 4097, 52: b"A" * 4097, 55: b"E" * 8192, 60: b"J" * 4096})
    path = tmp_path / "source.raw"
    path.write_bytes(image)
    return path, image[4 * 4096 : 4 * 4096 + 48 * 1024]


TKAPE_PREFETCH = """Description: Prefetch files
Id: f6715d3f-b8ca-4cc2-9e5e-4ed18e88abbe
RecreateDirectories: true
Targets:
    -
        Name: Prefetch
        Category: Prefetch
        Path: C:\\Windows\\prefetch\\
        FileMask: '*.pf'
"""
TKAPE_J = """Description: $J
Id: 2a9c6f80-250b-42a6-9d29-90cb0a20f7be
Targets:
    -
        Name: $J
        Category: FileSystem
        Path: C:\\$Extend\\
        FileMask: $UsnJrnl:$J
        AlwaysAddToQueue: true
        SaveAsFileName: $J
    -
        Name: $Max
        Category: FileSystem
        Path: C:\\$Extend\\
        FileMask: $UsnJrnl:$Max
        SaveAsFileName: $Max
"""
TKAPE_EVENTLOGS = """Description: Event logs
Id: d95784d9-bd1c-472b-aeef-de5d9ecc7aaa
Targets:
    -
        Name: Event logs Win7+
        Category: EventLogs
        Path: C:\\Windows\\System32\\winevt\\logs\\
        FileMask: '*.evtx'
"""
TKAPE_MFT = """Description: $MFT
Id: 2b3d01e2-25e1-4079-a630-6cb6e2069456
Targets:
    -
        Name: $MFT
        Category: FileSystem
        Path: C:\\
        FileMask: $MFT
"""
TKAPE_COMPOUND = """Description: compound
Id: 11111111-1111-1111-1111-111111111111
Targets:
    -
        Name: $MFT
        Category: FileSystem
        Path: $MFT.tkape
    -
        Name: Prefetch
        Category: Prefetch
        Path: Prefetch.tkape
"""
MKAPE_MFT = """Description: 'MFTECmd: process $MFT files'
Category: FileSystem
Id: 7ef84a6b-5215-46bb-af2a-3339a3227e25
ExportFormat: csv
FileMask: $MFT
Processors:
    -
        Executable: MFTECmd.exe
        CommandLine: -f %sourceFile% --csv %destinationDirectory%
        ExportFormat: csv
    -
        Executable: MFTECmd.exe
        CommandLine: -f %sourceFile% --json %destinationDirectory%
        ExportFormat: json
"""
MKAPE_COMPOUND = """Description: 'MFTECmd: process all files handled by MFTECmd'
Category: FileSystem
Id: 7ef84a6b-5215-47bb-af2a-2139a3277e25
ExportFormat: csv
Processors:
    -
        Executable: MFTECmd_$MFT.mkape
        CommandLine: ""
        ExportFormat: ""
"""
MKAPE_PECMD = """Description: 'PECmd: process prefetch files'
Category: ProgramExecution
Id: 7ef84a6b-5115-45bb-af2a-3249a3237e75
ExportFormat: csv
Processors:
    -
        Executable: PECmd.exe
        CommandLine: -d %sourceDirectory% --csv %destinationDirectory% --mp -q
        ExportFormat: csv
"""


def _definitions(tmp_path: Path) -> Path:
    root = tmp_path / "definitions"
    for relative, text in {
        "Targets/Windows/Prefetch.tkape": TKAPE_PREFETCH,
        "Targets/Windows/$J.tkape": TKAPE_J,
        "Targets/Windows/EventLogs.tkape": TKAPE_EVENTLOGS,
        "Targets/Windows/$MFT.tkape": TKAPE_MFT,
        "Targets/Compound/FileSystemMini.tkape": TKAPE_COMPOUND,
        "Modules/EZTools/MFTECmd/MFTECmd_$MFT.mkape": MKAPE_MFT,
        "Modules/Compound/MFTECmd.mkape": MKAPE_COMPOUND,
        "Modules/EZTools/PECmd.mkape": MKAPE_PECMD,
        "Modules/!Disabled/PECmd.mkape": "Description: disabled\nProcessors: []\n",
    }.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return root


def test_definitions_expand_targets_in_kape_order_and_dedupe_by_id(tmp_path: Path) -> None:
    definitions = KapeDefinitions(_definitions(tmp_path))
    rules = definitions.target_rules(["Prefetch", "FileSystemMini", "$J"])
    assert [(rule.requested_target, rule.name, rule.file_mask) for rule in rules] == [
        ("Prefetch", "Prefetch", "*.pf"),
        ("FileSystemMini", "$MFT", "$MFT"),
        ("$J", "$J", "$UsnJrnl:$J"),
        ("$J", "$Max", "$UsnJrnl:$Max"),
    ]
    assert rules[2].save_as == "$J" and rules[2].always_add_to_queue is True
    with pytest.raises(KapeDefinitionError):
        definitions.target_rules(["Missing"])


@pytest.mark.parametrize("option", ["        MinSize: 1024\n", "        MaxSize: 4096\n", None])
def test_definitions_refuse_target_options_the_collector_does_not_implement(tmp_path: Path, option) -> None:
    root = _definitions(tmp_path)
    text = TKAPE_PREFETCH + option if option else TKAPE_PREFETCH.replace("'*.pf'", "'regex:.+\\.pf'")
    (root / "Targets/Windows/Prefetch.tkape").write_text(text, encoding="utf-8")
    with pytest.raises(KapeDefinitionError, match="does not implement"):
        KapeDefinitions(root).target_rules(["Prefetch"])


def test_definitions_resolve_compound_modules_to_csv_processors(tmp_path: Path) -> None:
    definitions = KapeDefinitions(_definitions(tmp_path))
    processors = definitions.module_processors(["MFTECmd", "PECmd", "MFTECmd_$MFT"])
    assert [(item.requested_module, item.module_name, item.executable, item.export_format) for item in processors] == [
        ("MFTECmd", "MFTECmd_$MFT", "MFTECmd.exe", "csv"),
        ("PECmd", "PECmd", "PECmd.exe", "csv"),
    ]
    assert processors[0].file_mask == "$MFT" and processors[0].category == "FileSystem"
    assert processors[1].command_line == "-d %sourceDirectory% --csv %destinationDirectory% --mp -q"


def test_masks_components_and_argument_rendering(tmp_path: Path) -> None:
    assert split_file_masks("$UsnJrnl%3A$J|$J") == ["$UsnJrnl:$J", "$J"]
    assert declared_components("C:\\Users\\%user%\\AppData\\Roaming\\") == ["Users", "*", "AppData", "Roaming"]
    assert declared_components("C:\\") == []
    rendered = render_arguments(
        "-d %sourceDirectory% --bn BatchExamples\\Kroll_Batch.reb --csv %destinationDirectory%",
        source_directory=tmp_path / "targets",
        destination_directory=tmp_path / "modules" / "Registry",
        source_file=None,
        tool_directory=tmp_path,
    )
    assert rendered == ["-d", str(tmp_path / "targets"), "--bn", "BatchExamples/Kroll_Batch.reb", "--csv", str(tmp_path / "modules" / "Registry")]
    with pytest.raises(HostModuleError):
        render_arguments("-f %sourceFile%", source_directory=tmp_path, destination_directory=tmp_path, source_file=None, tool_directory=tmp_path)


@needs_tsk
def test_extract_targets_mirrors_kape_layout_dedup_sparse_and_valid_data(tmp_path: Path) -> None:
    image, mft = _image(tmp_path)
    index = VolumeIndex(image)
    assert _path_of(index, 32) == "\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    assert index.resolve_directories(["windows", "PREFETCH"]) == [21]
    assert sorted(index.stream_names(40)) == ["$J", "$Max"]

    definitions = KapeDefinitions(_definitions(tmp_path))
    rules = definitions.target_rules(["Prefetch", "$J", "EventLogs", "FileSystemMini"])
    output = tmp_path / "kape-output"
    result = extract_targets(index, rules, output_root=output, drive_letter="F", command_line="host targets")
    copied = {item.relative_path: item for item in result.copied}
    assert set(copied) == {
        "targets/F/Windows/prefetch/A.pf",
        "targets/F/$Extend/$J",
        "targets/F/$Extend/$Max",
        "targets/F/Windows/System32/winevt/logs/Security.evtx",
        "targets/F/$MFT",
    }
    assert (output / "targets/F/Windows/prefetch/A.pf").read_bytes() == b"A" * 4097
    assert (output / "targets/F/$Extend/$J").read_bytes() == b"J" * 4096
    assert copied["targets/F/$Extend/$J"].report.skipped_leading_sparse_bytes == 8192
    assert (output / "targets/F/$Extend/$Max").read_bytes() == bytes(range(32))
    security = (output / "targets/F/Windows/System32/winevt/logs/Security.evtx").read_bytes()
    assert security[:4096] == b"E" * 4096 and security[4096:] == bytes(4096)
    assert (output / "targets/F/$MFT").read_bytes() == mft
    assert [(item.source_path, item.reason) for item in result.skipped] == [("F:\\Windows\\prefetch\\B.pf", "Deduped")]
    assert copied["targets/F/Windows/prefetch/A.pf"].source_path == "F:\\Windows\\prefetch\\A.pf"
    console = result.log_files["console_log"].read_text(encoding="utf-8")
    assert "Command line: host targets" in console and "Skipping sparse data area in $J" in console
    copy_log = result.log_files["copy_log"].read_text(encoding="utf-8")
    assert copy_log.startswith("CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1")


@needs_tsk
def test_contextual_collection_can_preserve_distinct_identical_files(tmp_path: Path) -> None:
    image, _mft = _image(tmp_path)
    index = VolumeIndex(image)
    rules = KapeDefinitions(_definitions(tmp_path)).target_rules(["Prefetch"])
    result = extract_targets(index, rules, output_root=tmp_path / "complete-context",
                             drive_letter="C", deduplicate_by_content=False)
    assert {r.source_path for r in result.copied} == {
        "C:\\Windows\\prefetch\\A.pf", "C:\\Windows\\prefetch\\B.pf"
    }
    assert len({r.sha256 for r in result.copied}) == 1
    assert len({r.entry for r in result.copied}) == 2
    assert not result.skipped


def _lock(tmp_path: Path, *, entry: Path, host_runnable: bool = True) -> tuple[Path, dict]:
    root = tmp_path / "toolchain"
    tool_dir = root / "Tool"
    tool_dir.mkdir(parents=True)
    target = tool_dir / entry.name
    shutil.copyfile(entry, target)
    lock = {
        "schema_version": "fmb_host_toolchain_lock.v1",
        "dotnet_sdk": "10.0.107",
        "dotnet_runtime": "10.0.7",
        "tools": [
            {
                "tool": "Tool",
                "executable": "Tool.exe",
                "directory": "Tool",
                "entry_assembly": entry.name,
                "entry_assembly_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "version": "1.0",
                "host_runnable": host_runnable,
                "source": {"repository": "https://example.invalid/tool", "commit_sha": "0" * 40},
            }
        ],
    }
    lock_path = tmp_path / "lock.json"
    write_json(lock_path, lock)
    return root, lock


def test_toolchain_lock_verifies_entry_assemblies(tmp_path: Path) -> None:
    script = tmp_path / "tool.py"
    script.write_text("print('tool')\n", encoding="utf-8")
    root, lock = _lock(tmp_path, entry=script)
    toolchain = HostToolchain(root, lock, lock_path=tmp_path / "lock.json")
    assert toolchain.unverified() == []
    assert toolchain.binding_for("tool.exe").tool_name == "Tool"
    (root / "Tool" / "tool.py").write_text("print('changed')\n", encoding="utf-8")
    assert [row["status"] for row in toolchain.verify()] == ["hash_mismatch"]
    with pytest.raises(HostToolchainError):
        HostToolchain(root, {"schema_version": "other"})


def test_a_timed_out_processor_logs_its_partial_output_as_text(tmp_path: Path, monkeypatch) -> None:
    from fmb.collection.tools.host import modules

    script = tmp_path / "tool.py"
    script.write_text("print('unused')\n", encoding="utf-8")
    root, lock = _lock(tmp_path, entry=script)
    toolchain = HostToolchain(root, lock, lock_path=tmp_path / "lock.json")
    processors = KapeDefinitions(_definitions(tmp_path)).module_processors(["PECmd"])
    processors = [processors[0].__class__(**{**processors[0].__dict__, "executable": "Tool.exe", "file_mask": None})]
    targets_root = tmp_path / "kape-output" / "targets"
    targets_root.mkdir(parents=True)

    def timed_out(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"parsed 3 files\n", stderr=b"still \xffrunning")

    monkeypatch.setattr(modules.subprocess, "run", timed_out)
    with pytest.raises(HostModuleError, match="exceeded"):
        run_module_processors(
            processors, toolchain=toolchain, dotnet=sys.executable, targets_root=targets_root,
            modules_root=tmp_path / "kape-output" / "modules", tool_logs_dir=tmp_path / "tool-logs",
        )
    [stdout] = (tmp_path / "tool-logs").glob("*.stdout.txt")
    [stderr] = (tmp_path / "tool-logs").glob("*.stderr.txt")
    assert stdout.read_text(encoding="utf-8") == "parsed 3 files\n"
    assert stderr.read_text(encoding="utf-8") == "still \ufffdrunning"


def test_modules_run_bound_processors_and_defer_windows_only_ones(tmp_path: Path) -> None:
    script = tmp_path / "tool.py"
    script.write_text(
        "import sys, pathlib\n"
        "args = sys.argv[1:]\n"
        "dest = pathlib.Path(args[args.index('--csv') + 1])\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        "(dest / 'out.csv').write_text('Command,Value\\n')\n"
        "print('Command line: ' + ' '.join(args))\n",
        encoding="utf-8",
    )
    root, lock = _lock(tmp_path, entry=script)
    toolchain = HostToolchain(root, lock, lock_path=tmp_path / "lock.json")
    definitions = KapeDefinitions(_definitions(tmp_path))
    processors = definitions.module_processors(["PECmd"])
    processors = [processors[0].__class__(**{**processors[0].__dict__, "executable": "Tool.exe", "file_mask": None})]
    targets_root = tmp_path / "kape-output" / "targets"
    targets_root.mkdir(parents=True)
    modules_root = tmp_path / "kape-output" / "modules"
    runs = run_module_processors(
        processors, toolchain=toolchain, dotnet=sys.executable, targets_root=targets_root,
        modules_root=modules_root, tool_logs_dir=tmp_path / "tool-logs",
    )
    assert [run.status for run in runs] == ["completed"]
    assert runs[0].outputs == ["modules/ProgramExecution/out.csv"]
    console = modules_root / "ProgramExecution"
    assert any(path.name.endswith(".console.log") for path in console.iterdir())

    deferred_root, deferred_lock = _lock(tmp_path / "deferred", entry=script, host_runnable=False)
    deferred = HostToolchain(deferred_root, deferred_lock)
    runs = run_module_processors(
        processors, toolchain=deferred, dotnet=sys.executable, targets_root=targets_root,
        modules_root=tmp_path / "deferred-modules", tool_logs_dir=tmp_path / "deferred-logs",
    )
    assert [run.status for run in runs] == ["deferred"]
    with pytest.raises(HostModuleError):
        run_module_processors(
            definitions.module_processors(["MFTECmd"]), toolchain=toolchain, dotnet=sys.executable,
            targets_root=targets_root, modules_root=tmp_path / "unbound", tool_logs_dir=tmp_path / "unbound-logs",
        )


def test_host_result_and_request_validate_against_the_execution_contract(tmp_path: Path) -> None:
    request = build_tool_run_request(
        question_id="FULL-SCALE",
        question_text="Collect everything.",
        collector="kape",
        run_id="run-host",
        collector_config={"source": "F:\\", "output": "kape-output", "targets": "$MFT", "modules": "MFTECmd", "extra_args": []},
        source_evidence_sha256="a" * 64,
        request_id="run-host:host-collector",
        expected_platform=host_backend.HOST_COLLECTOR_PLATFORM,
        expected_tool="fmb-host-collector",
        required_capability="fmb_host_collector",
    )
    assert request["expected_execution"] == {
        "platform": host_backend.HOST_COLLECTOR_PLATFORM, "tool": "fmb-host-collector", "required_capability": "fmb_host_collector",
    }
    request_path = tmp_path / "tool_run_request.json"
    write_json(request_path, request)
    result = build_host_result(
        request=request, request_path=request_path, evidence_path=tmp_path / "image.vmdk",
        evidence_sha256="a" * 64, evidence_id=None, drive_letter="F", targets="$MFT", modules="MFTECmd",
        command_line="target: x; module: y", argv=["x", "y"], started_at="2026-09-12T00:00:00+00:00",
        ended_at="2026-09-12T00:01:00+00:00", duration_seconds=60.0,
        stdout_relative="tool-logs/host-collector.stdout.txt", stdout_sha256="b" * 64,
        stderr_relative="tool-logs/host-collector.stderr.txt", stderr_sha256="c" * 64,
        execution_environment=host_execution_environment(
            definitions_sha256="d" * 64, toolchain=None, source_hash_basis="test",
        ),
        definitions_sha256="d" * 64, exit_code=0,
    )
    assert result["tool_identity"]["name"] == "fmb-host-collector"
    assert result["source_evidence"]["hash_verified"] is True
    assert result["execution_environment"]["collection_agent"] == "fmb-host-collector"


def test_host_backend_preflight_reports_missing_requirements(tmp_path: Path) -> None:
    args = argparse.Namespace(windows_parsers=None, host_toolchain_root=str(tmp_path / "missing"))
    report = host_backend.preflight_host_collector_backend(args, which=lambda _name: None, exists=lambda _path: False)
    assert report["available"] is False
    assert {"dotnet", "windows_parsers", "vmrun"} <= set(report["missing"])
    assert "qemu-img" not in report["missing"]
    assert {"host_toolchain_lock", "host_toolchain_verified"} & set(report["missing"])
    assert "kape_definitions_verified" not in report["missing"]
    assert report["auto_selectable"] is False

    def unreadable(_path: Path) -> bool:
        raise OSError("unreadable")

    unvalidated = tmp_path / "parsers"
    unvalidated.mkdir()
    (unvalidated / "PECmd.exe").write_bytes(b"MZ unvalidated build")
    args = argparse.Namespace(windows_parsers=str(unvalidated), host_toolchain_root=str(tmp_path / "missing"),
                              expected_definitions_sha256="0" * 64)
    report = host_backend.preflight_host_collector_backend(
        args, which=lambda name: "/bin/vmrun" if name == "vmrun" else None, exists=unreadable)
    assert {"windows_parser_validated:PECmd.exe", "windows_parser_validated:SBECmd.exe",
            "kape_definitions_verified"} <= set(report["missing"])
    assert "vmrun" not in report["missing"]


def test_parser_appliance_packages_pinned_binaries_and_inputs(tmp_path: Path, monkeypatch) -> None:
    from fmb.collection.tools.host import parser_appliance

    parsers = tmp_path / "parsers"
    parsers.mkdir()
    (parsers / "PECmd.exe").write_bytes(b"MZ fake pecmd")
    builds = {hashlib.sha256(b"MZ fake pecmd").hexdigest(): "test build"}
    monkeypatch.setattr(parser_appliance, "validated_builds", lambda executable: builds)
    processors = KapeDefinitions(_definitions(tmp_path)).module_processors(["PECmd"])
    targets_root = tmp_path / "kape-output" / "targets"
    (targets_root / "F" / "Windows" / "prefetch").mkdir(parents=True)
    (targets_root / "F" / "Windows" / "prefetch" / "A.pf").write_bytes(b"MAM")
    (targets_root / "F" / "Users" / "u").mkdir(parents=True)
    (targets_root / "F" / "Users" / "u" / "NTUSER.DAT").write_bytes(b"regf")
    (targets_root / "2026-10-02T00_00_00_0000000_CopyLog.csv").write_text(
        "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,"
        "LastAccessedOnUtc,CopyDuration\n"
        "2026-10-02 00:00:00,F:\\Windows\\prefetch\\A.pf,targets/F/Windows/prefetch/A.pf,3,X,False,"
        "2023-09-08 04:40:00.1600422,2023-09-08 04:40:01,2023-09-08 04:40:02.5,00:00:00\n",
        encoding="utf-8",
    )
    package = build_input_package(
        package_path=tmp_path / "inputs.zip", parsers_dir=parsers, processors=processors, targets_root=targets_root,
    )
    with zipfile.ZipFile(tmp_path / "inputs.zip") as opened:
        names = sorted(opened.namelist())
        plan = json.loads(opened.read("plan.json"))
    assert names == ["bin/PECmd.exe", "plan.json", "targets/F/Windows/prefetch/A.pf"]
    assert plan["commands"][0]["arguments"] == ["-d", "%targets%", "--csv", "%out%", "--mp", "-q"]
    assert plan["commands"][0]["executable_sha256"] == hashlib.sha256(b"MZ fake pecmd").hexdigest()
    assert plan["commands"][0]["build"] == "test build"
    assert package["input_file_count"] == 1
    assert plan["file_times"] == [{"path": "targets/F/Windows/prefetch/A.pf", "created": 133386216001600422,
                                   "modified": 133386216010000000, "accessed": 133386216025000000}]
    assert render_guest_arguments("-d %sourceDirectory% --csv %destinationDirectory%") == ["-d", "%targets%", "--csv", "%out%"]
    with pytest.raises(ParserApplianceError):
        render_guest_arguments("-f %sourceFile%")
    (parsers / "PECmd.exe").write_bytes(b"MZ another build")
    with pytest.raises(ParserApplianceError, match="not a validated build"):
        build_input_package(
            package_path=tmp_path / "other.zip", parsers_dir=parsers, processors=processors, targets_root=targets_root,
        )


@pytest.mark.parametrize("rows, empty", [("", ["PECmd"]), ("a.pf,1\n", [])])
def test_parser_appliance_outputs_get_the_zero_row_guard(tmp_path: Path, rows: str, empty: list[str]) -> None:
    from fmb.collection.tools.host import parser_appliance

    package = {
        "commands": [{"label": "PECmd", "category": "ProgramExecution", "executable_sha256": "e" * 64,
                      "input_file_count": 1, "input_byte_count": 3}],
        "package_sha256": "p" * 64, "input_file_count": 1,
    }
    receipt = {"schema_version": parser_appliance.RECEIPT_SCHEMA, "os": "Windows", "machine": "ARM64",
               "results": [{"label": "PECmd", "executable_sha256": "e" * 64, "exit_code": 0,
                            "category": "ProgramExecution", "arguments": []}]}
    outputs_zip = tmp_path / "outputs.zip"
    with zipfile.ZipFile(outputs_zip, "w") as opened:
        opened.writestr("receipt.json", json.dumps(receipt))
        opened.writestr("modules\\ProgramExecution\\PECmd_Output.csv", "SourceFilename,RunCount\n" + rows)
    tool_logs = tmp_path / "logs"
    tool_logs.mkdir()
    record = parser_appliance._merge_outputs(
        outputs_zip=outputs_zip, appliance_dir=tmp_path / "appliance",
        modules_root=tmp_path / "kape-output" / "modules", tool_logs=tool_logs, package=package,
    )
    assert record["empty_output_modules"] == empty
    assert record["results"][0]["data_row_count"] == (0 if empty else 1)


def test_validated_windows_parser_builds_are_listed_in_the_lock() -> None:
    from fmb.collection.tools.host.parser_appliance import WINDOWS_PARSERS, validated_builds

    for executable in WINDOWS_PARSERS:
        builds = validated_builds(executable)
        assert len(builds) == 2 and all(len(digest) == 64 for digest in builds)


@needs_tsk
def test_extractor_rejects_native_path_escape_and_writes_nothing_outside_root(tmp_path: Path) -> None:
    case = tmp_path / "case"
    output = case / "out"
    output.mkdir(parents=True)
    sentinel = case / "escape.txt"
    sentinel.write_bytes(b"ORIGINAL_PUBLIC_SENTINEL")
    elsewhere = case / "elsewhere"
    elsewhere.mkdir()
    index = _index(
        tmp_path,
        {
            20: _record(20, [_resident(0x30, _fn("../../../escape.txt", 5)), _resident(0x80, b"REPLACED")]),
            21: _record(21, [_resident(0x30, _fn("victim.dat", 5)), _resident(0x80, b"NEW")]),
            22: _directory(22, "Windows", 5),
            23: _record(23, [_resident(0x30, _fn("x.txt", 22)), _resident(0x80, b"X")]),
        },
    )
    assert index.entries[20].names[0].name == "../../../escape.txt"
    preexisting = output / "targets" / "C" / "victim.dat"
    preexisting.parent.mkdir(parents=True)
    preexisting.write_bytes(b"KEEP")
    (output / "targets" / "C" / "Windows").symlink_to(elsewhere, target_is_directory=True)

    result = extract_targets(index, [_rule("C:\\", "*.*"), _rule("C:\\Windows\\", "*")], output_root=output)

    assert result.copied == []
    assert [(item.source_path, item.reason) for item in result.skipped] == [
        ("C:\\../../../escape.txt", SKIP_REASON_UNSAFE_PATH),
        ("C:\\victim.dat", SKIP_REASON_DESTINATION_EXISTS),
        ("C:\\Windows\\x.txt", SKIP_REASON_UNSAFE_PATH),
    ]
    assert sentinel.read_bytes() == b"ORIGINAL_PUBLIC_SENTINEL"
    assert preexisting.read_bytes() == b"KEEP"
    assert list(elsewhere.iterdir()) == []
    outside = sorted(
        path for path in case.rglob("*") if path.is_file() and not path.is_relative_to(output)
    )
    assert outside == [sentinel]
    assert "unsafe_path" in result.log_files["skip_log"].read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        extract_targets(index, [_rule("C:\\", "*")], output_root=tmp_path / "bad", drive_letter="../F")
    traversal = extract_targets(index, [_rule("C:\\", "victim.dat", save_as="..\\..\\hijack")], output_root=tmp_path / "save-as")
    assert traversal.copied == [] and traversal.skipped[0].reason == SKIP_REASON_UNSAFE_PATH


@needs_tsk
def test_index_attaches_extension_records_only_through_the_attribute_list(tmp_path: Path) -> None:
    stale = _index(
        tmp_path / "stale",
        {
            20: _record(20, [_resident(0x30, _fn("victim.dat", 5))], sequence=2),
            21: _record(21, [_resident(0x80, b"STALE_EXTENSION")], base=_reference(20, 1)),
        },
    )
    assert 21 not in stale.entries
    assert stale.entries[20].streams == {}
    with pytest.raises(NtfsIndexError, match="stream is absent"):
        stale.copy_stream(20, "", lambda _chunk: None)

    def chain(directory: Path, extension_base: int) -> VolumeIndex:
        entries = _list_entry(0x30, 1, _reference(30, 2)) + _list_entry(0x80, 2, _reference(31, 1))
        return _index(
            directory,
            {
                30: _record(
                    30,
                    [_resident(0x30, _fn("split.dat", 5), identity=1), _resident(0x20, entries, identity=3)],
                    sequence=2,
                ),
                31: _record(31, [_resident(0x80, b"EXTENSION_DATA", identity=2)], base=extension_base),
            },
        )

    valid = chain(tmp_path / "valid", _reference(30, 2))
    assert 31 not in valid.entries and _path_of(valid, 30) == "\\split.dat"
    copied: list[bytes] = []
    assert valid.copy_stream(30, "", copied.append).bytes_written == len(b"EXTENSION_DATA")
    assert b"".join(copied) == b"EXTENSION_DATA"

    other_base = chain(tmp_path / "other", _reference(29, 2))
    assert 30 not in other_base.entries and _path_of(other_base, 30) is None
    with pytest.raises(NtfsIndexError, match="stream is absent"):
        other_base.copy_stream(30, "", lambda _chunk: None)


@needs_tsk
def test_copy_stream_refuses_runs_outside_the_selected_volume(tmp_path: Path) -> None:
    index = _index(
        tmp_path,
        {
            20: _record(20, [_resident(0x30, _fn("outside.bin", 5)), _nonresident(0x80, [(1, 140)], logical=4)]),
            21: _record(21, [_resident(0x30, _fn("overlap.bin", 5)), _nonresident(0x80, [(2, 60), (2, 61)], logical=8192)]),
            22: _record(22, [_resident(0x30, _fn("inside.bin", 5)), _nonresident(0x80, [(1, 62)], logical=4)]),
        },
        {60: b"OVERLAP!", 62: b"DATA", 140: b"DATA"},
        image_clusters=160,
    )
    assert 20 not in index.entries and _path_of(index, 20) is None
    sink: list[bytes] = []
    with pytest.raises(NtfsIndexError, match="stream is absent"):
        index.copy_stream(20, "", sink.append)
    with pytest.raises(UnsupportedStreamError, match="overlap"):
        index.copy_stream(21, "", sink.append)
    assert sink == []
    assert index.copy_stream(22, "", sink.append).bytes_written == 4
    assert b"".join(sink) == b"DATA"


@needs_tsk
@pytest.mark.skipif(not QEMU_AVAILABLE, reason="qemu-img is required to build the VMDK fixtures")
def test_partitioned_vmdk_reads_like_the_raw_volume(tmp_path: Path) -> None:
    volume, _mft = _image(tmp_path)
    disk = bytearray(1024 * 1024) + volume.read_bytes()
    struct.pack_into("<BBBBBBBBII", disk, 446, 0, 0, 0, 0, 7, 0, 0, 0, 2048, len(disk) // 512 - 2048)
    disk[510:512] = b"\x55\xaa"
    (tmp_path / "disk.raw").write_bytes(bytes(disk))
    vmdk = tmp_path / "disk.vmdk"
    subprocess.run(
        ["qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(tmp_path / "disk.raw"), str(vmdk)],
        check=True, capture_output=True, timeout=60,
    )
    raw, index = VolumeIndex(volume), VolumeIndex(vmdk)
    assert index.partition_offset == 1024 * 1024 and index.geometry == raw.geometry
    assert index.children == raw.children and index.entries.keys() == raw.entries.keys()
    copied: list[bytes] = []
    index.copy_stream(32, "", copied.append)
    assert b"".join(copied) == b"E" * 4096 + bytes(4096)
    child = tmp_path / "child.vmdk"
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "vmdk", "-b", str(vmdk), "-F", "vmdk", str(child)],
        check=True, capture_output=True, timeout=60,
    )
    with pytest.raises(NtfsIndexError, match="self-contained"):
        VolumeIndex(child)


@needs_tsk
def test_hardlinked_names_are_enumerated_and_matched_per_link(tmp_path: Path) -> None:
    index = _index(
        tmp_path,
        {
            20: _record(
                20,
                [
                    _resident(0x30, _fn("first.txt", 5), identity=1),
                    _resident(0x30, _fn("second.bmp", 5), identity=2),
                    _resident(0x80, b"same bytes", identity=3),
                ],
            ),
        },
    )
    links = [item for item in index.iter_file_paths(5, recursive=False) if item[2] == 20]
    assert links == [((), "first.txt", 20), ((), "second.bmp", 20)]
    only_bmp = extract_targets(index, [_rule("C:\\", "*.bmp")], output_root=tmp_path / "bmp")
    assert [item.relative_path for item in only_bmp.copied] == ["targets/C/second.bmp"]
    assert (tmp_path / "bmp" / "targets" / "C" / "second.bmp").read_bytes() == b"same bytes"
    both = extract_targets(index, [_rule("C:\\", "*.txt|*.bmp")], output_root=tmp_path / "both")
    assert [item.relative_path for item in both.copied] == ["targets/C/first.txt"]
    assert [(item.source_path, item.reason) for item in both.skipped] == [("C:\\second.bmp", "Deduped")]


@needs_tsk
def test_copies_keep_their_source_times_for_the_parsers(tmp_path: Path) -> None:
    from fmb.collection.tools.host.parser_appliance import copy_log_source_times

    index = _index(tmp_path, {20: _record(20, [_resident(0x30, _fn("a.pf", 5)), _resident(0x80, b"MAM")])})
    created, modified, accessed = 133387920001600422, 133387920001600423, 133400000000000000
    index.entries[20].standard_information = {
        key: {"ntfs_filetime": value, "utc": filetime_to_utc_iso(value)}
        for key, value in (("created", created), ("modified", modified), ("accessed", accessed))
    }
    output = tmp_path / "out"
    result = extract_targets(index, [_rule("C:\\", "a.pf")], output_root=output)
    copy = output / result.copied[0].relative_path
    epoch = 116444736000000000
    assert copy.stat().st_mtime_ns == (modified - epoch) * 100
    assert copy.stat().st_atime_ns == (accessed - epoch) * 100
    assert copy_log_source_times(output / "targets") == {
        "targets/C/a.pf": {"created": created, "modified": modified, "accessed": accessed}
    }


@needs_tsk
def test_extractor_logs_every_rematch_it_does_not_copy(tmp_path: Path) -> None:
    from fmb.collection.tools.host.extractor import SKIP_REASON_ALREADY_COPIED, SKIP_REASON_DESTINATION_TAKEN

    index = _index(tmp_path, {
        20: _record(20, [_resident(0x30, _fn("a.txt", 5)), _resident(0x80, b"A")]),
        21: _record(21, [_resident(0x30, _fn("b.txt", 5)), _resident(0x80, b"B")]),
    })
    rules = [_rule("C:\\", "a.txt"), _rule("C:\\", "a.txt"),
             _rule("C:\\", "a.txt", save_as="same.txt"), _rule("C:\\", "b.txt", save_as="same.txt")]
    result = extract_targets(index, rules, output_root=tmp_path / "out", deduplicate_by_content=False)
    assert [item.relative_path for item in result.copied] == ["targets/C/a.txt", "targets/C/same.txt"]
    assert [(item.source_path, item.reason) for item in result.skipped] == [
        ("C:\\a.txt", SKIP_REASON_ALREADY_COPIED),
        ("C:\\b.txt", SKIP_REASON_DESTINATION_TAKEN),
    ]
    assert (tmp_path / "out" / "targets" / "C" / "same.txt").read_bytes() == b"A"


def _host_bundle(
    root: Path,
    *,
    request_args: list[str],
    appliance: dict,
    result_args: list[str] | None = None,
    module_runs: list[dict] | None = None,
    extra_outputs: dict[str, str] | None = None,
) -> dict:
    root.mkdir(parents=True)
    bundle = root / "bundle"
    output = bundle / "kape-output"
    output.mkdir(parents=True)
    (output / "public.txt").write_text("public", encoding="utf-8")
    for relative, content in (extra_outputs or {}).items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    logs = bundle / "tool-logs"
    logs.mkdir()
    stdout = logs / "stdout.txt"
    stderr = logs / "stderr.txt"
    stdout.write_text("done", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    request = build_tool_run_request(
        question_id="FULL-SCALE", question_text="Public fixture", collector="kape", run_id="public-host",
        collector_config={"source": "F:\\", "output": "kape-output", "targets": "RegistryHives", "modules": "SBECmd", "extra_args": request_args},
        source_evidence_sha256="a" * 64, expected_platform=host_backend.HOST_COLLECTOR_PLATFORM, expected_tool="fmb-host-collector",
        required_capability="fmb_host_collector",
    )
    request_path = root / "tool_run_request.json"
    write_json(request_path, request)
    result = build_host_result(
        request=request, request_path=request_path, evidence_path=root / "public.vmdk", evidence_sha256="a" * 64,
        evidence_id=None, drive_letter="F", targets="RegistryHives", modules="SBECmd", command_line="fixture",
        argv=["fixture"], started_at="2026-09-12T00:00:00+00:00", ended_at="2026-09-12T00:01:00+00:00",
        duration_seconds=60, stdout_relative="tool-logs/stdout.txt", stdout_sha256=digest(stdout),
        stderr_relative="tool-logs/stderr.txt", stderr_sha256=digest(stderr),
        execution_environment=host_execution_environment(
            definitions_sha256="d" * 64, toolchain={"lock_sha256": "b" * 64}, source_hash_basis="public fixture",
        ),
        definitions_sha256="d" * 64, exit_code=0,
        extra_args=request_args if result_args is None else result_args,
    )
    metadata = {
        "module_runs": (
            [{"status": "deferred", "module": "SBECmd"}] if module_runs is None else module_runs
        ),
        "toolchain": {"lock_sha256": "b" * 64},
        "parser_appliance": appliance,
    }
    documents = write_host_bundle_documents(
        bundle_dir=bundle, request=request, request_path=request_path, result=result, metadata=metadata,
    )
    return {
        "documents": documents,
        "validate": dict(
            request_path=request_path, result_path=documents["result"], manifest_path=documents["manifest"],
            collector_output_root=output, required_artifact_globs=["modules/FileFolderAccess/*.csv"],
        ),
    }


def test_bundle_metadata_is_hash_bound_and_waivers_need_request_authorization(tmp_path: Path) -> None:
    validate = host_backend.validate_host_collector_bundle
    run_args = parser_appliance_request_args("run", ["SBECmd"])
    completed = _host_bundle(
        tmp_path / "run", request_args=run_args,
        appliance={"mode": "run", "status": "completed", "modules": ["SBECmd"]},
    )
    result_document = json.loads(completed["documents"]["result"].read_text(encoding="utf-8"))
    binding = result_document["execution_environment"]["host_collector_metadata"]
    assert binding["path"] == "host_collector_metadata.json"
    assert binding["sha256"] == hashlib.sha256(completed["documents"]["metadata"].read_bytes()).hexdigest()
    with pytest.raises(host_backend.HostCollectorError, match="required KAPE artifact pattern missing"):
        validate(**completed["validate"])

    edited = json.loads(completed["documents"]["metadata"].read_text(encoding="utf-8"))
    edited["parser_appliance"].update(mode="skip", status="skipped")
    write_json(completed["documents"]["metadata"], edited)
    with pytest.raises(host_backend.HostCollectorError, match="does not match the hash bound"):
        validate(**completed["validate"])
    completed["documents"]["metadata"].unlink()
    with pytest.raises(host_backend.HostCollectorError, match="metadata is missing"):
        validate(**completed["validate"])

    skip_args = parser_appliance_request_args("skip", ["SBECmd"])
    authorized = _host_bundle(
        tmp_path / "skip", request_args=skip_args,
        appliance={"mode": "skip", "status": "skipped", "modules": ["SBECmd"]},
    )
    with pytest.raises(host_backend.HostCollectorError, match="does not declare a parser appliance mode"):
        validate(**authorized["validate"])

    executed_skip_without_request = _host_bundle(
        tmp_path / "run-but-skipped", request_args=run_args,
        appliance={"mode": "skip", "status": "skipped", "modules": ["SBECmd"]},
    )
    with pytest.raises(host_backend.HostCollectorError, match="differs between request and execution"):
        validate(**executed_skip_without_request["validate"])

    unauthorized_module = _host_bundle(
        tmp_path / "skip-unlisted", request_args=parser_appliance_request_args("skip", []),
        appliance={"mode": "skip", "status": "skipped", "modules": ["SBECmd"]},
    )
    with pytest.raises(host_backend.HostCollectorError, match="does not declare a parser appliance mode"):
        validate(**unauthorized_module["validate"])

    undeclared = _host_bundle(
        tmp_path / "undeclared", request_args=[],
        appliance={"mode": "skip", "status": "skipped", "modules": ["SBECmd"]},
    )
    with pytest.raises(host_backend.HostCollectorError, match="does not declare a parser appliance mode"):
        validate(**undeclared["validate"])


def test_toolchain_verifies_declared_trees_and_runtime_identity(tmp_path: Path) -> None:
    root = tmp_path / "toolchain"
    (root / "Tool").mkdir(parents=True)
    dll = root / "Tool" / "Tool.dll"
    dll.write_bytes(b"public-stub-not-executable")
    lock = {
        "schema_version": "fmb_host_toolchain_lock.v1",
        "dotnet_runtime": "Microsoft.NETCore.App 10.0.7",
        "tools": [{
            "directory": "Tool", "entry_assembly": "Tool.dll", "tool": "Tool", "executable": "Tool.exe",
            "entry_assembly_sha256": hashlib.sha256(dll.read_bytes()).hexdigest(),
        }],
        "registry_plugins": {"directory": "RECmd/Plugins", "file_count": 66, "tree_sha256": "0" * 64},
        "assets": {"EvtxECmd/Maps": {"file_count": 429, "tree_sha256": "0" * 64}},
    }
    missing = HostToolchain(root, lock).unverified()
    assert [(row["kind"], row["tree"], row["status"]) for row in missing] == [
        ("tree", "RECmd/Plugins", "missing"), ("tree", "EvtxECmd/Maps", "missing"),
    ]

    plugins = root / "RECmd" / "Plugins"
    plugins.mkdir(parents=True)
    (plugins / "RegistryPlugin.B.dll").write_bytes(b"plugin b")
    (plugins / "RegistryPlugin.A.dll").write_bytes(b"plugin a")
    maps = root / "EvtxECmd" / "Maps"
    (maps / "sub").mkdir(parents=True)
    (maps / "sub" / "x.map").write_text("map", encoding="utf-8")
    plugin_hash, plugin_count = tree_sha256(plugins)
    names = ["RegistryPlugin.A.dll", "RegistryPlugin.B.dll"]
    lines = "".join(f"{name}\t{hashlib.sha256((plugins / name).read_bytes()).hexdigest()}\n" for name in names)
    assert plugin_count == 2 and plugin_hash == hashlib.sha256(lines.encode("utf-8")).hexdigest()
    map_hash, map_count = tree_sha256(maps)
    lock["registry_plugins"].update(file_count=plugin_count, tree_sha256=plugin_hash)
    lock["assets"]["EvtxECmd/Maps"].update(file_count=map_count, tree_sha256=map_hash)
    toolchain = HostToolchain(root, lock)
    assert toolchain.unverified() == []
    described = toolchain.describe(verification=toolchain.verify())
    observed = {row["tree"]: row["observed_sha256"] for row in described["verification"] if row["kind"] == "tree"}
    assert observed == {"RECmd/Plugins": plugin_hash, "EvtxECmd/Maps": map_hash} and described["verified"] is True

    runtimes = lambda _dotnet: ["Microsoft.NETCore.App 10.0.7 [/opt/dotnet/shared/Microsoft.NETCore.App]"]
    assert toolchain.unverified(dotnet=str(dll), list_runtimes=runtimes) == []
    older = lambda _dotnet: ["Microsoft.NETCore.App 9.0.4 [/opt/dotnet/shared/Microsoft.NETCore.App]"]
    runtime_rows = toolchain.unverified(dotnet=str(dll), list_runtimes=older)
    assert [(row["kind"], row["status"]) for row in runtime_rows] == [("runtime", "mismatch")]
    assert runtime_rows[0]["dotnet_sha256"] == hashlib.sha256(dll.read_bytes()).hexdigest()
    assert [row["status"] for row in toolchain.unverified(dotnet=str(dll), list_runtimes=lambda _d: None)] == ["unreadable"]

    (plugins / "RegistryPlugin.A.dll").write_bytes(b"plugin a (changed)")
    tampered = toolchain.unverified()
    assert [(row["tree"], row["status"]) for row in tampered] == [("RECmd/Plugins", "hash_mismatch")]
    assert tampered[0]["observed_sha256"] == tree_sha256(plugins)[0] != plugin_hash
    lock["registry_plugins"].update(file_count=3, tree_sha256=tree_sha256(plugins)[0])
    assert [row["status"] for row in HostToolchain(root, lock).unverified()] == ["file_count_mismatch"]


def test_modules_receive_absolute_paths_when_called_with_relative_ones(tmp_path: Path, monkeypatch) -> None:
    script = tmp_path / "tool.py"
    script.write_text(
        "import sys, pathlib\n"
        "args = sys.argv[1:]\n"
        "dest = pathlib.Path(args[args.index('--csv') + 1])\n"
        "assert dest.is_absolute(), dest\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        "(dest / 'out.csv').write_text('Command,Value\\n')\n",
        encoding="utf-8",
    )
    root, lock = _lock(tmp_path, entry=script)
    toolchain = HostToolchain(root, lock, lock_path=tmp_path / "lock.json")
    processors = KapeDefinitions(_definitions(tmp_path)).module_processors(["PECmd"])
    processors = [processors[0].__class__(**{**processors[0].__dict__, "executable": "Tool.exe", "file_mask": None})]
    (tmp_path / "run" / "kape-output" / "targets").mkdir(parents=True)
    monkeypatch.chdir(tmp_path / "run")
    runs = run_module_processors(
        processors, toolchain=toolchain, dotnet=sys.executable, targets_root=Path("kape-output/targets"),
        modules_root=Path("kape-output/modules"), tool_logs_dir=Path("tool-logs"),
    )
    assert [run.status for run in runs] == ["completed"]
    assert (tmp_path / "run" / "kape-output" / "modules" / "ProgramExecution" / "out.csv").is_file()


@needs_tsk
def test_empty_resident_stream_copies_as_empty_bytes(tmp_path: Path) -> None:
    index = _index(tmp_path, {24: _record(24, [_resident(0x30, _fn("User.dat.LOG2", 5)), _resident(0x80, b"", identity=2)])})
    stream = index.merged_stream(24, "")
    assert stream is not None and stream.resident == b"" and stream.logical_size == 0
    copied = bytearray()
    report = index.copy_stream(24, "", copied.extend)
    assert copied == b"" and report.bytes_written == 0 and report.resident


def test_required_artifact_patterns_ignore_case_as_windows_paths_do(tmp_path):
    from fmb.collection.tools.host.validation import any_case, assert_required_kape_artifacts

    log = tmp_path / "targets" / "C" / "Windows" / "System32" / "winevt" / "logs" / "Security.evtx"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"ElfFile")
    checks: list[dict] = []
    assert_required_kape_artifacts(tmp_path, ["targets/*/Windows/System32/winevt/Logs/*.evtx"], checks=checks)
    assert checks[-1]["status"] == "pass"
    assert any_case("targets/*/$MFT") == "[tT][aA][rR][gG][eE][tT][sS]/*/$[mM][fF][tT]"
