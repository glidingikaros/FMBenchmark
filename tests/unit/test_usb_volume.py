from __future__ import annotations

import copy
import csv
import importlib.util
import json
import struct
from pathlib import Path

import pytest

from fmb.analysis.catalog import techniques_for_question
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.analysis.usb_volume import assess_usb_volume_activity
from fmb.collection.usb_volume import manifest_artifact
from fmb.core.hashing import sha256_file
from fmb.index.scanners.usb_volume import (
    parse_retained_journal,
    parse_usb_volume_facts,
    shell_link_from_lecmd,
)
from paper_fixtures import projected_input

spec = importlib.util.spec_from_file_location("native_ntfs_fixture", Path(__file__).with_name("test_ntfs_surfaces.py"))
assert spec and spec.loader
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
FRN = 30 | 7 << 48


def link(*, entry="0x1E", sequence="0x7", serial="AABBCCDD", name="original.txt",
         local="U:\\Records\\original.txt", source=r"C:\kape-output\targets\C\Users\vagrant\native.lnk"):
    return {"SourceFile": source, "DriveType": "Removable storage media (Floppy, USB)",
            "VolumeSerialNumber": serial, "VolumeLabel": "RecordsMedia", "LocalPath": local,
            "CommonPath": "", "TargetIDAbsolutePath": "This PC\\U:\\Records\\" + name,
            "TargetMFTEntryNumber": entry, "TargetMFTSequenceNumber": sequence}


def usn(name="renamedx.txt", *, offset=0, reason=0x200, reference=FRN):
    encoded = name.encode("utf-16le")
    size = (60 + len(encoded) + 7) & ~7
    return struct.pack("<IHHQQqQIIIIHH", size, 2, 0, reference, 20 | 3 << 48, offset,
        132537600000000000, reason, 0, 0, 32, len(encoded), 60) + encoded + bytes(size - 60 - len(encoded))


def facts(*, active=False, name="renamedx.txt", reason=0x200, directory_parent=5, mft_sequence=7):
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 11, 512)
    boot[13] = 8
    struct.pack_into("<QQQ", boot, 40, 131072, 4, 8)
    struct.pack_into("<bb", boot, 64, -10, 0)
    struct.pack_into("<b", boot, 68, -12)
    struct.pack_into("<Q", boot, 72, 0x11223344AABBCCDD)
    boot[510:] = b"\x55\xaa"
    mft = bytearray(31 * 1024)
    mft[5 * 1024:6 * 1024] = native._record(5, [], flags=3)
    mft[20 * 1024:21 * 1024] = native._record(20, [native._resident(0x30, native._fn("Records", directory_parent, 1))], sequence=3, flags=3)
    mft[30 * 1024:] = native._record(30, [native._resident(0x30, native._fn(name))], sequence=mft_sequence, flags=int(active))
    binding = {"device_instance_id": "USBSTOR\\Disk&Ven_VMware&Prod_Virtual_Storage&Rev_1.00\\SERIAL&0",
        "attachment_kind": "hypervisor_virtual_usb_mass_storage", "physical_host_device": False,
        "disk_bus_type": "USB", "disk_size_bytes": 64 * 1024 * 1024, "volume_guid_path": "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\",
        "volume_serial_number": "AABBCCDD", "target_path": "U:\\Records\\original.txt",
        "target_file_reference_number": FRN, "journal_id": 123, "journal_start_usn": 0}
    result = parse_usb_volume_facts(boot=bytes(boot), mft=bytes(mft), journal=usn(name, reason=reason),
        journal_max=struct.pack("<QQQQ", 8388608, 1048576, 123, 0), link=link(), binding=binding)
    result["native_binding_hash_verified"] = True
    return result


def test_shell_link_binds_native_volume_path_and_exact_target_reference():
    parsed = shell_link_from_lecmd(link())
    assert parsed["target_file_reference_number"] == FRN
    assert parsed["volume_serial_number"] == "aabbccdd"
    assert parsed["drive_type"] == 2
    assert parsed["target_path"] == "U:\\Records\\original.txt"
    assert shell_link_from_lecmd(link(serial="00001234"))["volume_serial_number"] == "00001234"
    for sequence in ("", "0x0"):
        assert shell_link_from_lecmd(link(sequence=sequence))["target_file_reference_number"] is None
    assert shell_link_from_lecmd(link(name="other.txt"))["target_file_reference_number"] is None


@pytest.mark.parametrize("change", [
    {"DriveType": "(None)", "VolumeSerialNumber": "", "LocalPath": ""}, {"DriveType": "Drive 9"},
    {"VolumeSerialNumber": "AABBCC"}, {"LocalPath": "Records\\original.txt"},
    {"LocalPath": "\\\\server\\share\\original.txt"}, {"TargetMFTEntryNumber": "thirty"},
    {"TargetMFTSequenceNumber": "0x10000"}])
def test_shell_link_rejects_nonlocal_or_malformed_lecmd_rows(change):
    with pytest.raises(ValueError):
        shell_link_from_lecmd({**link(), **change})


def test_journal_scan_preserves_reference_and_detects_offset_corruption():
    maximum = struct.pack("<QQQQ", 8388608, 1048576, 123, 0)
    parsed = parse_retained_journal(bytes(8) + usn(offset=8), maximum)
    assert parsed["scan_complete"] is True
    assert parsed["records"][0]["file_reference_number"] == FRN
    assert parse_retained_journal(bytes(8) + usn(), maximum)["scan_complete"] is False


def test_complete_native_reference_name_discrepancy_and_retained_benign():
    positive = facts()
    assert positive["native_identity_consistent"] is True
    assert positive["same_reference_mft_paths"] == ["\\Records\\renamedx.txt"]
    assert positive["alternative_name_usn_record_count"] == 1
    assert assess_usb_volume_activity(positive) == "supported"
    assert assess_usb_volume_activity(facts(active=True, name="original.txt", reason=0x100)) == "not_supported"
    assert assess_usb_volume_activity(facts(reason=0x2200)) == "indeterminate"


def test_unresolved_active_parent_cannot_turn_unindexed_path_into_absence():
    row = facts(directory_parent=25)
    assert row["active_mft_complete"] is False
    assert row["unresolved_active_mft_entries"] == [20]
    assert assess_usb_volume_activity(row) == "indeterminate"


def test_native_freeing_sequence_increment_preserves_distinct_historical_reference():
    row = facts(mft_sequence=8)
    assert row["native_mft_sequence_relation"] == "freed_immediate_successor"
    assert row["referenced_entry_mft_sequence"] == 8
    assert row["link_file_reference_number"] == FRN
    assert row["same_reference_mft_active"] is None
    assert row["same_reference_mft_paths"] == []
    assert assess_usb_volume_activity(row) == "supported"
    assert assess_usb_volume_activity(facts(mft_sequence=8, name="original.txt")) == "not_supported"


@pytest.mark.parametrize("change", ["active", "sequence_jump", "wrong_parent", "wrong_name", "no_delete", "wrap", "false_relation"])
def test_obsolete_reference_does_not_bind_reused_unmatched_or_wrapped_slot(change):
    row = facts(mft_sequence=8)
    if change == "active":
        row["referenced_entry_mft_active"] = True
    elif change == "sequence_jump":
        row["referenced_entry_mft_sequence"] = 9
    elif change == "wrong_parent":
        row["referenced_entry_file_names"][0]["parent_file_reference_number"] += 1
    elif change == "wrong_name":
        row["referenced_entry_file_names"][0]["name"] = "unrelated.txt"
    elif change == "no_delete":
        row["same_reference_usn_records"][0]["reason"] = 0x100
        row["same_reference_delete_record_count"] = 0
    elif change == "wrap":
        wrapped = 30 | 65535 << 48
        row["link_file_reference_number"] = row["binding_file_reference_number"] = wrapped
        row["same_reference_usn_records"][0]["file_reference_number"] = wrapped
        row["referenced_entry_mft_sequence"] = 1
    else:
        row["native_mft_sequence_relation"] = "exact"
    assert assess_usb_volume_activity(row) == "indeterminate"


@pytest.mark.parametrize("active,name,reason,outcome", [
    (False, "renamedx.txt", 0x200, "supported"),
    (True, "original.txt", 0x100, "not_supported"),
    (False, "renamedx.txt", 0x2200, "indeterminate"),
])
def test_native_device_roster_central_decision_and_model_facts_remain_aligned(active, name, reason, outcome):
    fields = facts(active=active, name=name, reason=reason)
    observation = {"observation_id": "obs:native-usb-fixture", "artifact_family": "usb_volume",
        "observation_type": "usb_volume_reference_history", "subject_ref": fields["device_instance_id"],
        "fields": fields, "source_record_ref": "fixture:native-usb"}
    index = {"schema_version": "evidence_index.v1", "run_id": "native-usb-fixture",
        "parser_runs": [{"parser_kind": "native_usb_volume", "status": "consumed",
                         "coverage_status": "complete", "observations": [observation]}]}
    technique = next(row for row in techniques_for_question("Q-MEDIA-01") if row.technique_id == "usb_volume_activity_gap")
    value = build_analysis_input(index, technique)
    assert value.readiness == "ready"
    assert len(value.candidate_roster.subjects) == 1
    assert analyze_input(value).assessments[0].outcome == outcome
    packet = json.dumps(projected_input(value))
    for key in ("native_boot_volume_serial", "link_file_reference_number", "same_reference_usn_records",
                "unresolved_active_mft_ancestry_count"):
        assert key in packet


@pytest.mark.parametrize("key,value", [
    ("native_identity_consistent", False), ("journal_lowest_valid_usn", 8),
    ("journal_scan_complete", False), ("active_mft_complete", False),
    ("disk_size_bytes", 123), ("physical_host_device", True),
    ("same_reference_usn_records", []), ("alternative_name_usn_record_count", 2),
    ("same_reference_mft_active", None), ("link_file_reference_number", 30),
])
def test_unproven_identity_incomplete_coverage_or_inconsistent_counts_fail_closed(key, value):
    row = facts()
    row[key] = value
    assert assess_usb_volume_activity(row) == "indeterminate"


def test_generation_binding_values_neither_reach_the_card_nor_decide():
    row = facts()
    expected = assess_usb_volume_activity(row)
    for key in ("binding_journal_id", "binding_journal_start_usn", "binding_file_reference_number",
                "native_binding_hash_verified", "attachment_kind", "physical_host_device"):
        changed = copy.deepcopy(row)
        changed.pop(key, None)
        assert assess_usb_volume_activity(changed, require_fixture_device=False) == expected, key
    from fmb.analysis.evidence_projection import _MODEL_FIELDS_BY_OBSERVATION_TYPE
    shown = set(_MODEL_FIELDS_BY_OBSERVATION_TYPE["usb_volume_reference_history"])
    assert not shown & {"attachment_kind", "physical_host_device", "volume_guid_path", "native_binding_file",
                        "native_binding_hash_verified"}
    assert not any(name.startswith("binding_") for name in shown)


def test_every_required_field_omission_and_numeric_bool_fail_closed():
    original = facts()
    for key in ("native_identity_consistent", "active_mft_complete", "journal_scan_complete",
                "same_reference_usn_records", "malformed_mft_entries", "journal_parse_error_offsets", "same_reference_mft_paths",
                "journal_id", "journal_lowest_valid_usn", "journal_retained_end_usn",
                "same_reference_rename_record_count", "active_original_path_count", "original_name_usn_record_count",
                "alternative_name_usn_record_count", "same_reference_delete_record_count", "link_file_reference_number",
                "disk_size_bytes"):
        missing = copy.deepcopy(original)
        del missing[key]
        assert assess_usb_volume_activity(missing) == "indeterminate", key
    original["original_name_usn_record_count"] = False
    assert assess_usb_volume_activity(original) == "indeterminate"


def test_manifest_bound_artifacts_reject_tampering_and_path_escape(tmp_path):
    artifact = tmp_path / "native_media.vmdk"
    artifact.write_bytes(b"retained native volume")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"artifacts": [{"file": artifact.name, "size_bytes": artifact.stat().st_size, "sha256": sha256_file(artifact)}]}))
    assert manifest_artifact(manifest, artifact.name) == artifact
    artifact.write_bytes(b"different native bytes")
    with pytest.raises(ValueError, match="does not match"):
        manifest_artifact(manifest, artifact.name)
    with pytest.raises((ValueError, FileNotFoundError)):
        manifest_artifact(manifest, "../native_media.vmdk")


def test_collector_and_adapter_retain_whole_sources_and_reject_later_tampering(tmp_path, monkeypatch):
    from fmb.collection import usb_volume as collection
    from fmb.index.adapters import usb_volume as adapter
    generated = tmp_path / "generated"
    generated.mkdir()
    primary = generated / "full_scale.vmdk"
    primary.write_bytes(b"synthetic primary bytes")
    companion = generated / "native_media.vmdk"
    companion.write_bytes(b"synthetic companion bytes")
    binding = generated / "native_media_binding.json"
    binding.write_text(json.dumps({"schema_version": "native_media_binding.v1", "companion_file": companion.name,
        "disk_bus_type": "USB", "attachment_kind": "hypervisor_virtual_usb_mass_storage", "physical_host_device": False,
        "link_path": r"C:\Users\vagrant\AppData\Roaming\Microsoft\Windows\Recent\native.lnk"}), encoding="utf-8-sig")
    manifest = generated / "manifest.json"
    manifest.write_text(json.dumps({"artifacts": [{"file": path.name, "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path)} for path in (primary, companion, binding)]}))
    kape = tmp_path / "kape-output"
    shortcut = kape / "targets/C/Users/vagrant/AppData/Roaming/Microsoft/Windows/Recent/native.lnk"
    shortcut.parent.mkdir(parents=True)
    shortcut.write_bytes(b"collected shortcut bytes")
    lecmd = kape / "modules/FileFolderAccess/20260918050416_LECmd_Output.csv"
    lecmd.parent.mkdir(parents=True)
    rows = [link(source=str(shortcut.with_name("other.lnk"))), link(source=str(shortcut))]
    with lecmd.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    monkeypatch.setattr(collection, "extract_companion_streams", lambda *_: {key: key.encode() for key in ("boot", "mft", "journal", "journal_max")})
    native_manifest = collection.collect_usb_volume(generation_manifest_path=manifest, kape_root=kape,
        output_dir=tmp_path / "native", evidence_sha256=sha256_file(primary))
    receipt = json.loads(native_manifest.read_text())
    assert receipt["sources"]["link"]["sha256"] == sha256_file(shortcut)
    decoded = {}
    monkeypatch.setattr(adapter, "parse_usb_volume_facts", lambda **sources: decoded.update(sources) or facts())
    parsed = adapter.usb_volume_parser_run(native_manifest_path=native_manifest,
        normalized_output_dir=tmp_path / "normalized", collector_run={"collector": "kape"})
    assert decoded["link"]["SourceFile"] == str(shortcut)
    retained = {row["path"] for row in parsed["raw_outputs"]}
    assert {str(companion), str(shortcut), str(lecmd)} <= retained
    assert parsed["observations"][0]["fields"]["native_binding_hash_verified"] is True
    assert parsed["observations"][0]["subject_ref"] == facts()["device_instance_id"]
    payload = json.loads(Path(parsed["normalized_output"]["path"]).read_text())
    assert payload["record_count"] == parsed["observation_count"] == 1
    assert payload["observations"] == parsed["observations"]
    assert payload["truth_sources_used"] == []
    companion.write_bytes(b"changed companion")
    with pytest.raises(ValueError, match="complete original source hash"):
        adapter.usb_volume_parser_run(native_manifest_path=native_manifest,
            normalized_output_dir=tmp_path / "normalized", collector_run={"collector": "kape"})
    companion.write_bytes(b"synthetic companion bytes")
    lecmd.write_text(lecmd.read_text(encoding="utf-8-sig").splitlines()[0] + "\n", encoding="utf-8-sig")
    with pytest.raises(ValueError, match="LECmd did not decode"):
        collection.collect_usb_volume(generation_manifest_path=manifest, kape_root=kape,
            output_dir=tmp_path / "native-again", evidence_sha256=sha256_file(primary))


@pytest.mark.skipif(
    not all(importlib.util.find_spec(name) for name in ("pytsk3", "pyvmdk")),
    reason="pytsk3 and libvmdk-python are required for image reads",
)
@pytest.mark.parametrize("size", [64 * 1024 * 1024, 32 * 1024 * 1024, 96 * 1024 * 1024])
def test_companion_streams_are_read_through_the_sleuth_kit(tmp_path: Path, size: int) -> None:
    import test_host_collector as ntfs
    from fmb.collection.usb_volume import extract_companion_streams

    journal = b"U" * 96
    records = {
        5: ntfs._directory(5, ".", 5, (ntfs._reference(11, 1), ntfs._fn("$Extend", 5))),
        11: ntfs._directory(11, "$Extend", 5, (ntfs._reference(40, 2), ntfs._fn("$UsnJrnl", 11))),
        40: ntfs._record(
            40,
            [
                ntfs._resident(0x30, ntfs._fn("$UsnJrnl", 11)),
                ntfs._nonresident(0x80, [(2, None), (1, 100)], logical=3 * 4096, name="$J", identity=3),
                ntfs._resident(0x80, b"M" * 32, name="$Max", identity=4),
            ],
            sequence=2,
        ),
    }
    image = ntfs._volume(records, {100: journal}, image_clusters=size // 4096)
    path = tmp_path / "companion.raw"
    path.write_bytes(image)
    binding = {"disk_size_bytes": size, "partition_offset_bytes": 0}
    streams = extract_companion_streams(path, binding)
    assert streams["boot"] == image[:512]
    assert streams["mft"] == image[4 * 4096 : 4 * 4096 + 48 * 1024]
    assert streams["journal"] == bytes(2 * 4096) + journal + bytes(4096 - len(journal))
    assert streams["journal_max"] == b"M" * 32
    with pytest.raises(ValueError, match="partition identity"):
        extract_companion_streams(path, {**binding, "partition_offset_bytes": 4096})
    with pytest.raises(ValueError, match="bounded disk"):
        extract_companion_streams(path, {**binding, "disk_size_bytes": 1024})


@pytest.mark.skipif(
    not all(importlib.util.find_spec(name) for name in ("pytsk3", "pyvmdk")),
    reason="pytsk3 and libvmdk-python are required for image reads",
)
def test_a_companion_beyond_the_medium_bound_is_refused_before_it_is_read(tmp_path: Path) -> None:
    from fmb.collection.usb_volume import extract_companion_streams
    from fmb.core.limits import MAX_USB_MEDIUM_BYTES

    path = tmp_path / "companion.raw"
    with path.open("wb") as handle:
        handle.truncate(MAX_USB_MEDIUM_BYTES + 512)
    with pytest.raises(ValueError, match="bounded disk"):
        extract_companion_streams(path, {"disk_size_bytes": MAX_USB_MEDIUM_BYTES + 512, "partition_offset_bytes": 0})


@pytest.mark.parametrize("size,valid", [(512, True), (32 * 1024 * 1024, True), (64 * 1024 * 1024, True),
                                        (4 * 1024 ** 3, True), (0, False), (123, False), (4 * 1024 ** 3 + 512, False),
                                        (67108864.0, False), ("67108864", False), (True, False)])
def test_a_medium_may_declare_any_sector_multiple_up_to_four_gibibytes(size, valid):
    from fmb.analysis.population_binding import _member_hint
    from fmb.core.limits import usb_medium_size

    assert usb_medium_size(size) is valid
    definition = next(row for row in techniques_for_question("Q-MEDIA-01")
                      if row.technique_id == "usb_volume_activity_gap")
    member = {"identity_hint": {"attachment_kind": "hypervisor_virtual_usb_mass_storage",
                                "disk_size_bytes": size, "binding_file": "media_0123456789ab.json"}}
    if valid:
        assert _member_hint(definition, member) == member["identity_hint"]
    else:
        with pytest.raises(ValueError, match="native USB population hint is invalid"):
            _member_hint(definition, member)
    row = facts()
    row["disk_size_bytes"] = size
    assert assess_usb_volume_activity(row) == ("supported" if valid else "indeterminate")


def _fake_volume(*, generation_manifest_path, kape_root, output_dir, evidence_sha256, binding_file):
    output_dir.mkdir(parents=True)
    receipt = output_dir / "native-usb-volume.json"
    receipt.write_text(json.dumps({"schema_version": "native_usb_volume_sources.v1", "evidence_sha256": evidence_sha256,
                                   "companion_sha256": binding_file[6] * 64,
                                   "sources": {"binding": {"file": binding_file}}}))
    return receipt


@pytest.mark.parametrize("count", [1, 2, 3, 5])
def test_any_number_of_registered_media_is_collected_and_read_back(tmp_path, monkeypatch, count):
    from fmb.collection import usb_volume as collection

    monkeypatch.setattr(collection, "collect_usb_volume", _fake_volume)
    names = [f"media_{digit * 12}.json" for digit in "13579"[:count]]
    index = collection.collect_usb_volumes(binding_files=names, generation_manifest_path=tmp_path / "manifest.json",
                                           kape_root=tmp_path, output_dir=tmp_path / "native-usb",
                                           evidence_sha256="a" * 64)
    assert [row["binding_file"] for row in json.loads(index.read_text())["volumes"]] == sorted(names)
    assert len(collection.usb_volume_source_manifests(index)) == count


@pytest.mark.parametrize("names", [[], ["media_111111111111.json"] * 2, ["media_11111111111.json"],
                                   ["media_111111111111.json", "native_media_binding.json"]])
def test_media_collection_refuses_an_empty_repeated_or_unregistered_binding_list(tmp_path, monkeypatch, names):
    from fmb.collection import usb_volume as collection

    monkeypatch.setattr(collection, "collect_usb_volume", _fake_volume)
    with pytest.raises(ValueError, match="one or more unique registered public bindings"):
        collection.collect_usb_volumes(binding_files=names, generation_manifest_path=tmp_path / "manifest.json",
                                       kape_root=tmp_path, output_dir=tmp_path / "native-usb", evidence_sha256="a" * 64)
