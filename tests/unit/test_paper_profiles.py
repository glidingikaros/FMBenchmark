import importlib.resources
import json

import pytest

from fmb import profiles
from fmb.analysis.catalog import TECHNIQUES
from fmb.analysis.questions import BROAD_QUESTIONS
from fmb.analysis.target_contract import TARGET_QUESTIONS
from fmb.core.hashing import sha256_file
from fmb.core.paths import PROJECT_ROOT
from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND


EXPECTED_COMPONENTS = {
    "BQ-TIME-01": ["timestamp_manipulation"],
    "BQ-DELETE-01": ["deleted_file_journal_residue", "typed_path_residue"],
    "BQ-SHELLBAG-01": ["shellbag_missing_directory"],
    "BQ-DIRECTORY-01": ["i30_directory_residue"],
    "BQ-STREAM-01": ["alternate_data_stream"],
    "BQ-USB-01": ["usbstor_setupapi_discrepancy", "usb_volume_activity_gap"],
    "BQ-FILE-01": ["bitmap_trailing_data", "ntfs_allocation_inconsistency"],
    "BQ-EXEC-01": ["prefetch_missing_executable", "shimcache_path_residue"],
    "BQ-LOG-01": ["security_log_clear_event", "event_record_sequence_gap"],
}
EXPECTED_FAMILIES = {
    "BQ-TIME-01": ["ntfs.logfile", "ntfs.mft", "ntfs.usn"],
    "BQ-DELETE-01": ["ntfs.logfile", "ntfs.mft", "ntfs.usn", "windows.registry.typed_paths"],
    "BQ-SHELLBAG-01": ["ntfs.mft", "ntfs.usn", "windows.registry.shellbag"],
    "BQ-DIRECTORY-01": ["ntfs.i30", "ntfs.mft", "ntfs.usn"],
    "BQ-STREAM-01": ["ntfs.ads", "ntfs.mft"],
    "BQ-USB-01": ["usb_volume", "windows.registry.usbstor", "windows.setupapi"],
    "BQ-FILE-01": ["collected.file.content", "ntfs.file_size_allocation", "ntfs.mft"],
    "BQ-EXEC-01": ["ntfs.mft", "windows.prefetch", "windows.registry.amcache", "windows.registry.shimcache"],
    "BQ-LOG-01": ["windows.event_log.record_sequence", "windows.event_log.security"],
}


def test_fixed_profile_covers_all_nine_questions_and_fourteen_components_in_order():
    profile = profiles.resolve_paper_profile()
    questions = profile["questions"]
    assert [item["question_id"] for item in questions] == list(EXPECTED_COMPONENTS)
    assert {item["question_id"]: item["technique_ids"] for item in questions} == EXPECTED_COMPONENTS
    assert {item["question_id"]: item["artifact_families"] for item in questions} == EXPECTED_FAMILIES
    assert profile["question_group_version"] == "broad_questions_20260912.v1"
    components = [component for question in questions for component in question["components"]]
    assert len(components) == len({item["technique_id"] for item in components}) == 14
    assert {item["technique_id"] for item in components} == {item.technique_id for item in TECHNIQUES}
    for resolved, declared in zip(questions, BROAD_QUESTIONS, strict=True):
        assert resolved["group_id"] == declared.group_id
        assert {"title": resolved["title"], "question_text": resolved["question_text"]} == (
            TARGET_QUESTIONS[resolved["question_id"]])


def test_family_requirements_keep_required_optional_and_alternative_routes_distinct():
    profile = profiles.resolve_paper_profile()
    definitions = {item.technique_id: item for item in TECHNIQUES}
    for question in profile["questions"]:
        assert [item["technique_id"] for item in question["components"]] == question["technique_ids"]
        for component in question["components"]:
            definition = definitions[component["technique_id"]]
            assert component["question_id"] == definition.question_id
            assert component["subject_type"] == definition.subject_type
            assert component["required_artifact_families"] == list(definition.required_artifact_families)
            assert component["optional_artifact_families"] == list(definition.optional_artifact_families)
            assert component["alternative_required_artifact_families"] == [
                list(group) for group in definition.alternative_required_artifact_families
            ]
    timestamp = profile["questions"][0]["components"][0]
    assert timestamp["required_artifact_families"] == ["ntfs.mft", "ntfs.usn"]
    assert timestamp["optional_artifact_families"] == ["ntfs.logfile"]
    assert timestamp["alternative_required_artifact_families"] == [["ntfs.mft", "ntfs.logfile"]]


def test_family_union_has_declared_parser_outputs_and_retains_supporting_records():
    profile = profiles.resolve_paper_profile()
    assert profile["artifact_families"] == sorted({family for families in EXPECTED_FAMILIES.values() for family in families})
    assert len(profile["artifact_families"]) == 17
    assert profile["parser_outputs"] == {kind: list(families) for kind, families in PARSER_ARTIFACT_FAMILIES_BY_KIND.items()}
    assert len(profile["parser_outputs"]) == 16
    assert set(profile["artifact_families"]) <= {family for families in profile["parser_outputs"].values() for family in families}
    assert profile["parser_outputs"]["windows_jump_list"] == ["windows.jump_list", "windows.lnk"]


def test_fixed_collection_declaration_and_packaged_targets_are_preserved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    decoy = tmp_path / "contracts/paper/collection.json"
    decoy.parent.mkdir(parents=True)
    decoy.write_text('{"question_id": "unrelated checkout"}')
    profile = profiles.resolve_paper_profile()
    packaged = importlib.resources.files("fmb").joinpath("contracts/paper/collection.json")
    declaration = profile["collection_declaration"]
    assert declaration == json.loads(packaged.read_text())
    assert sha256_file(PROJECT_ROOT / "contracts/paper/collection.json") == "4df6572d2f013ecc78e4db861989dfe07e7e996bf8089e9bd31c47764c5ef817"
    selection = declaration["collection"]["kape"]
    assert selection["target_names"] == [
        "$MFT", "$J", "$LogFile", "EventLogs", "EvidenceOfExecution", "RegistryHives",
        "Prefetch", "LNKFilesAndJumpLists", "USBDetective", "USBDevicesLogs",
        "FMBBoundedUserBMP", "FileSystem", "$Boot", "FMBSetupApiLogs",
    ]
    assert selection["module_names"] == [
        "MFTECmd", "MFTECmd_$J", "EvtxECmd", "PECmd", "AppCompatCacheParser",
        "AmcacheParser", "RECmd_Kroll", "JLECmd", "LECmd", "SBECmd",
    ]
    assert len(declaration["scenario_ids"]) == 14
    assert declaration["kape_definitions"]["commit"] == "c47575d8b91fcf884b6b56f9c1558823aee9eed3"
    assert declaration["historical_kape_archive_sha256"] == "5399945d55052267994a1a76decf54b8d463fd5fd29f65e1aca6f4b365516e31"
    from fmb.collection.tools.host.definitions import KapeDefinitions

    assert KapeDefinitions().tree_sha256 == declaration["kape_definitions"]["tree_sha256"]
    from fmb.collection.tools.kape.paths import BUNDLED_KAPE_TARGETS

    assert set(BUNDLED_KAPE_TARGETS) <= set(selection["target_names"])
    for name, path in BUNDLED_KAPE_TARGETS.items():
        assert path.is_relative_to(PROJECT_ROOT) and path.is_file()
        assert importlib.resources.files("fmb").joinpath(
            "collection/tools/kape/assets/targets/" + name + ".tkape"
        ).read_bytes() == path.read_bytes()


def test_resolution_only_reads_the_packaged_declaration_and_returns_fresh_values(monkeypatch):
    reads = []
    original = profiles.read_json

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(profiles, "read_json", read)
    first = profiles.resolve_paper_profile()
    first["questions"][0]["components"][0]["required_artifact_families"].clear()
    first["collection_declaration"]["collection"]["kape"]["target_names"].clear()
    first["parser_outputs"]["ntfs_mft"].clear()
    second = profiles.resolve_paper_profile()
    assert reads == [PROJECT_ROOT / "contracts/paper/collection.json"] * 2
    assert second["questions"][0]["components"][0]["required_artifact_families"] == ["ntfs.mft", "ntfs.usn"]
    assert second["collection_declaration"]["collection"]["kape"]["target_names"][0] == "$MFT"
    assert second["parser_outputs"]["ntfs_mft"] == ["ntfs.mft"]


@pytest.mark.parametrize("change", ["missing", "duplicate", "unknown"])
def test_incomplete_or_ambiguous_component_mapping_is_rejected(monkeypatch, change):
    from copy import deepcopy

    from fmb import question_packs

    packs = question_packs.load_packs()
    if change == "missing":
        changed = packs[:-1]
    else:
        changed = deepcopy(packs)
        extra = deepcopy(changed[0]["components"][0])
        if change == "unknown":
            extra["technique_id"] = "unknown"
        changed[0]["components"].append(extra)
    monkeypatch.setattr(question_packs, "load_packs", lambda questions=None: changed)
    with pytest.raises(ValueError, match="component"):
        profiles.resolve_paper_profile()


