from pathlib import Path, PurePosixPath
import uuid

import pytest

from fmb.core import paper_contract
from fmb.core.collection_paths import CollectionPaths
from fmb.core.hashing import sha256_file
from fmb.core.paper_artifacts import condition_build, preparation_folder
from fmb.core.sealed_records import write_json
from fmb.index.adapters.volume_binding import load_drive_binding
from fmb.preparation.native import image_binding

ORIGINAL = PurePosixPath("/nonexistent/original/collection/analysis")


def _collection(root: Path, recorded_root: Path) -> tuple[Path, dict]:
    analysis = root / "analysis"
    for relative in ("execution/02/out.json", "factual-supplement/norm.json"):
        (analysis / relative).parent.mkdir(parents=True, exist_ok=True)
        (analysis / relative).write_text("{}")
    index = {"parser_runs": [
        {"raw_outputs": [{"path": str(recorded_root / "execution/02/out.json")}],
         "normalized_output": {"path": str(recorded_root / "factual-supplement/norm.json")}}]}
    return analysis, index


def test_an_unmoved_collection_reads_its_recorded_paths(tmp_path):
    analysis, index = _collection(tmp_path, tmp_path.resolve() / "analysis")
    locate = CollectionPaths(analysis, index)
    assert not locate.relocated
    assert locate(index["parser_runs"][0]["raw_outputs"][0]["path"]) == analysis.resolve() / "execution/02/out.json"


def test_a_moved_collection_reads_its_files_where_it_is_now(tmp_path):
    analysis, index = _collection(tmp_path, ORIGINAL)
    locate = CollectionPaths(analysis, index)
    assert locate.relocated and locate.original == ORIGINAL
    assert locate(ORIGINAL / "factual-supplement/norm.json") == analysis.resolve() / "factual-supplement/norm.json"
    with pytest.raises(ValueError, match="outside the collection"):
        locate("/nonexistent/other/analysis/execution/02/out.json")


def test_a_moved_collection_finds_its_collector_output_after_the_original_folder_is_gone(tmp_path):
    from fmb.preparation.native import collected_kape_root

    kape = Path("execution/01-collection/bundle-extracted/kape-output")
    journal = tmp_path / "analysis" / kape / "targets/C/$Extend/$J"
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"")
    index = {"parser_runs": [{"parser_kind": "ntfs_usn", "raw_outputs": [{"path": str(ORIGINAL / kape / "targets/C/$Extend/$J")}]}]}
    assert collected_kape_root(tmp_path / "analysis", index) == (tmp_path / "analysis").resolve() / kape


def test_a_collection_recorded_under_two_spellings_of_its_folder_is_one_collection(tmp_path):
    analysis, index = _collection(tmp_path, tmp_path.resolve() / "analysis")
    detour = tmp_path.resolve() / "elsewhere" / ".." / "analysis"
    index["parser_runs"][0]["normalized_output"]["path"] = str(detour / "factual-supplement/norm.json")
    locate = CollectionPaths(analysis, index)
    assert not locate.relocated
    assert locate(detour / "factual-supplement/norm.json") == analysis.resolve() / "factual-supplement/norm.json"
    with pytest.raises(ValueError, match="outside the collection"):
        locate(tmp_path.resolve() / "analysis" / ".." / "other" / "file.json")


def test_a_card_drops_a_collector_folder_spelled_with_dots_but_not_an_ambiguous_target_path():
    from fmb.analysis.evidence_projection import _collected_artifact_path, blinding_violations

    target = "kape-output/targets/C/Windows/System32/config/SYSTEM"
    assert _collected_artifact_path("/work/a/../runs/x/analysis/extracted/" + target) == "targets/C/Windows/System32/config/SYSTEM"
    assert _collected_artifact_path("/work/runs/x/analysis/extracted/" + target) == "targets/C/Windows/System32/config/SYSTEM"
    ambiguous = "/Users/u/work/runs/x/analysis/extracted/kape-output/targets/C/Windows/../SYSTEM"
    assert _collected_artifact_path(ambiguous) == ambiguous and blinding_violations(ambiguous)


def test_generation_files_a_collection_records_are_read_in_the_generation_given_now(tmp_path):
    analysis, index = _collection(tmp_path, ORIGINAL)
    collected_from = PurePosixPath("/nonexistent/original/generation")
    write_json(analysis / "factual-collection.json", {"evidence": str(collected_from / "full_scale.vmdk")})
    index["parser_runs"].append({"raw_outputs": [{"path": str(collected_from / "media_0123456789ab.vmdk")}]})
    generation = tmp_path / "generation"
    generation.mkdir()
    locate = CollectionPaths(analysis, index, generation=generation)
    assert locate.original == ORIGINAL
    assert locate(collected_from / "media_0123456789ab.vmdk") == generation.resolve() / "media_0123456789ab.vmdk"
    with pytest.raises(ValueError, match="no generation folder is given"):
        CollectionPaths(analysis, index)(collected_from / "media_0123456789ab.vmdk")


def test_a_collection_missing_a_recorded_output_is_refused(tmp_path):
    analysis, index = _collection(tmp_path, ORIGINAL)
    (analysis / "factual-supplement/norm.json").unlink()
    with pytest.raises(ValueError, match="do not share one root|not in the folder given"):
        CollectionPaths(analysis, index)


def test_the_drive_binding_checks_its_sources_where_the_collection_is_now(tmp_path):
    analysis, index = _collection(tmp_path, ORIGINAL)
    locate = CollectionPaths(analysis, index)
    system = analysis / "execution/02/out.json"
    native = analysis / "factual-supplement/norm.json"
    entry = bytes(16) + uuid.uuid4().bytes_le + bytes(96)
    proof = {"gpt_partition_entry_hex": entry.hex(), "gpt_partition_id": str(uuid.UUID(bytes_le=entry[16:32])),
             "mounted_device_values": [{"name": "\\DosDevices\\C:", "bytes_hex": (b"DMIO:ID:" + entry[16:32]).hex()}]}
    binding = tmp_path / "binding.json"
    write_json(binding, {"schema_version": "native_drive_letter_binding.v1", "proof": proof,
                         "system_path": str(ORIGINAL / "execution/02/out.json"), "system_sha256": sha256_file(system),
                         "native_manifest_path": str(ORIGINAL / "factual-supplement/norm.json"),
                         "native_manifest_sha256": sha256_file(native)})
    with pytest.raises(FileNotFoundError):
        load_drive_binding(binding)
    assert load_drive_binding(binding, locate=locate) == proof


def _image_case(tmp_path: Path, *, recorded: str | None = None, population: bytes = b'{"members": []}'):
    generation = tmp_path / "generation"
    generation.mkdir(parents=True)
    (generation / "full_scale.vmdk").write_bytes(b"image")
    (generation / "factual-challenge-population.json").write_bytes(b'{"members": []}')
    image = sha256_file(generation / "full_scale.vmdk")
    write_json(generation / "manifest.json", {"artifacts": [{"file": "full_scale.vmdk", "sha256": image}]})
    analysis = tmp_path / "analysis"
    (analysis / "factual-supplement").mkdir(parents=True)
    write_json(analysis / "factual-collection.json", {"evidence": "/moved/away/full_scale.vmdk",
                                                      "evidence_index_sha256": "7" * 64})
    scope = (tmp_path / "scope.json")
    scope.write_bytes(population)
    write_json(analysis / "factual-supplement" / "native-surface-preparation.json",
               {"evidence_sha256": recorded or image})
    write_json(analysis / "factual-supplement" / "public-population-binding.json",
               {"evidence_sha256": recorded or image, "public_manifest_sha256": sha256_file(scope)})
    return analysis, generation, image


def test_a_collection_is_bound_to_the_image_by_hash_wherever_it_was_made(tmp_path):
    analysis, generation, image = _image_case(tmp_path)
    binding = image_binding(analysis=analysis, generation=generation)
    assert binding["image_sha256"] == image and binding["evidence_index_sha256"] == "7" * 64
    assert binding["scope_record_sha256"] == sha256_file(generation / "factual-challenge-population.json")


def test_a_collection_of_another_image_or_population_is_refused(tmp_path):
    analysis, generation, _ = _image_case(tmp_path / "a", recorded="8" * 64)
    with pytest.raises(ValueError, match="another image"):
        image_binding(analysis=analysis, generation=generation)
    analysis, generation, _ = _image_case(tmp_path / "b", population=b'{"members": ["other"]}')
    with pytest.raises(ValueError, match="another declared population"):
        image_binding(analysis=analysis, generation=generation)


def test_a_build_names_its_stream_head_file_relative_to_itself(tmp_path):
    (tmp_path / "stream-heads.json").write_text("{}")
    bound = paper_contract.bind_options({"stream_heads_path": "stream-heads.json"}, tmp_path)
    assert bound["stream_heads_path"] == str(tmp_path.resolve() / "stream-heads.json")
    legacy = {"stream_heads_path": str(tmp_path / "stream-heads.json")}
    assert paper_contract.bind_options(legacy, None) == legacy
    lab = {"stream_heads_path": ".fmb/lab/pilot/e2e-i1-01/stream-heads.json"}
    assert paper_contract.bind_options(lab, None) == lab
    with pytest.raises(ValueError):
        paper_contract.bind_options({"stream_heads_path": "../stream-heads.json"}, tmp_path)


def test_records_name_their_neighbours_relative_to_themselves_or_absolutely(tmp_path):
    built = tmp_path / "run" / "preparation" / "cards"
    condition = tmp_path / "run" / "conditions" / "luna-high"
    for folder in (built, condition, tmp_path / "run" / "preparation" / "prepared"):
        folder.mkdir(parents=True)
    assert preparation_folder(built, {"production_preparation": "../prepared"}) == (built.parent / "prepared").resolve()
    assert condition_build(condition, {"built": "../../preparation/cards"}) == built.resolve()
    assert condition_build(condition, {"built": str(built)}) == built.resolve()
