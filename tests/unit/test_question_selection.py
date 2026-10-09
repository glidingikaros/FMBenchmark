import pytest
from copy import deepcopy
from pathlib import Path

from fmb.analysis.inputs import canonical_sha256
from fmb.analysis.population_binding import bind_population_manifest
from fmb.collection.tools.host.definitions import KapeDefinitions
from fmb.collection.tools.host.toolchain import HostToolchain, tree_sha256
from fmb.core.case_contract import QIDS, prepare_case
from fmb.core.errors import SchemaValidationError
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import read_json, seal_directory, write_json
from fmb.profiles import collection_profile, resolve_paper_profile, resolve_profile, validate_profile


@pytest.mark.parametrize("qid", QIDS)
def test_each_question_resolves_an_executable_subset(qid):
    g2 = resolve_profile([qid])
    validate_profile(g2, [qid])
    assert collection_profile(g2) == resolve_paper_profile([qid])
    selection = g2["collection"]
    from fmb.collection.tools.kape.paths import BUNDLED_KAPE_TARGETS

    definitions = KapeDefinitions(bundled_targets=BUNDLED_KAPE_TARGETS)
    assert definitions.target_rules(selection["targets"])
    processors = definitions.module_processors(selection["modules"])
    assert processors
    modules = {p.module_name for p in processors}
    if "ntfs.mft" in g2["artifact_families"]:
        assert "MFTECmd_$MFT" in modules
        assert not {"MFTECmd_$Boot", "MFTECmd_$SDS"} & modules
    else:
        assert "$MFT" not in selection["targets"]
    assert ("PECmd" in modules) == (qid == "BQ-EXEC-01")
    assert ("SBECmd" in modules) == (qid == "BQ-SHELLBAG-01")
    if qid == "BQ-LOG-01":
        assert selection["targets"] == ["EventLogs"]
        assert selection["modules"] == ["EvtxECmd"]
        assert list(g2["parser_outputs"]) == ["windows_evtx_security"]
    if qid == "BQ-USB-01":
        assert "LECmd" in modules and "windows_jump_list" in g2["parser_outputs"]
    if qid == "BQ-DIRECTORY-01":
        assert "RegistryHives" in selection["targets"]


def test_full_selection_keeps_preset_order_and_duplicate_questions_are_rejected():
    assert resolve_profile(list(reversed(QIDS))) == resolve_profile()
    with pytest.raises(ValueError, match="repeated"):
        resolve_profile(["BQ-LOG-01", "BQ-LOG-01"])


def _toolchain(root):
    entry = root / "EvtxECmd/EvtxECmd.dll"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(b"verified parser")
    maps = entry.parent / "Maps"
    maps.mkdir()
    (maps / "one.map").write_text("verified event map")
    lock = {"schema_version": "fmb_host_toolchain_lock.v1", "tools": [
        {"tool": "EvtxECmd", "executable": r"EvtxECmd\EvtxECmd.exe", "directory": "EvtxECmd",
         "entry_assembly": entry.name, "entry_assembly_sha256": sha256_file(entry)},
        {"tool": "RECmd", "executable": r"RECmd\RECmd.exe", "directory": "RECmd",
         "entry_assembly": "RECmd.dll", "entry_assembly_sha256": "1" * 64}],
        "registry_plugins": {"directory": "RECmd/Plugins", "tree_sha256": "2" * 64},
        "assets": {"EvtxECmd/Maps": {"tree_sha256": tree_sha256(maps)[0], "file_count": 1}}}
    return HostToolchain(root, lock)


def test_toolchain_selection_verifies_needed_assets_and_ignores_absent_unrelated_tools(tmp_path):
    toolchain = _toolchain(tmp_path)
    selected = {r"EvtxECmd\EvtxECmd.exe"}
    assert not toolchain.unverified(executables=selected)
    assert toolchain.unverified()
    (tmp_path / "EvtxECmd/Maps/one.map").write_text("tampered map")
    assert toolchain.unverified(executables=selected)[0]["status"] == "hash_mismatch"


def test_log_preflight_does_not_probe_windows_or_registry_dependencies(tmp_path, monkeypatch):
    from fmb.collection.paper_host import collection_args
    from fmb.collection.tools.host import backend

    toolchain = _toolchain(tmp_path)
    monkeypatch.setattr(backend.HostToolchain, "load", lambda **_: toolchain)
    monkeypatch.setattr(toolchain, "verify_runtime", lambda *_, **__: {"status": "verified"})
    find_spec = backend.importlib.util.find_spec

    def lookup(name):
        assert name != "Registry"
        return find_spec(name)

    def which(name):
        assert name == "dotnet"
        return "/unused/dotnet"

    monkeypatch.setattr(backend.importlib.util, "find_spec", lookup)
    args = collection_args(profile=resolve_paper_profile(["BQ-LOG-01"]), evidence=None, windows_parsers=None)
    assert backend.preflight_host_collector_backend(args, which=which)["available"]


def _log_population():
    from test_population_binding import _build_public_manifest, _full_scale_index

    public = _build_public_manifest(experiment="full_scale", seed=20260826)
    index = _full_scale_index(public)
    index["parser_runs"] = [r for r in index["parser_runs"] if r["parser_kind"] == "windows_evtx_security"]
    techniques = {"security_log_clear_event", "event_record_sequence_gap"}
    return public, index, techniques


def test_selected_population_preserves_whole_manifest_and_complete_negative_rosters():
    public, index, techniques = _log_population()
    bound = bind_population_manifest(index, public, techniques=techniques)
    assert bound["population_manifest"] == public
    assert {p["technique_id"] for p in bound["candidate_populations"]} == techniques
    for population in bound["candidate_populations"]:
        scenario = next(s for s in public["scenarios"].values() if s["technique_id"] == population["technique_id"])
        assert len(population["subjects"]) == len(scenario["members"])
        assert population["coverage_status"] == "complete"
    with pytest.raises(ValueError, match="absent"):
        bind_population_manifest(index, public, techniques={"undeclared"})


@pytest.mark.parametrize("damage", ["count", "hint", "duplicate"])
def test_unselected_population_is_validated_before_selection(damage):
    public, index, techniques = _log_population()
    scenario = public["scenarios"]["timestomp_01"]
    if damage == "count":
        scenario["declared_count"] += 1
    elif damage == "hint":
        scenario["members"][0]["identity_hint"] = {"undeclared": "value"}
    else:
        scenario["members"][1]["candidate_id"] = scenario["members"][0]["candidate_id"]
    public["manifest_sha256"] = canonical_sha256({k: v for k, v in public.items() if k != "manifest_sha256"})
    with pytest.raises(ValueError):
        bind_population_manifest(index, public, techniques=techniques)


def _reference_table():
    scenarios = {"security": {"technique_id": "security_log_clear_event", "candidate_ids": ["s0", "s1"]},
                 "gap": {"technique_id": "event_record_sequence_gap", "candidate_ids": ["g0", "g1"]},
                 "omitted": {"technique_id": "timestamp_manipulation", "candidate_ids": ["t0"]}}
    table = {"native_volume_serial_number": None,
             "population": {"manifest_sha256": "1" * 64, "experiment": "full_scale", "scenarios": scenarios},
             "candidate_subjects": {"security": {"s0": "a", "s1": "b"}, "gap": {"g0": "a", "g1": "b"}},
             "base_rosters": {"BQ-LOG-01": ["a", "b"]},
             "questions": [{"question_id": "BQ-LOG-01", "evidence_bundle_sha256": "2" * 64,
                            "cards": [{"subject_id": sid, "components": ["security_log_clear_event",
                                                                          "event_record_sequence_gap"]}
                                      for sid in ("a", "b")]}]}
    reference = {"schema_version": "generation_finding_reference.v1", "reference_contract": "broad_native_findings.v1",
                 "experiment": "full_scale", "case": "positive", "population_manifest_sha256": "1" * 64,
                 "operation_truth_payload_sha256": "2" * 64, "archive_receipt_payload_sha256": "3" * 64,
                 "scenarios": [{"scenario_id": k, "candidate_ids": ["s0"] if k == "security" else []}
                               for k in scenarios]}
    return table, reference


@pytest.mark.parametrize("damage", [None, "missing", "unknown", "duplicate"])
def test_reference_checks_omitted_questions_without_scoring_them(monkeypatch, damage):
    from fmb.evaluation.factual_reference import bind_from_table
    from fmb.generation import factual_challenge

    monkeypatch.setattr(factual_challenge, "validate_receipt", lambda *_: None)
    table, reference = _reference_table()
    if damage == "missing":
        reference["scenarios"].pop()
    elif damage == "unknown":
        reference["scenarios"][-1]["candidate_ids"] = ["unknown"]
    elif damage == "duplicate":
        reference["scenarios"][-1]["candidate_ids"] = ["t0", "t0"]
    if damage:
        with pytest.raises((ValueError, SchemaValidationError)):
            bind_from_table(table=table, base_reference=reference, plan={}, receipt={"members": []})
    else:
        bound = bind_from_table(table=table, base_reference=reference, plan={}, receipt={"members": []})
        assert set(bound) == {"BQ-LOG-01"}
        assert bound["BQ-LOG-01"]["assessments"]["b"]["security_log_clear_event"]["status"] == "not_supported"
        table["questions"].append({"question_id": "BQ-TIME-01", "cards": []})
        with pytest.raises(ValueError, match="native boot serial"):
            bind_from_table(table=table, base_reference=reference, plan={}, receipt={"members": []})


def test_selected_log_presentation_never_opens_mft_or_native_streams(tmp_path, monkeypatch):
    from fmb.paper import presentation
    from paper_fixtures import log_bundle

    prepared = tmp_path / "prepared"
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    (tmp_path / "generation").mkdir()
    write_json(prepared / "manifest.json", {"analysis": str(analysis), "generation": str(tmp_path / "generation"),
                                           "truth_sources_used": [], "oracle_lock_sha256": "test"})
    write_json(prepared / "cases/BQ-LOG-01.json", prepare_case(log_bundle([100, 103], event_ids=[4624, 4624])))
    seal_directory(prepared)
    monkeypatch.setattr(presentation.integrity, "source_manifest_sha256", lambda: "test")
    monkeypatch.setattr(presentation, "OPTIONS_TEMPLATE", {"views": ["stream_bytes_only"]})

    def forbidden(*_, **__):
        pytest.fail("unselected native preparation was opened")

    for name in ("collection_sources", "scan_listing", "stream_heads", "volume_ids"):
        monkeypatch.setattr(presentation, name, forbidden)
    presentation.build(prepared=prepared, analysis=analysis, image="I1-01", output=tmp_path / "cards",
                       questions=["BQ-LOG-01"])
    assert not (tmp_path / "cards/stream-heads.json").exists()
    assert not (tmp_path / "cards/mft-scan.json").exists()


@pytest.mark.parametrize("version,expected", [("v1", "independent admission"), ("v2", "distinct frozen")])
def test_admission_scope_is_versioned_even_with_a_stray_v1_selection(tmp_path, version, expected):
    from fmb.evaluation.admission import admit_conditions
    from paper_fixtures import log_bundle
    from test_s3_stage import _new_format_build, _references

    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    prepared, built = _new_format_build(tmp_path, case, deterministic=True)
    manifest = read_json(prepared / "manifest.json")
    manifest.update(schema_version="paper_native_preparation." + version, selected_questions=["BQ-LOG-01"])
    write_json(prepared / "manifest.json", manifest)
    (prepared / "preparation-seal.json").unlink()
    seal_directory(prepared)
    report = read_json(built / "build-report.json")
    report["production_seal_sha256"] = sha256_file(prepared / "preparation-seal.json")
    write_json(built / "build-report.json", report)
    seal = read_json(built / "build-seal.json")
    seal["files"]["build-report.json"] = sha256_file(built / "build-report.json")
    write_json(built / "build-seal.json", seal)
    references = _references(case)
    write_json(prepared / "admission/references.json", references)
    seal_directory(prepared / "admission", "truth-seal.json")
    with pytest.raises(ValueError, match=expected):
        admit_conditions(prepared=prepared, built=built, condition_runs=[], references=references)


def test_s2_receipts_are_exactly_scoped():
    from fmb.pipeline.reads import undeclared

    allowed = ["analysis-timing.json", ".analysis-timing.json.123.tmp", "analysis-truth-guard.json"]
    assert not undeclared("S2", {"run": allowed})
    rejected = [".analysis-timing.json/nested.tmp", ".analysis-timing.json.other", "other-timing.json"]
    assert undeclared("S2", {"run": rejected}) == ["run:" + name for name in rejected]
    assert undeclared("S3", {"run": allowed}) == ["run:" + name for name in allowed]
    assert undeclared("check:sources", {"run": allowed}) == ["run:" + name for name in allowed[:2]]
    assert undeclared("check:sources", {"run": [".analysis-truth-guard.json.123.tmp"]})


@pytest.mark.parametrize("qid", ["BQ-LOG-01", "BQ-TIME-01", "BQ-FILE-01"])
def test_noncontent_collection_does_not_require_a_bmp_population_limit(tmp_path, monkeypatch, qid):
    from types import SimpleNamespace
    from fmb.analysis import population_binding
    from fmb.collection import alignment, analysis, factual_challenge, paper_host

    evidence = tmp_path / "full_scale.vmdk"
    evidence.write_bytes(b"image")
    generated = SimpleNamespace(content_subject_limit=None, i30_directory_paths=(),
                                evidence_sha256=sha256_file(evidence), population_manifest={"scenarios": {}})
    monkeypatch.setattr(population_binding, "load_generated_population_bundle", lambda *_, **__: generated)
    monkeypatch.setattr(factual_challenge, "load_public_population", lambda _: None)
    calls = []

    def collect(**kwargs):
        calls.append(kwargs)
        assert kwargs["bounded_content_subject_limit"] is None
        assert kwargs["bounded_i30_directory_paths"] == ()
        return {"collected": True}

    monkeypatch.setattr(paper_host, "collect_host", collect)
    for module, name in [(alignment, "add_native_population_surfaces"),
                         (population_binding, "bind_population_manifest"),
                         (analysis, "add_reference_scoped_usn"), (analysis, "add_reference_scoped_ads")]:
        monkeypatch.setattr(module, name, lambda index, *_, **__: index)
    kwargs = dict(profile=resolve_paper_profile([qid]), output_dir=tmp_path / "analysis", run_id="selection",
                  windows_parsers=None)
    if qid == "BQ-FILE-01":
        with pytest.raises(ValueError, match="content"):
            analysis.collect_evidence_index(evidence, **kwargs)
        assert not calls
    else:
        assert analysis.collect_evidence_index(evidence, **kwargs) == {"collected": True}
        assert len(calls) == 1


def test_usb_selection_does_not_collect_system_mft_or_other_native_populations(tmp_path, monkeypatch):
    from fmb.collection import alignment

    wanted = []

    def system(*_, **__):
        pytest.fail("USB-only selection read the system MFT")

    def usb(**kwargs):
        wanted.append(kwargs)
        return tmp_path / "usb.json"

    monkeypatch.setattr(alignment, "collect_ntfs_surfaces", system)
    monkeypatch.setattr(alignment, "collect_usb_volumes", usb)
    monkeypatch.setattr(alignment, "usb_volume_source_manifests", lambda p: [p])
    monkeypatch.setattr(alignment, "usb_volume_parser_run", lambda **_: {"parser_kind": "native_usb_volume"})
    index = {"collector_runs": [{"output_root": str(tmp_path / "kape-output")}], "parser_runs": []}
    manifest = {"scenarios": {
        "usb": {"technique_id": "usb_volume_activity_gap", "members": [{"identity_hint": {"binding_file": "media.json"}}]},
        "ads": {"technique_id": "alternate_data_stream", "members": [{"subject_ref": "unselected", "identity_hint": {}}]}}}
    actual = alignment.add_native_population_surfaces(index, manifest=manifest, evidence_image=tmp_path / "full_scale.vmdk",
        evidence_sha256="1" * 64, output_dir=tmp_path / "analysis", techniques={"usb_volume_activity_gap"}, system_volume=False)
    assert wanted[0]["binding_files"] == ["media.json"]
    assert actual["parser_runs"] == [{"parser_kind": "native_usb_volume"}]
    assert not (tmp_path / "analysis/native-surface-preparation.json").exists()


@pytest.mark.parametrize("qid,required", [("BQ-LOG-01", False), ("BQ-TIME-01", True)])
def test_logfile_prerequisite_follows_the_selected_family(tmp_path, monkeypatch, qid, required):
    from fmb.collection.paper_host import collection_args
    from fmb.collection.tools.host import backend
    from fmb.index.scanners import logfile_runtime

    toolchain = _toolchain(tmp_path)
    monkeypatch.setattr(backend.HostToolchain, "load", lambda **_: toolchain)
    monkeypatch.setattr(toolchain, "verify_runtime", lambda *_, **__: {"status": "verified"})
    called = []

    def unavailable():
        called.append(True)
        return {"available": False, "reason": "fixture missing driver"}

    monkeypatch.setattr(logfile_runtime, "logfile_runtime_availability", unavailable)
    args = collection_args(profile=resolve_paper_profile([qid]), evidence=None, windows_parsers=None)
    report = backend.preflight_host_collector_backend(args, which=lambda _: "/unused/dotnet")
    assert bool(called) is required
    assert ("dfir_ntfs_verified" in report["missing"]) is required


@pytest.mark.parametrize("damage", ["bytes", "missing", "conflicting-record"])
def test_selected_parser_source_verification_rejects_missing_or_changed_evidence(tmp_path, damage):
    from fmb.preparation.native import _verified_parser_outputs

    path = tmp_path / "events.csv"
    path.write_text("EventID\n1102\n")
    row = {"path": str(path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}
    index = {"parser_runs": [{"raw_outputs": [row]}, {"normalized_output": deepcopy(row)}]}
    assert _verified_parser_outputs(index, Path) == {path}
    if damage == "bytes":
        path.write_text("EventID\n4624\n")
    elif damage == "missing":
        path.unlink()
    else:
        index["parser_runs"][1]["normalized_output"]["sha256"] = "0" * 64
    with pytest.raises((ValueError, FileNotFoundError)):
        _verified_parser_outputs(index, Path)
