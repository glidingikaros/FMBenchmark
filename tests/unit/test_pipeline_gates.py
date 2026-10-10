import json
from pathlib import Path

import pytest

from fmb.core import paper_integrity as integrity
from fmb.core.errors import SchemaValidationError
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.core.truth_guard import public_generation_files
from fmb.paper import workflow
from fmb.pipeline import evaluation, stages
from fmb.pipeline.gates import read_gate, verify_run, write_gate
from fmb.pipeline.runner import run_pipeline
from fmb.profiles import resolve_paper_profile
from fmb.question_packs import load_families

MEDIA = "0123456789ab"


def _generation(root: Path) -> Path:
    root.mkdir()
    (root / "full_scale.vmdk").write_bytes(b"system image")
    (root / f"media_{MEDIA}.vmdk").write_bytes(b"companion image")
    write_json(root / f"media_{MEDIA}.json", {"device_instance_id": "USBSTOR\\Disk\\X&0"})
    write_json(root / "population_manifest.json", {"members": []})
    write_json(root / "factual-challenge-population.json", {"members": []})
    for private in ("ground_truth.json", "finding_reference.json", "recipe.json"):
        write_json(root / private, {"private": True})
    artifacts = [
        {"file": name, "sha256": sha256_file(root / name)}
        for name in ("full_scale.vmdk", f"media_{MEDIA}.vmdk", f"media_{MEDIA}.json", "population_manifest.json")
    ]
    write_json(root / "manifest.json", {"artifacts": artifacts})
    return root


def test_gate_documents_are_validated_hashed_and_tamper_evident(tmp_path):
    payload = {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": "I1-01",
               "admission": {"status": "passed", "certificates": []}, "scores": {}}
    entry = write_gate(tmp_path, "G5", payload)
    assert entry["sha256"] == sha256_file(tmp_path / entry["path"])
    assert read_gate(tmp_path, entry) == payload
    (tmp_path / entry["path"]).write_text(canonical_json({**payload, "scores": {"x": {}}}) + "\n")
    with pytest.raises(ValueError, match="changed after it was written"):
        read_gate(tmp_path, entry)
    with pytest.raises(FileExistsError):
        write_gate(tmp_path, "G5", payload)


def test_write_gate_refuses_a_mislabelled_or_invalid_document(tmp_path):
    with pytest.raises(ValueError, match="declares gate"):
        write_gate(tmp_path, "G4", {"gate": "G5"})
    with pytest.raises(SchemaValidationError):
        write_gate(tmp_path, "G5", {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1"})


def test_g1_declares_exactly_the_files_the_truth_guard_allows(tmp_path):
    generation = _generation(tmp_path / "generation")
    g1 = stages.evidence_gate(generation, "I1-01")
    allowed = sorted(str(p) for p in public_generation_files(generation) if p.exists())
    assert g1["readable_paths"] == allowed
    assert not any(Path(p).name in {"ground_truth.json", "finding_reference.json", "recipe.json"}
                   for p in g1["readable_paths"])
    assert g1["system_image"]["sha256_source"] == "generation_manifest"
    assert g1["companion_media"][0]["media_id"] == MEDIA
    assert [Path(r["path"]).name for r in g1["scope_records"]] == [
        "population_manifest.json", "factual-challenge-population.json"]
    write_gate(tmp_path / "run", "G1", g1)


def test_g1_refuses_an_acquisition_record_that_differs_from_the_manifest(tmp_path):
    generation = _generation(tmp_path / "generation")
    write_json(generation / f"media_{MEDIA}.json", {"device_instance_id": "edited"})
    with pytest.raises(ValueError, match="acquisition record differs"):
        stages.evidence_gate(generation, "I1-01")


def test_a_stage_may_read_only_what_g1_declares(tmp_path):
    g1 = stages.evidence_gate(_generation(tmp_path / "generation"), "I1-01")
    stages.check_reads(g1["readable_paths"][:2], g1, stage="S2")
    with pytest.raises(ValueError, match="does not declare"):
        stages.check_reads([str(tmp_path / "generation" / "ground_truth.json")], g1, stage="S2")


def test_g2_carries_the_nine_question_paper_profile(tmp_path):
    profile = resolve_paper_profile()
    g2 = stages.profile_gate(profile)
    assert len(g2["questions"]) == 9
    assert g2["collection"]["targets"] == profile["collection_declaration"]["collection"]["kape"]["target_names"]
    write_gate(tmp_path, "G2", g2)


def _fake_stages(monkeypatch, generation: Path, *, undeclared_read: Path | None = None, admission: str = "passed",
                 answer: list | None = None, image_sha256: str | None = None):

    def prepare(*, analysis, generation, image, output, question_scope="hidden", presentation_check=True,
                g2=None):
        assert presentation_check is False
        assert g2["gate"] == "G2"
        built, prepared = output / "cards", output / "prepared"
        built.mkdir(parents=True)
        prepared.mkdir()
        write_json(prepared / "manifest.json", {
            "collection_binding": {"image": "full_scale.vmdk",
                                   "image_sha256": image_sha256 or sha256_file(generation / "full_scale.vmdk"),
                                   "image_hash_records": ["factual-supplement/native-surface-preparation.json"],
                                   "evidence_index_sha256": "5" * 64},
            "collection_original_root": str(analysis)})
        seal_directory(prepared)
        write_json(built / "items.json", [{"case_id": "r1", "question_id": "BQ-TIME-01"}])
        opened = [str(generation / "manifest.json")] + ([str(undeclared_read)] if undeclared_read else [])
        write_json(built / "build-report.json", {
            "level": "L0N", "options_sha256": "0" * 64, "requests_per_pass": 1, "findings": 1,
            "truth_sources_used": [], "generation_files_opened": opened,
            "questions": {"BQ-TIME-01": {"cards": 1, "findings": 1}}})
        (built / "sent").mkdir()
        write_json(built / "sent" / "r1.json", {"card": "r1"})
        write_json(built / "view-options.json", {"stream_heads_path": None, "views": ["no_scope"]})
        seal_directory(built, "build-seal.json")
        seal = read_json(built / "build-seal.json")
        seal["requests"] = {"r1": {
            "case_sha256": "1" * 64, "sent_sha256": sha256_file(built / "sent" / "r1.json"), "sent_bytes": 10,
            "findings": 1}}
        write_json(built / "build-seal.json", seal)
        return {"status": "built"}

    def assess_rules(*, built, output, engine_name, question_definitions, generation=None):
        assert engine_name == "rules" and "BQ-TIME-01" in question_definitions and generation is not None
        result = {"supported_findings": answer if answer is not None else ["finding:a"], "insufficient_findings": []}
        write_json(output / "deterministic" / "r1.json", result)
        write_json(output / "assessment.json", {"engine": {"id": "rules", "module": "fmb.assessment.rules"}})
        seal_directory(output, "assessment-seal.json")
        return {"status": "assessed"}

    def check_presentation(*, prepared, built, engine_name):
        return {"status": "passed", "engine": engine_name}

    def freeze_condition(*, built, condition, output, generation=None, passes=None):
        assert generation is not None
        output.mkdir(parents=True)
        write_json(output / "protocol.json", {"condition_id": condition, "settings": {"model": "m"}})
        write_json(output / "manifest.json", {"rows": [
            {"request_id": "r1", "question_id": "BQ-TIME-01", "request_sha256": "3" * 64}]})
        seal_directory(output)
        return {"status": "frozen"}

    def admit_native(prepared, *, built, condition_runs, rules, binding=None, verify_sources=True):
        assert (rules / "assessment.json").is_file()
        assert verify_sources is False
        for run in condition_runs:
            write_json(run / "admission" / "references.json", {})
            write_json(run / "admission" / "admission.json", {
                "status": admission, "preparation_seal_sha256": sha256_file(run / "preparation-seal.json"),
                "references_sha256": sha256_file(run / "admission" / "references.json")})
            seal_directory(run / "admission", "admission-seal.json")
        return {"status": admission}

    def rules_gate(rules, built, g3, g3_sha256, roots=None):
        answer = read_json(Path(rules) / "deterministic" / "r1.json")
        return {"gate": "G4", "schema_version": "fmb.pipeline.g4.v1", "case_label": g3["case_label"],
                "assessor": {"kind": "rules", "id": "rules", "view": "decoded"}, "status": "complete",
                "g3_sha256": g3_sha256, "results": [{"request_id": "r1", "question_id": "BQ-TIME-01", "pass": None,
                                                     "state": "completed", **answer}]}

    monkeypatch.setattr(stages, "rules_gate", rules_gate)
    monkeypatch.setattr(stages, "check_assessment", lambda g4, g3, roots:
                        roots["run"] / ("assessment/rules" if g4["assessor"]["kind"] == "rules"
                                        else "conditions/" + g4["assessor"]["id"]))
    monkeypatch.setattr(stages, "view_differences", lambda built: {
        "sent": {"read_by": ["S3'"], "description": "sent"},
        "decoded": {"read_by": ["S3"], "description": "decoded", "differences_from_sent": {}}})
    monkeypatch.setattr(evaluation, "findings_table", lambda built, g3, runs, rules=None: [])
    monkeypatch.setattr(evaluation, "comparison", lambda rows: {"rules": {}, "conditions": {}})
    monkeypatch.setattr(workflow, "prepare", prepare)
    monkeypatch.setattr(workflow, "assess_rules", assess_rules)
    from fmb.paper import presentation_check

    monkeypatch.setattr(presentation_check, "check_presentation", check_presentation)
    monkeypatch.setattr(workflow, "freeze_condition", freeze_condition)
    monkeypatch.setattr(workflow, "admit_native", admit_native)
    monkeypatch.setattr(workflow, "check_preparation_sources", lambda prepared: {"status": "passed", "source_files": 0})
    monkeypatch.setattr(integrity, "source_manifest_sha256", lambda: "4" * 64)


def _analysis(tmp_path: Path, generation: Path, *, missing_family: str | None = None,
              collected_from: Path | None = None) -> Path:
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    source = collected_from or generation.resolve()
    write_json(tmp_path / "analysis-truth-guard.json", {
        "status": "completed", "evidence": str(source / "full_scale.vmdk"),
        "generation_files_opened": [str(source / "population_manifest.json")]})
    families = {f for q in resolve_paper_profile()["questions"] for f in q["artifact_families"]} - {missing_family}
    registry = load_families()
    write_json(analysis / "evidence_index.json", {"parser_runs": [
        *({"parser": registry[f]["parsers"][0]["parser"], "source_module": registry[f]["parsers"][0]["module"],
           "status": "consumed", "coverage_status": "complete", "coverage_families": [f]} for f in sorted(families)),
        {"parser": "q", "source_module": None, "status": "consumed_empty", "coverage_status": "unavailable",
         "coverage_families": [missing_family] if missing_family else []}]})
    return analysis


def test_the_runner_moves_every_stage_through_declared_gates(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")}
    result = run_pipeline(config)
    assert result["status"] == "completed" and result["dispatched"] is False
    assert result["gates"] == ["G1", "G2", "G3", "G4:luna-high", "G4:rules", "G5"]
    assert verify_run(tmp_path / "run")["status"] == "verified"
    manifest = read_json(tmp_path / "run" / "run-manifest.json")
    assert [(s["stage"], s["reads"], s["writes"]) for s in manifest["stages"]] == [
        ("S1", ["question"], ["G2"]),
        ("S2", ["G1", "G2"], ["G3"]),
        ("check", ["G3"], []),
        ("check", ["G3"], []),
        ("S3", ["G2", "G3"], ["G4:rules"]),
        ("S3'", ["G3"], []),
        ("S4", ["G3", "G4:rules"], []),
        ("S3'", ["G3"], ["G4:luna-high"]),
        ("S4", ["G1", "G3", "G4:rules", "G4:luna-high"], ["G5"]),
    ]
    assert manifest["status"] == "completed"
    records = {read_json(tmp_path / "run" / s["reads_record"]["path"])["step"]:
               read_json(tmp_path / "run" / s["reads_record"]["path"])["read"] for s in manifest["stages"]}
    assert set(records) == {"S1", "S2", "check:presentation", "check:sources", "S3", "S3':freeze",
                            "S4:admission", "S3':publish", "S4:evaluation"}
    assert records["S3"]["run"] and all(p.startswith(("preparation/cards", "assessment/")) for p in records["S3"]["run"])
    assert not records["S4:admission"]["analysis"] and not records["S3"]["generation"]
    rules = json.loads((tmp_path / "run" / "gates" / "G4-rules.json").read_text())
    assert rules["results"][0]["supported_findings"] == ["finding:a"]
    llm = json.loads((tmp_path / "run" / "gates" / "G4-luna-high.json").read_text())
    assert llm["status"] == "frozen" and llm["results"] == []
    assert manifest["config_sha256"] == sha256_bytes(canonical_json(config | {"conditions": ["luna-high"]}).encode())
    assert manifest["implementations"]["S3"] == {"engine": "rules", "module": "fmb.assessment.rules"}
    assert manifest["implementations"]["S2"]["question_scope"] == "hidden"
    assert manifest["implementations"]["S3'"] == {"luna-high": "m"}
    g2 = json.loads((tmp_path / "run" / "gates" / "G2.json").read_text())
    assert g2["question_definitions"]["BQ-TIME-01"]["scope"].startswith("Creation, modification")


def test_the_runner_stops_when_preparation_read_an_undeclared_file(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve(), undeclared_read=generation.resolve() / "ground_truth.json")
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")}
    with pytest.raises(ValueError, match="S2 preparation read generation files that G1 does not declare"):
        run_pipeline(config)


def test_g3_binds_a_collection_made_from_a_moved_generation_by_its_image_hash(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    moved_from = tmp_path / "elsewhere" / "generation"
    config = {"case_label": "I1-01", "generation": str(generation),
              "analysis": str(_analysis(tmp_path, generation, collected_from=moved_from)),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")}
    run_pipeline(config)
    g1, g3 = (read_json(tmp_path / "run" / "gates" / name) for name in ("G1.json", "G3.json"))
    assert g3["collection"]["mode"] == "reused"
    assert g3["collection"]["image_sha256"] == g1["system_image"]["sha256"]


def test_the_runner_refuses_a_collection_of_another_image(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve(), image_sha256="6" * 64)
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")}
    with pytest.raises(ValueError, match="image hash differs from G1's"):
        run_pipeline(config)


def test_a_collection_guard_read_outside_its_recorded_generation_is_refused(tmp_path):
    g1 = stages.evidence_gate(_generation(tmp_path / "generation"), "I1-01", {"generation": tmp_path / "generation"})
    collected_from = tmp_path / "elsewhere"
    stages.check_reads([str(collected_from / "manifest.json")], g1, stage="S2 collection", generation=collected_from)
    with pytest.raises(ValueError, match="outside the generation folder"):
        stages.check_reads([str(tmp_path / "other" / "manifest.json")], g1, stage="S2 collection",
                           generation=collected_from)
    with pytest.raises(ValueError, match="does not declare"):
        stages.check_reads([str(collected_from / "ground_truth.json")], g1, stage="S2 collection",
                           generation=collected_from)


@pytest.mark.parametrize("change, message", [
    ({"surprise": 1}, "unknown configuration keys"),
    ({"conditions": []}, "at least one distinct condition"),
    ({"analysis": None}, "existing analysis or a collect section"),
    ({"dispatch": {"execute": False}}, "dispatch requires execute: true"),
    ({"dispatch": {"execute": True, "cap_usd": "1"}}, "dispatch requires input_usd_per_million"),
])
def test_the_runner_refuses_an_incomplete_configuration(tmp_path, change, message):
    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")} | change
    with pytest.raises(ValueError, match=message):
        run_pipeline(config)
    assert not (tmp_path / "run").exists()


def test_the_runner_stops_when_a_required_family_has_no_usable_source(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    config = {"case_label": "I1-01", "generation": str(generation),
              "analysis": str(_analysis(tmp_path, generation, missing_family="ntfs.usn")),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")}
    with pytest.raises(ValueError, match="no usable source for families the profile requires: BQ-TIME-01: ntfs.usn"):
        run_pipeline(config)


@pytest.fixture
def built(tmp_path):
    from fmb.assessment.rules import assess
    from fmb.core.case_contract import prepare_case
    from fmb.core.sealed_records import seal_directory
    from paper_fixtures import log_bundle

    root = tmp_path / "cards"
    (root / "sent").mkdir(parents=True)
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    (root / "sent" / "log.json").write_text(canonical_json(case))
    write_json(root / "deterministic" / "log.json", assess(case))
    write_json(root / "view-options.json", {"stated_reasons": True})
    write_json(root / "items.json", [{"case_id": "log", "question_id": "BQ-LOG-01"}])
    seal_directory(root, "build-seal.json")
    seal = read_json(root / "build-seal.json")
    seal["requests"] = {"log": {"sent_sha256": sha256_file(root / "sent" / "log.json"),
                                "deterministic_sha256": sha256_file(root / "deterministic" / "log.json")}}
    write_json(root / "build-seal.json", seal)
    g3 = {"case_label": "I1-01", "view_options": stages.file_ref(root / "view-options.json"),
          "questions": {"BQ-LOG-01": {"requests": [{"request_id": "log",
                                                    "sent_sha256": seal["requests"]["log"]["sent_sha256"]}]}}}
    return root, g3, read_json(root / "deterministic" / "log.json")


@pytest.fixture
def cards(tmp_path):
    from fmb.core.case_contract import prepare_case
    from fmb.core.sealed_records import seal_directory
    from paper_fixtures import log_bundle

    root = tmp_path / "cards"
    (root / "sent").mkdir(parents=True)
    (tmp_path / "prepared").mkdir()
    (tmp_path / "generation").mkdir(exist_ok=True)
    write_json(tmp_path / "prepared" / "manifest.json", {"generation": str(tmp_path / "generation")})
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    (root / "sent" / "log.json").write_text(canonical_json(case))
    write_json(root / "view-options.json", {"stated_reasons": True})
    write_json(root / "items.json", [{"case_id": "log", "question_id": "BQ-LOG-01"}])
    write_json(root / "build-report.json", {"production_preparation": str(tmp_path / "prepared")})
    seal_directory(root, "build-seal.json")
    seal = read_json(root / "build-seal.json")
    seal["requests"] = {"log": {"sent_sha256": sha256_file(root / "sent" / "log.json")}}
    write_json(root / "build-seal.json", seal)
    g3 = {"case_label": "I1-01", "view_options": stages.file_ref(root / "view-options.json"),
          "questions": {"BQ-LOG-01": {"requests": [{"request_id": "log",
                                                    "sent_sha256": seal["requests"]["log"]["sent_sha256"]}]}}}
    return root, g3, case


def test_s3_is_a_stage_of_its_own_and_seals_its_result_set(cards, tmp_path):
    from fmb.assessment.rules import assess
    from fmb.assessment.stage import assess_cards, verify_assessment
    from fmb.profiles import question_definitions

    root, g3, case = cards
    rules = tmp_path / "rules"
    result = assess_cards(built=root, output=rules, question_definitions=question_definitions())
    assert result["engine"] == "rules" and result["requests"] == 1
    record = verify_assessment(rules, built=root)
    assert record["engine"]["module"] == "fmb.assessment.rules" and record["truth_sources_used"] == []
    decisions = read_json(rules / "decisions" / "log.json")["decisions"]
    assert all({"status", "evidence_refs", "statement"} <= set(d) for c in decisions.values() for d in c.values())
    g4 = stages.rules_gate(rules, root, g3, "5" * 64)
    expected = assess(case)
    assert g4["assessor"]["view"] == "decoded" and g4["assessor"]["assessment"]["path"].endswith("assessment.json")
    assert [(r["supported_findings"], r["insufficient_findings"]) for r in g4["results"]] == [
        (expected["supported_findings"], expected["insufficient_findings"])]
    write_gate(tmp_path / "run", "G4", g4, qualifier="rules")
    seal = read_json(root / "build-seal.json")
    seal["sealed_utc"] = "changed"
    write_json(root / "build-seal.json", seal)
    with pytest.raises(ValueError):
        verify_assessment(rules, built=root)


def test_s3_refuses_a_sent_card_that_differs_from_its_build_or_g3(cards, tmp_path):
    from fmb.assessment.stage import assess_cards

    root, g3, _ = cards
    g3["questions"]["BQ-LOG-01"]["requests"][0]["sent_sha256"] = "0" * 64
    rules = tmp_path / "rules"
    assess_cards(built=root, output=rules)
    with pytest.raises(ValueError, match="sent card differs from G3"):
        stages.rules_gate(rules, root, g3, "5" * 64)
    (root / "sent" / "log.json").write_text((root / "sent" / "log.json").read_text() + " ")
    with pytest.raises(ValueError):
        assess_cards(built=root, output=tmp_path / "again")


def test_s3_refuses_an_unregistered_engine_and_a_wrong_definition(cards, tmp_path):
    from fmb.assessment.stage import assess_cards
    from fmb.profiles import question_definitions

    root, _, _ = cards
    with pytest.raises(ValueError, match="unknown S3 engine"):
        assess_cards(built=root, output=tmp_path / "x", engine_name="other")
    wrong = question_definitions()
    wrong["BQ-LOG-01"] = {**wrong["BQ-LOG-01"], "question_text": "Something else."}
    with pytest.raises(ValueError, match="differs from the declared definition"):
        assess_cards(built=root, output=tmp_path / "y", question_definitions=wrong)


def test_g3_names_both_views_and_what_the_decoding_adds(built):
    root, _, _ = built
    views = stages.view_differences(root)
    assert views["sent"]["read_by"] == ["S3'", "S3"] and views["decoded"]["read_by"] == ["S3"]
    assert set(views["decoded"]["differences_from_sent"]) == {"BQ-LOG-01"}


def test_s4_reads_the_rules_decisions_from_s3s_result_set(cards, tmp_path, monkeypatch):
    from fmb.assessment.stage import assess_cards
    from fmb.core.case_contract import target_catalog

    root, g3, case = cards
    expected = {fid: "not_supported" for fid in target_catalog(case)}
    monkeypatch.setattr(evaluation, "_references", lambda runs: {"log": {"expected_status": expected}})
    rules = tmp_path / "rules"
    assess_cards(built=root, output=rules)
    run = tmp_path / "luna-high"
    run.mkdir()
    from_s3 = evaluation.findings_table(root, g3, [run], rules=rules)
    recomputed = evaluation.findings_table(root, g3, [run])
    assert from_s3 == recomputed and len(from_s3) == len(expected)


def _executed(run: Path, case_finding_ids: dict, answer: dict, reason: str) -> Path:
    call = run / "run" / "call-001"
    call.mkdir(parents=True)
    write_json(run / "protocol.json", {"condition_id": "luna-high"})
    write_json(run / "run" / "completion.json", {"outcomes": []})
    write_json(call / "outcome.json", {"request_id": "log", "pass": 1, "status": "completed", "attempts": 2})
    write_json(call / "two-list.json", answer)
    write_json(call / "assessment.json", {"reasons": {public: reason for public in case_finding_ids}})
    return run


def test_s4_tabulates_every_finding_with_both_assessors_and_the_reference(built, tmp_path, monkeypatch):
    from fmb.core import paper_contract
    from fmb.core.case_contract import target_catalog

    root, g3, sealed = built
    case = paper_contract.decode_case(read_json(root / "sent" / "log.json"), {"stated_reasons": True})
    catalog = target_catalog(case)
    gap = next(fid for fid, t in catalog.items() if t["component"] == "event_record_sequence_gap")
    expected = {fid: "supported" if fid == gap else "not_supported" for fid in catalog}
    monkeypatch.setattr(evaluation, "_references", lambda runs: {"log": {"expected_status": expected}})
    display = paper_contract.finding_display_ids(case, {"stated_reasons": True})
    run = _executed(tmp_path / "luna-high", display.values(),
                    {"supported_findings": [gap], "insufficient_findings": []}, "Records r00002 and r00003 show it.")
    rows = evaluation.findings_table(root, g3, [run])
    assert len(rows) == len(catalog)
    row = next(r for r in rows if r["finding_id"] == gap)
    assert row["reference"] == "supported" and row["rules"]["status"] == "supported" and row["rules"]["cited"]
    [answer] = row["llm"]["luna-high"]
    citations = answer.pop("citations")
    assert answer == {"pass": 1, "state": "completed", "status": "supported",
                      "cited": ["r00002", "r00003"], "reason": "Records r00002 and r00003 show it."}
    assert sorted(citations["on_subject_card"] + citations["elsewhere_in_request"] + citations["unknown"]) == [
        "r00002", "r00003"]
    result = evaluation.comparison(rows)
    one = result["conditions"]["luna-high"]["passes"]["1"]
    assert one["exact_questions"] == 1 and one["f1"] == 1.0
    assert one["per_question"] == {"BQ-LOG-01": {"missed": [], "spurious": [], "unresolved": [], "not_run": [],
                                                 "exact": True}}
    assert result["rules"]["per_question"]["BQ-LOG-01"]["exact"] is True
    assert one["citations"]["decisions_citing_records"] == 1
    assert one["agreement_with_rules"] == one["agreement_with_reference"] == len(catalog)
    assert result["rules"]["agreement_with_reference"] == len(catalog)
    low, high = one["f1_bootstrap_95"]
    assert low <= one["f1"] <= high


def test_s4_counts_an_unusable_answer_as_missed_positives(built, tmp_path, monkeypatch):
    from fmb.core import paper_contract
    from fmb.core.case_contract import target_catalog

    root, g3, _ = built
    case = paper_contract.decode_case(read_json(root / "sent" / "log.json"), {"stated_reasons": True})
    gap = next(fid for fid, t in target_catalog(case).items() if t["component"] == "event_record_sequence_gap")
    expected = {fid: "supported" if fid == gap else "not_supported" for fid in target_catalog(case)}
    monkeypatch.setattr(evaluation, "_references", lambda runs: {"log": {"expected_status": expected}})
    run = _executed(tmp_path / "luna-high", [], {}, "")
    write_json(run / "run" / "call-001" / "outcome.json", {"request_id": "log", "pass": 1, "status": "invalid_response"})
    one = evaluation.comparison(evaluation.findings_table(root, g3, [run]))["conditions"]["luna-high"]["passes"]["1"]
    assert one["finding_counts"]["fn"] == 1 and one["finding_counts"]["tp"] == 0 and one["exact_questions"] == 0


def _run(tmp_path, monkeypatch, name, **fake):
    generation = tmp_path / "generation"
    if not generation.exists():
        _generation(generation)
        _analysis(tmp_path, generation)
    _fake_stages(monkeypatch, generation.resolve(), **fake)
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(tmp_path / "analysis"),
              "conditions": ["luna-high"], "output": str(tmp_path / name)}
    return run_pipeline(config), tmp_path / name


def test_gate_documents_name_files_relative_to_declared_roots(tmp_path, monkeypatch):
    _, run = _run(tmp_path, monkeypatch, "run")
    g1 = json.loads((run / "gates" / "G1.json").read_text())
    assert g1["generation_root"] == "generation" and g1["system_image"]["root"] == "generation"
    assert g1["system_image"]["path"] == "full_scale.vmdk"
    assert all(not Path(p).is_absolute() for p in g1["readable_paths"])
    g3 = json.loads((run / "gates" / "G3.json").read_text())
    assert g3["build_seal"]["root"] == "run" and g3["build_seal"]["path"] == "preparation/cards/build-seal.json"
    manifest = read_json(run / "run-manifest.json")
    assert manifest["roots"]["generation"] == str((tmp_path / "generation").resolve())
    assert manifest["admission_policy"] == "strict"
    text = "".join((run / "gates" / name).read_text() for name in ("G1.json", "G3.json", "G4-luna-high.json", "G5.json"))
    assert str(tmp_path) not in text


def test_diff_finds_two_runs_in_different_folders_the_same_and_a_changed_stage_different(tmp_path, monkeypatch):
    from fmb.pipeline.diff import diff_runs

    _run(tmp_path, monkeypatch, "first")
    _run(tmp_path, monkeypatch, "second")
    same = diff_runs(tmp_path / "first", tmp_path / "second")
    assert same["status"] == "same" and same["code"]["same"] and same["implementations"]["same"]
    _run(tmp_path, monkeypatch, "changed", answer=["finding:b"])
    changed = diff_runs(tmp_path / "first", tmp_path / "changed")
    assert changed["status"] == "different" and changed["gates"]["G4:rules"]["status"] == "different"
    assert changed["gates"]["G1"]["status"] == changed["gates"]["G3"]["status"] == "same"
    assert changed["gates"]["G4:rules"]["first"][0]["path"] == "/results/0/supported_findings/0"


def test_g5_keeps_the_rules_part_when_admission_fails(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(evaluation, "findings_table", lambda built, g3, runs, rules=None: calls.append(rules) or [])
    result, run = _run(tmp_path, monkeypatch, "run", admission="failed")
    assert result["status"] == "failed" and result["dispatched"] is False
    g5 = json.loads((run / "gates" / "G5.json").read_text())
    assert "findings" in g5 and "comparison" in g5 and g5["admission"]["policy"] == "strict"


@pytest.mark.parametrize("policy, dispatched", [("strict", False), ("report-only", True)])
def test_the_admission_policy_is_declared_and_labels_unadmitted_dispatch(tmp_path, monkeypatch, policy, dispatched):
    from fmb.evaluation import scoring

    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve(), admission="failed")
    sent = []

    def execute_condition(run, **kwargs):
        sent.append(kwargs["development_unadmitted"])
        return {"completed": 0}

    monkeypatch.setattr(workflow, "execute_condition", execute_condition)
    monkeypatch.setattr(scoring, "score_run", lambda run: {"passes": [1]})
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
              "conditions": ["luna-high"], "output": str(tmp_path / "run"), "admission": policy,
              "dispatch": {"execute": True, "cap_usd": "1", "input_usd_per_million": "1", "output_usd_per_million": "1"}}
    result = run_pipeline(config)
    assert result["dispatched"] is dispatched and result["admission_policy"] == policy
    assert sent == ([True] if dispatched else [])
    assert read_json(tmp_path / "run" / "run-manifest.json")["admission_policy"] == policy


def test_the_runner_refuses_an_undeclared_admission_policy(tmp_path):
    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run"), "admission": "lenient"}
    with pytest.raises(ValueError, match="admission must be strict or report-only"):
        run_pipeline(config)
