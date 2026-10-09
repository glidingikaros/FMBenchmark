import os
from pathlib import Path

import pytest

from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import read_json, write_json
from fmb.paper import workflow
from fmb.pipeline import reads, stages
from fmb.pipeline.gates import verify_run
from fmb.pipeline.runner import run_pipeline
from test_pipeline_gates import _analysis, _fake_stages, _generation


def test_each_stage_may_read_only_what_its_gates_declare():
    assert reads.undeclared("S3", {"run": ["preparation", "preparation/cards/sent/r1.json", "assessment/rules/x.json"],
                                   "generation": [], "analysis": []}) == []
    assert reads.undeclared("S3", {"run": [], "generation": ["manifest.json"], "analysis": []}) == [
        "generation:manifest.json"]
    assert reads.undeclared("S3", {"generation": ["."]}) == []
    assert reads.undeclared("S3", {"generation": ["factual-checkpoints"]}) == ["generation:factual-checkpoints"]
    assert reads.undeclared("S3", {"run": ["preparation/prepared/manifest.json"]}) == [
        "run:preparation/prepared/manifest.json"]
    assert reads.undeclared("S4:admission", {"run": ["preparation/prepared/reference-binding.json"],
                                             "generation": ["finding_reference.json"],
                                             "analysis": ["evidence_index.json"]}) == ["analysis:evidence_index.json"]
    assert reads.undeclared("S2", {"analysis": ["anything/at/all.json"], "run": ["preparation/cards/x"]}) == []


def test_reads_are_classified_under_the_most_specific_root(tmp_path):
    run = tmp_path / "run"
    roots = {"run": run, "generation": tmp_path / "generation", "analysis": run / "analysis"}
    found = reads.by_root({str(run / "analysis" / "evidence_index.json"), str(run / "gates" / "G1.json"),
                           str(tmp_path / "elsewhere.json")}, roots)
    assert found == {"analysis": ["evidence_index.json"], "generation": [], "run": ["gates/G1.json"]}


def _config(tmp_path, generation):
    return {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
            "conditions": ["luna-high"], "output": str(tmp_path / "run")}


def test_a_failing_stage_still_leaves_a_run_manifest(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())

    def prepare(**_):
        (generation / "manifest.json").read_text()
        raise RuntimeError("preparation broke")

    monkeypatch.setattr(workflow, "prepare", prepare)
    with pytest.raises(RuntimeError, match="preparation broke"):
        run_pipeline(_config(tmp_path, generation))
    manifest = read_json(tmp_path / "run" / "run-manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["failure"] == {"step": "S2", "type": "RuntimeError", "message": "preparation broke"}
    assert sorted(manifest["gates"]) == ["G1", "G2"]
    failed = manifest["stages"][-1]
    assert failed["step"] == "S2" and failed["status"] == "failed"
    assert "manifest.json" in reads.read_record(tmp_path / "run", failed)["read"]["generation"]
    assert verify_run(tmp_path / "run")["run_status"] == "failed"


@pytest.mark.parametrize("audit_fails", [False, True])
def test_read_audit_preserves_the_original_phase_exception(tmp_path, monkeypatch, audit_fails):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())

    def prepare(**_):
        (generation / "finding_reference.json").read_text()
        raise RuntimeError("original preparation failure")

    monkeypatch.setattr(workflow, "prepare", prepare)
    if audit_fails:
        write = Path.write_bytes

        def write_bytes(path, data):
            if path.name == "S2.json":
                raise OSError("read-record disk failure")
            return write(path, data)

        monkeypatch.setattr(Path, "write_bytes", write_bytes)
    with pytest.raises(RuntimeError, match="original preparation failure") as error:
        run_pipeline(_config(tmp_path, generation))
    manifest = read_json(tmp_path / "run" / "run-manifest.json")
    failed = manifest["stages"][-1]
    assert failed["status"] == "failed" and failed["step"] == "S2"
    assert error.value.__notes__ and "phase audit failed" in error.value.__notes__[0]
    if audit_fails:
        assert "disk failure" in failed["detail"]["audit_error"]
        assert "finding_reference.json" in failed["detail"]["unwritten_reads"]["generation"]
        with pytest.raises(ValueError, match="no record"):
            verify_run(tmp_path / "run")
    else:
        assert "finding_reference.json" in reads.read_record(tmp_path / "run", failed)["read"]["generation"]


def test_manifest_failure_does_not_replace_the_phase_exception(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    write = Path.write_text

    def write_text(path, *args, **kwargs):
        if path.name == "run-manifest.json":
            raise OSError("manifest disk failure")
        return write(path, *args, **kwargs)

    def prepare(**_):
        raise RuntimeError("original preparation failure")

    monkeypatch.setattr(Path, "write_text", write_text)
    monkeypatch.setattr(workflow, "prepare", prepare)
    with pytest.raises(RuntimeError, match="original preparation failure") as error:
        run_pipeline(_config(tmp_path, generation))
    assert "failed to record run manifest" in error.value.__notes__[0]


@pytest.mark.parametrize("mode", ["r", "r+", os.O_RDONLY, os.O_RDWR])
def test_read_measurement_includes_read_write_opens_and_resolved_aliases(tmp_path, mode):
    run, generation = tmp_path / "run", tmp_path / "generation"
    (run / "conditions" / "luna-high").mkdir(parents=True)
    generation.mkdir()
    reference = generation / "finding_reference.json"
    reference.write_text("private")
    alias = run / "conditions" / "luna-high" / "sent.json"
    alias.symlink_to(reference)
    with reads.measured() as opened:
        if isinstance(mode, str):
            with alias.open(mode) as stream:
                stream.read()
        else:
            fd = os.open(alias, mode)
            try:
                os.read(fd, 8)
            finally:
                os.close(fd)
    found = reads.by_root(opened, {"run": run, "generation": generation})
    assert found["generation"] == ["finding_reference.json"]
    assert reads.undeclared("S3':dispatch", found) == ["generation:finding_reference.json"]


@pytest.mark.parametrize("step", ["S3':freeze", "S3':dispatch", "S3':publish"])
def test_model_phases_cannot_read_condition_references(step):
    reference = "conditions/luna-high/admission/references.json"
    assert reads.undeclared(step, {"run": [reference]}) == ["run:" + reference]
    certificate = "conditions/luna-high/admission/admission.json"
    assert bool(reads.undeclared(step, {"run": [certificate]})) is (step != "S3':dispatch")


def test_a_stage_that_reads_an_undeclared_file_is_refused(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    honest = workflow.assess_rules

    def assess_rules(**kwargs):
        (generation / "manifest.json").read_text()
        return honest(**kwargs)

    monkeypatch.setattr(workflow, "assess_rules", assess_rules)
    with pytest.raises(ValueError, match="S3 read files its gates do not declare: generation:manifest.json"):
        run_pipeline(_config(tmp_path, generation))
    manifest = read_json(tmp_path / "run" / "run-manifest.json")
    assert manifest["failure"]["step"] == "S3"


def test_verify_rechecks_every_file_a_gate_references(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    run_pipeline(_config(tmp_path, generation))
    assert verify_run(tmp_path / "run")["files_checked"] > 0
    certificate = tmp_path / "run" / "conditions" / "luna-high" / "admission" / "admission.json"
    write_json(certificate, {"status": "edited"})
    with pytest.raises(ValueError, match="differs from its gate"):
        verify_run(tmp_path / "run")


def test_a_stage_checks_the_build_against_g3_before_reading_it(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    run_pipeline(_config(tmp_path, generation))
    run = tmp_path / "run"
    g3 = read_json(run / "gates" / "G3.json")
    roots = {"run": run, "generation": generation, "analysis": tmp_path / "analysis"}
    assert stages.check_build(g3, roots) == run / "preparation" / "cards"
    write_json(run / "preparation" / "cards" / "sent" / "r1.json", {"card": "edited"})
    with pytest.raises(ValueError, match="sent card differs from G3"):
        stages.check_build(g3, roots)


def test_g3_resolves_every_cited_record_source_to_its_collected_file(tmp_path):
    analysis = tmp_path / "analysis"
    (analysis / "execution").mkdir(parents=True)
    collected = analysis / "execution" / "$LogFile"
    collected.write_bytes(b"log file bytes")
    digest = sha256_file(collected)
    write_json(analysis / "evidence_index.json", {"parser_runs": [
        {"parser": "dfir_ntfs", "source_module": "$LogFile", "raw_outputs": [
            {"artifact_record_id": "source:" + digest[:16], "path": str(collected), "sha256": digest,
             "size_bytes": str(collected.stat().st_size), "artifact_family": "ntfs.logfile"}]}]})
    built = tmp_path / "cards"
    (built / "sent").mkdir(parents=True)
    write_json(built / "sent" / "r1.json", {"source_reference_map": {"r00001": f"source:{digest[:16]}:$LogFile:lsn=1"}})
    roots = {"run": tmp_path / "run", "generation": tmp_path / "generation", "analysis": analysis}
    (tmp_path / "generation").mkdir()
    table = stages.source_table(analysis, tmp_path / "generation", built, roots)
    assert table == {"source:" + digest[:16]: {
        "sha256": digest, "size_bytes": 14, "root": "analysis", "path": "execution/$LogFile",
        "artifact_family": "ntfs.logfile", "read_by": [{"parser": "dfir_ntfs", "module": "$LogFile"}]}}
    write_json(built / "sent" / "r2.json", {"source_reference_map": {"r00002": "source:0000000000000000:x"}})
    with pytest.raises(ValueError, match="cite sources the collection does not record"):
        stages.source_table(analysis, tmp_path / "generation", built, roots)


def test_every_citation_scheme_names_one_source():
    assert stages._cited_source("source:28117eed9960b5c7:$LogFile:lsn=1") == "source:28117eed9960b5c7"
    assert stages._cited_source("native:mft-source:f65074a50bf6c589:$MFT:entry=1:sequence=2") == \
        "native:mft-source:f65074a50bf6c589"
    assert stages._cited_source("native-mft:" + "a" * 64 + ":attribute=4") == "native-mft:" + "a" * 64
    assert stages._cited_source("native-usb-volume:" + "b" * 64) == "native-usb-volume:" + "b" * 64
    assert stages._cited_source("vagrant_UsrClass.csv:row=20") == "vagrant_UsrClass.csv"


@pytest.fixture
def audited_run(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    config = _config(tmp_path, generation)
    config["dispatch"] = {"execute": True, "cap_usd": "0", "input_usd_per_million": "1",
                          "output_usd_per_million": "1"}
    run_pipeline(config)
    run = tmp_path / "run"
    assert verify_run(run)["lifecycle"] == "recorded_order_verified"
    return run, read_json(run / "run-manifest.json")


@pytest.mark.parametrize("edit", ["reorder", "missing", "duplicate", "timestamps", "early_publication"])
def test_verify_rejects_impossible_phase_histories(audited_run, edit):
    run, manifest = audited_run
    entries = manifest["stages"]
    if edit == "reorder":
        entries[4], entries[6] = entries[6], entries[4]
    elif edit == "missing":
        entries.pop(2)
    elif edit == "duplicate":
        entries.insert(2, entries[1])
    elif edit == "timestamps":
        entries[4]["started_utc"] = entries[0]["started_utc"]
    else:
        freeze = next(s for s in entries if s["step"] == "S3':freeze")
        publish = next(s for s in entries if s["step"] == "S3':publish")
        freeze["writes"], publish["writes"] = publish["writes"], []
    write_json(run / "run-manifest.json", manifest)
    with pytest.raises(ValueError, match="out of order|publication"):
        verify_run(run)


@pytest.mark.parametrize("step, role", [("S4:admission", "frozen:luna-high"),
                                       ("S4:admission", "admission_baseline"),
                                       ("S3':dispatch", "admission:luna-high"),
                                       ("S3':publish", "frozen:luna-high"),
                                       ("S4:evaluation", "admission:luna-high")])
def test_verify_requires_the_artifacts_consumed_by_each_phase(audited_run, step, role):
    run, manifest = audited_run
    next(s for s in manifest["stages"] if s["step"] == step)["inputs"].pop(role)
    write_json(run / "run-manifest.json", manifest)
    with pytest.raises(ValueError, match="artifact dependencies"):
        verify_run(run)


def test_verify_checks_frozen_members_as_well_as_their_seal(audited_run):
    run, _ = audited_run
    write_json(run / "conditions" / "luna-high" / "protocol.json", {"edited": True})
    with pytest.raises(ValueError, match="sealed file changed|differs from its gate"):
        verify_run(run)


def test_a_read_record_cannot_claim_a_different_phase_even_with_an_updated_hash(audited_run):
    from fmb.pipeline.contract import check_reads

    run, manifest = audited_run
    entry = next(s for s in manifest["stages"] if s["step"] == "S3")
    record = run / entry["reads_record"]["path"]
    write_json(record, read_json(record) | {"step": "S4:admission"})
    entry["reads_record"]["sha256"] = sha256_file(record)
    write_json(run / "run-manifest.json", manifest)
    for check in (verify_run, check_reads):
        with pytest.raises(ValueError, match="does not belong to its phase"):
            check(run)


def test_legacy_manifests_remain_readable_without_claiming_phase_verification(audited_run):
    from fmb.pipeline.contract import check_run

    run, manifest = audited_run
    manifest["schema_version"] = "fmb.pipeline.run.v1"
    publish = next(s for s in manifest["stages"] if s["step"] == "S3':publish")
    next(s for s in manifest["stages"] if s["step"] == "S3':freeze")["writes"] = publish["writes"]
    manifest["stages"].remove(publish)
    for entry in manifest["stages"]:
        for key in ("step", "status", "inputs", "outputs"):
            entry.pop(key)
    write_json(run / "run-manifest.json", manifest)
    result = verify_run(run)
    assert result["lifecycle"] == "unverified_legacy" and result["limitations"]
    assert check_run(run)["checks"]["gates"]["detail"]["lifecycle"] == "unverified_legacy"


def test_a_partial_publication_is_recorded_on_the_phase_that_wrote_it(tmp_path, monkeypatch):
    from fmb.pipeline import runner

    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    config = _config(tmp_path, generation)
    config["conditions"].append("other")
    write = runner.write_gate

    def write_gate(*args, **kwargs):
        if kwargs.get("qualifier") == "other":
            raise RuntimeError("publication failed")
        return write(*args, **kwargs)

    monkeypatch.setattr(runner, "write_gate", write_gate)
    with pytest.raises(RuntimeError, match="publication failed"):
        run_pipeline(config)
    run = tmp_path / "run"
    manifest = read_json(run / "run-manifest.json")
    assert manifest["stages"][-1]["step"] == "S3':publish"
    assert manifest["stages"][-1]["writes"] == ["G4:luna-high"]
    assert verify_run(run)["run_status"] == "failed"


def test_changed_phase_input_is_rejected_before_private_admission(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())

    def check_sources(prepared):
        seal = prepared / "preparation-seal.json"
        seal.write_text(seal.read_text() + " ")
        return {"status": "passed", "source_files": 0}

    monkeypatch.setattr(workflow, "check_preparation_sources", check_sources)
    monkeypatch.setattr(workflow, "admit_native", lambda *_, **__: pytest.fail("changed input admitted"))
    with pytest.raises(ValueError, match="phase input changed since its production: preparation"):
        run_pipeline(_config(tmp_path, generation))
    manifest = read_json(tmp_path / "run" / "run-manifest.json")
    assert manifest["failure"]["step"] == "S4:admission"
