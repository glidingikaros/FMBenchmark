from pathlib import Path
import time

from fmb.assessment.requests import write_condition
from fmb.assessment.llm import execute_schedule
from fmb.core import paper_integrity as integrity
from fmb.core.hashing import sha256_file
from fmb.core.paper_artifacts import preparation_folder, verify_preparation, verify_prepared_condition
from fmb.core.paper_protocol import declare_conditions, paper_protocol, run_declaration
from fmb.core.sealed_records import read_json, write_json, seal_directory, verify_seal
from fmb.core.truth_guard import truth_blind_reads
from fmb.evaluation.admission import admit_conditions, read_admission
from fmb.evaluation.native_reference import write_native_references
from fmb.paper.presentation import build
from fmb.paper.presentation_check import check_presentation
from fmb.preparation.native import prepare_cases


def prepare_native(
    *, analysis: Path, generation: Path, output: Path, planned_counts: dict,
    questions: list[str] | None = None,
) -> dict:
    started = time.monotonic()
    source_lock = integrity.source_manifest_sha256()
    manifest = prepare_cases(
        analysis=analysis, generation=generation, output=output,
        planned_counts=planned_counts, questions=questions,
    )
    with truth_blind_reads(generation):
        write_json(
            output / "source-hashes.json",
            integrity.snapshot_sources(output / "frozen-source"),
        )
        manifest.update(
            oracle_lock_sha256=source_lock,
            elapsed_seconds=time.monotonic() - started,
        )
        write_json(output / "manifest.json", manifest)
        seal_directory(output)
    return {
        "output": str(output),
        "questions": len(manifest["rows"]),
        "preparation_seal_sha256": sha256_file(output / "preparation-seal.json"),
    }


def prepare(*, analysis: Path, generation: Path, image: str, output: Path, question_scope: str = "hidden",
            presentation_check: bool = True, g2: dict | None = None, assemble=None) -> dict:
    from fmb.core.case_contract import QIDS
    from fmb.profiles import resolve_profile, validate_profile

    g2 = resolve_profile() if g2 is None else g2
    questions = [question["question_id"] for question in g2["questions"]]
    validate_profile(g2, questions)
    output.mkdir(parents=True, exist_ok=False)
    prepare_native(
        analysis=analysis, generation=generation, output=output / "prepared",
        planned_counts=paper_protocol()["images"].get(image.split("-", 1)[0], {}).get("planned_counts"),
        questions=questions,
    )
    result = build(
        prepared=output / "prepared", analysis=analysis, image=image,
        output=output / "cards", question_scope=question_scope, questions=None if questions == list(QIDS) else questions,
        **({"assemble": assemble} if assemble is not None else {}),
    )
    if presentation_check:
        check = check_presentation(prepared=output / "prepared", built=output / "cards", engine_name="rules")
        write_json(output / "presentation-check.json", check)
        result["presentation_check"] = check["status"]
    return result


def assess_rules(*, built: Path, output: Path, engine_name: str = "rules", question_definitions: dict | None = None,
                 generation: Path | None = None, assessor=None) -> dict:
    from fmb.assessment.stage import assess_cards

    built = Path(built).resolve(strict=True)
    metadata = read_json(built / "build-report.json")
    if integrity.source_manifest_sha256() != metadata["oracle_lock_sha256"]:
        raise ValueError("implementation changed after card preparation")
    return assess_cards(built=built, output=output, engine_name=engine_name,
                        question_definitions=question_definitions, generation=generation, assessor=assessor)


def freeze_condition(
    *, built: Path, condition: str, output: Path, completion: bool = False, generation: Path | None = None,
    passes: int | None = None,
) -> dict:
    built = Path(built).resolve(strict=True)
    verify_seal(built, "build-seal.json")
    metadata = read_json(built / "build-report.json")
    if (preparation_folder(built, metadata) / "admission").exists():
        raise ValueError("freeze requests before opening reference admission")
    source_lock = integrity.source_manifest_sha256()
    if source_lock != metadata["oracle_lock_sha256"]:
        raise ValueError("implementation changed after card preparation")
    return write_condition(
        built=built, condition=condition, output=output,
        source_lock=source_lock, completion=completion, generation=generation, passes=passes,
    )


def check_preparation_sources(prepared: Path) -> dict:
    prepared = Path(prepared).resolve(strict=True)
    verify_preparation(prepared, sources=True)
    return {"status": "passed", "source_files": len(read_json(prepared / "source-records.json"))}


def admit_native(prepared: Path, *, built: Path, condition_runs: list[Path], rules: Path | None = None,
                 binding: Path | None = None, verify_sources: bool = True) -> dict:
    prepared, built = Path(prepared).resolve(strict=True), Path(built).resolve(strict=True)
    manifest = verify_preparation(prepared, sources=verify_sources)
    verify_seal(built, "build-seal.json")
    if not condition_runs:
        raise ValueError("freeze model requests before opening reference data")
    if rules is not None:
        from fmb.assessment.stage import verify_assessment

        verify_assessment(rules, built=built)
    for condition in condition_runs:
        verify_prepared_condition(condition, built=built)
    report = read_json(built / "build-report.json")
    if (
        preparation_folder(built, report) != prepared
        or report["production_seal_sha256"] != sha256_file(prepared / "preparation-seal.json")
        or report["reference_already_opened"]
    ):
        raise ValueError("build does not belong to this truth-blind preparation")
    references = write_native_references(prepared, manifest, binding=binding)
    return admit_conditions(
        prepared=prepared, built=built, condition_runs=condition_runs,
        references=references, rules=rules,
    )


def execute_condition(
    root: Path, *, cap_usd, rates: dict, execute: bool = False, provider=None,
    sleep=time.sleep, pass_limit: int | None = None, question_ids: list | None = None,
    development_unadmitted: bool = False, counter=None,
    primary: Path | None = None,
) -> dict:
    root = Path(root).resolve(strict=True)
    protocol, _, schedule = verify_prepared_condition(root)
    admission = read_admission(root)
    development = None
    if admission["status"] != "passed":
        if not development_unadmitted:
            raise ValueError("condition lacks exact independent admission")
        development = {"label": "development_not_admitted", "admission_status": admission["status"],
                       "admission_sha256": sha256_file(root / "admission/admission.json")}
    with declare_conditions(run_declaration(protocol)):
        return execute_schedule(
            root, protocol=protocol, schedule=schedule, cap_usd=cap_usd, rates=rates,
            execute=execute, provider=provider, sleep=sleep, pass_limit=pass_limit,
            question_ids=question_ids, development=development, counter=counter,
            primary=primary,
        )
