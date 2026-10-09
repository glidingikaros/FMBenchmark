from pathlib import Path

from fmb.core import paper_contract
from fmb.core.case_contract import QIDS
from fmb.core.case_contract import target_catalog
from fmb.core.hashing import sha256_file
from fmb.core.paper_results import finding_status
from fmb.core.sealed_records import (
    contained_path,
    read_json,
    write_json,
    verify_seal,
    seal_directory,
    now,
)


def admit_evidence(g3: dict, baseline: dict, frozen: dict, *, roots: dict[str, Path]) -> dict:
    from fmb.paper.workflow import admit_native
    from fmb.pipeline.stages import check_preparation, checked_binding, resolve

    seal = resolve(baseline, roots)
    if (seal.name != "assessment-seal.json" or seal.parent.parent != roots["run"] / "assessment"
            or sha256_file(seal) != baseline["sha256"]):
        raise ValueError("admission baseline differs from its declared assessment seal")
    rules = seal.parent
    if read_json(rules / "assessment.json")["engine"]["id"] != "rules":
        raise ValueError("paper admission requires the fixed rules baseline")
    for reference in frozen.values():
        if sha256_file(resolve(reference, roots)) != reference["sha256"]:
            raise ValueError("frozen condition differs from its declared seal")
    prepared, built = check_preparation(g3, roots)
    return admit_native(
        prepared, built=built,
        condition_runs=[resolve(reference, roots).parent for reference in frozen.values()],
        rules=rules, binding=checked_binding(g3, roots), verify_sources=False)


def admit_conditions(
    *, prepared: Path, built: Path, condition_runs: list[Path], references: dict, rules: Path | None = None
):
    from fmb.core.paper_artifacts import condition_options, preparation_folder, verify_prepared_condition

    prepared = Path(prepared).resolve(strict=True)
    built = Path(built).resolve(strict=True)
    verify_seal(prepared)
    verify_seal(built, "build-seal.json")
    legacy = all("deterministic_sha256" in binding
                 for binding in read_json(built / "build-seal.json")["requests"].values())
    assessment = None
    if rules is not None:
        from fmb.assessment.stage import rule_result, verify_assessment

        rules = Path(rules).resolve(strict=True)
        assessment = verify_assessment(rules, built=built)
    elif not legacy:
        raise ValueError("admission needs S3's sealed rule assessment (fmb paper assess)")
    build = read_json(built / "build-report.json")
    if (
        preparation_folder(built, build) != prepared
        or build["production_seal_sha256"]
        != sha256_file(prepared / "preparation-seal.json")
        or build["reference_already_opened"]
    ):
        raise ValueError("build is not bound to the truth-blind preparation")
    verify_seal(prepared / "admission", "truth-seal.json")
    manifest = read_json(prepared / "manifest.json")
    preparation_scope = (manifest["selected_questions"] if manifest.get("schema_version") == "paper_native_preparation.v2"
                         else list(QIDS))
    if read_json(prepared / "admission/references.json") != references or set(
        references
    ) != set(preparation_scope):
        raise ValueError("reference differs from independent admission")
    if not condition_runs or len({Path(p).resolve() for p in condition_runs}) != len(
        condition_runs
    ):
        raise ValueError("provide distinct frozen conditions")
    pending = []
    for root in condition_runs:
        root = Path(root).resolve(strict=True)
        protocol, rows, _ = verify_prepared_condition(root, built=built)
        options = condition_options(root, protocol)
        if (root / "admission").exists():
            raise FileExistsError("admission already exists")
        selected, seen, differences = {}, {qid: set() for qid in QIDS}, []
        for row in rows:
            rid, qid = row["request_id"], row["question_id"]
            case = paper_contract.decode_case(
                read_json(root / "cases" / (rid + ".json")), options
            )
            fids = set(target_catalog(case))
            if seen[qid] & fids:
                raise ValueError("finding occurs in more than one request")
            seen[qid].update(fids)
            wanted = {
                fid: references[qid]["expected_status"][fid] for fid in sorted(fids)
            }
            if any(
                value not in {"supported", "not_supported"} for value in wanted.values()
            ):
                raise ValueError("independent reference contains an unresolved label")
            prediction = (rule_result(rules, rid, case)[0] if assessment is not None
                          else read_json(root / "deterministic" / (rid + ".json")))
            actual = {fid: finding_status(prediction, fid) for fid in fids}
            if actual != wanted:
                differences.append(rid)
            selected[rid] = {
                "expected_status": wanted,
                "basis": references[qid]["basis"],
                "case_sha256": row["case_sha256"],
            }
        declared = build.get("selected_questions", list(QIDS))
        if (set(declared) - set(QIDS)
                or any(seen[qid] != set(references[qid]["expected_status"]) for qid in declared)
                or any(seen[qid] for qid in set(QIDS) - set(declared))):
            raise ValueError("requests do not cover the complete independent reference")
        pending.append((root, selected, differences))
    passed = all(not differences for _, _, differences in pending)
    for root, selected, differences in pending:
        directory = root / "admission"
        directory.mkdir()
        write_json(directory / "references.json", selected)
        write_json(
            directory / "admission.json",
            {
                "schema_version": "paper_admission.v1",
                "status": "passed" if passed else "failed",
                "admitted_utc": now(),
                "different_requests": differences,
                "preparation_seal_sha256": sha256_file(root / "preparation-seal.json"),
                "truth_seal_sha256": sha256_file(
                    prepared / "admission/truth-seal.json"
                ),
                "references_sha256": sha256_file(directory / "references.json"),
                **({"rule_assessment": {"engine": assessment["engine"]["id"],
                                        "assessment_sha256": sha256_file(rules / "assessment.json")}}
                   if assessment is not None else {}),
                "claim_boundary": "screened cohort admission, not held-out accuracy",
            },
        )
        seal_directory(directory, "admission-seal.json")
    return {
        "status": "passed" if passed else "failed",
        "conditions": len(pending),
        "different_requests": {str(root): different for root, _, different in pending},
    }


def read_admission(root: Path) -> dict:
    directory = Path(root) / "admission"
    seal = read_json(contained_path(directory, "admission-seal.json"))
    certificate = contained_path(directory, "admission.json")
    if sha256_file(certificate) != seal["files"]["admission.json"]:
        raise ValueError("sealed file changed or is missing: admission.json")
    admission = read_json(certificate)
    if (admission["preparation_seal_sha256"] != sha256_file(Path(root) / "preparation-seal.json")
            or admission["references_sha256"] != seal["files"]["references.json"]
            or admission["status"] not in {"passed", "failed"}):
        raise ValueError("condition lacks exact independent admission")
    return admission


def reference_file(root: Path, override: Path | None = None) -> Path:
    root = Path(root).resolve(strict=True)
    if (root / "admission/admission-seal.json").is_file():
        seal = verify_seal(root / "admission", "admission-seal.json")
        canonical = root / "admission/references.json"
        digest = seal["files"]["references.json"]
        certificate = read_json(root / "admission/admission.json")
        if (
            certificate["preparation_seal_sha256"]
            != sha256_file(root / "preparation-seal.json")
            or certificate["references_sha256"] != digest
        ):
            raise ValueError("reference admission binding changed")
    else:
        seal = verify_seal(root)
        canonical = root / "references.json"
        if "references.json" not in seal["files"]:
            raise ValueError("reference is not covered by a seal")
        digest = seal["files"]["references.json"]
    selected = Path(override) if override is not None else canonical
    if sha256_file(selected) != digest:
        raise ValueError("substituted reference differs from sealed labels")
    return selected
