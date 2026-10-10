from pathlib import Path
from fmb.evaluation.factual_reference import bind_factual_references, bind_from_table
from fmb.core.case_contract import QIDS, finding_id
from fmb.analysis.shared_evidence import EvidenceBundle
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import now, read_json, write_json, seal_directory
from fmb.generation.pilot_profile import validate_materialization


def write_native_references(prepared: Path, manifest: dict, binding: Path | None = None) -> dict:
    admission = prepared / "admission"
    admission.mkdir(exist_ok=False)
    generation = Path(manifest["generation"])
    declared = read_json(generation / "manifest.json")
    truth_sources = {}

    def artifact(name):
        path = generation / name
        records = [r for r in declared["artifacts"] if r["file"] == name]
        if (
            Path(name).name != name
            or path.is_symlink()
            or len(records) != 1
            or path.stat().st_size != records[0]["size_bytes"]
            or sha256_file(path) != records[0]["sha256"]
        ):
            raise ValueError("generation truth receipt is not manifest-bound: " + name)
        truth_sources[name] = records[0]["sha256"]
        return read_json(path)

    reference_name = declared["finding_reference"]
    reference_path = generation / reference_name
    if (
        reference_path.name != reference_name
        or reference_path.is_symlink()
        or sha256_file(reference_path) != declared["finding_reference_sha256"]
    ):
        raise ValueError("finding reference is not manifest-bound")
    reference = read_json(reference_path)
    truth_sources[reference_name] = declared["finding_reference_sha256"]
    plan, receipt = (
        artifact("factual-challenge-plan.json"),
        artifact("factual-challenge-receipt.json"),
    )
    initial = artifact("pilot-materialization.json")
    validate_materialization(plan, initial, receipt)
    table_path = Path(binding) if binding is not None else prepared / "reference-binding.json"
    if table_path.is_file():
        from fmb.core.schemas import validate_payload

        table = read_json(table_path)
        validate_payload(table, "reference_binding.schema.json")
        if table["native_volume_serial_number"] != manifest["native_volume_serial_number"]:
            raise ValueError("the binding table belongs to another preparation")
        factual = bind_from_table(table=table, base_reference=reference, plan=plan, receipt=receipt)
    else:
        bundles = [
            EvidenceBundle((prepared / "bundles" / (qid + ".json")).read_text())
            for qid in QIDS
        ]
        factual = bind_factual_references(
            base_index=read_json(Path(manifest["base_evidence_index"])),
            base_reference=reference,
            bundles=bundles,
            plan=plan,
            receipt=receipt,
            native_volume_serial_number=manifest["native_volume_serial_number"],
        )
    references = {
        qid: {
            "expected_status": {
                finding_id(sid, component): row["status"]
                for sid, components in value["assessments"].items()
                for component, row in components.items()
            },
            "basis": "independent host operations and native identity receipts",
            "truth_sources": truth_sources,
        }
        for qid, value in factual.items()
    }
    write_json(admission / "factual-references.json", factual)
    write_json(admission / "references.json", references)
    write_json(
        admission / "provenance.json",
        {
            "admitted_utc": now(),
            "generation": str(generation),
            "truth_sources": truth_sources,
            "preparation_seal_sha256": sha256_file(prepared / "preparation-seal.json"),
        },
    )
    seal_directory(admission, "truth-seal.json")
    return references
