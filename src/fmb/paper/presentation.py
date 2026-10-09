from copy import deepcopy
import os
from pathlib import Path
import re
import time
from fmb.core import paper_contract as contracts, paper_integrity as integrity
from fmb.core.case_contract import QIDS
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.sealed_records import canonical_json, now, read_json, write_json
from fmb.core.truth_guard import truth_blind_reads
from fmb.preparation.cards import (
    PRESENTATION, LISTING_QUESTIONS, SPLIT_QUESTIONS, OPTIONS_TEMPLATE, LEVEL,
    collection_sources, listing_prefixes, scan_listing, denaive, stream_heads,
    volume_ids, one_card_case,
)

QUESTION_SCOPE = {"hidden", "shown"}


def _targets(case: dict) -> int:
    return sum(len(card["assessment_targets"]) for card in case["candidate_roster"])


def build(
    *,
    prepared: Path,
    analysis: Path,
    image: str,
    output: Path,
    question_scope: str = "hidden",
    questions: list[str] | None = None,
    assemble=None,
) -> dict:
    from fmb.core.sealed_records import verify_seal
    from fmb.analysis.native_preparation import encode_log_case

    if not re.fullmatch(r"I[0-9]{1,2}(-[A-Za-z0-9]{1,12})?", image):
        raise ValueError("invalid image label")
    if question_scope not in QUESTION_SCOPE:
        raise ValueError("question_scope must be hidden or shown")
    selected = list(QIDS) if questions is None else [qid for qid in QIDS if qid in set(questions)]
    if questions is not None and (not selected or len(selected) != len(set(questions))):
        raise ValueError("questions must name distinct paper questions")
    started = time.monotonic()
    prepared, analysis = prepared.resolve(strict=True), analysis.resolve(strict=True)
    verify_seal(prepared)
    manifest = read_json(prepared / "manifest.json")
    if (
        Path(manifest["analysis"]).resolve() != analysis
        or manifest.get("truth_sources_used") != []
    ):
        raise ValueError(
            "the sealed production preparation belongs to another collection"
        )
    if (prepared / "admission").exists():
        raise ValueError(
            "the production reference was already opened; the I-series build must precede admission"
        )
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    source_lock = integrity.source_manifest_sha256()
    if source_lock != manifest["oracle_lock_sha256"]:
        raise ValueError("oracle lock changed after the production preparation")
    log, report, seal = [], {"image": image, "questions": {}}, {}
    with truth_blind_reads(Path(manifest["generation"])) as guard:
        production = {
            qid: read_json(prepared / "cases" / (qid + ".json")) for qid in selected
        }
        cases = dict(production)
        if "BQ-LOG-01" in cases:
            cases["BQ-LOG-01"] = encode_log_case(production["BQ-LOG-01"])
        for qid in selected:
            for transform in PRESENTATION[qid]:
                trial = deepcopy(cases[qid])
                try:
                    transform(trial)
                    kept, why = True, ""
                except Exception as error:
                    kept, why = False, f"{type(error).__name__}: {error}"[:300]
                log.append(
                    {
                        "question": qid,
                        "step": "U " + transform.__name__,
                        "kept": kept,
                        "reason": why,
                        "changed_case": canonical_json(trial)
                        != canonical_json(cases[qid]),
                    }
                )
                if kept:
                    cases[qid] = trial
        scan = {"scanned_rows": 0}
        if set(selected) & set(LISTING_QUESTIONS):
            sources = collection_sources(analysis)
            prefixes, digests = listing_prefixes(cases)
            scan = scan_listing(sources["mft_csv"], prefixes, digests)
            write_json(output / "mft-scan.json",
                       {k: v for k, v in scan.items() if k != "rows"} | {"kept_rows": len(scan["rows"])})
            for qid in LISTING_QUESTIONS:
                if qid in cases:
                    cases[qid] = denaive(cases[qid], scan, log)
        options = deepcopy(OPTIONS_TEMPLATE)
        if question_scope == "shown":
            options["views"] = [view for view in options["views"] if view != "no_scope"]
        if "BQ-STREAM-01" in cases:
            heads = stream_heads(cases["BQ-STREAM-01"], analysis / "factual-supplement" / "native-ntfs")
            write_json(output / "stream-heads.json", heads)
            options["stream_heads_path"] = "stream-heads.json"
        pair = volume_ids(cases["BQ-DIRECTORY-01"]) if "BQ-DIRECTORY-01" in cases else None
        if pair:
            options["volume_ids"] = {"BQ-DIRECTORY-01": pair}
        write_json(output / "view-options.json", options)
        bound = contracts.bind_options(options, output)
        (output / "cases").mkdir()
        (output / "sent").mkdir()
        items = []
        for qid in selected:
            source = cases[qid]
            if assemble is not None:
                source = assemble(source)
            parts = (
                [
                    (f"-c{n:02d}", one_card_case(source, n - 1))
                    for n in range(1, len(source["candidate_roster"]) + 1)
                ]
                if qid in SPLIT_QUESTIONS
                else [("", source)]
            )
            question = {
                "cards": len(source["candidate_roster"]),
                "findings": _targets(production[qid]),
                "requests": len(parts),
                "production_case_bytes": len(canonical_json(production[qid])),
                "sent_bytes": 0,
            }
            for suffix, case in parts:
                sent = contracts.encode(case, bound)
                case_id = f"e2e-{image.lower()}-{qid}{suffix}"
                text, sent_text = canonical_json(case), canonical_json(sent)
                (output / "cases" / (case_id + ".json")).write_text(text)
                (output / "sent" / (case_id + ".json")).write_text(sent_text)
                seal[case_id] = {
                    "case_sha256": sha256_bytes(text.encode()),
                    "sent_sha256": sha256_bytes(sent_text.encode()),
                    "sent_bytes": len(sent_text.encode()),
                    "findings": _targets(case),
                }
                question["sent_bytes"] += len(sent_text.encode())
                items.append(
                    {
                        "case_id": case_id,
                        "question_id": qid,
                        "family": qid.split("-")[1].lower(),
                        "path": "cases/" + case_id + ".json",
                        "realism": "native",
                        "view": "complete",
                    }
                )
            report["questions"][qid] = question
        opened = sorted(guard["opened"])
        if guard["denied"]:
            raise ValueError("the I-series build attempted a private read")
    write_json(output / "items.json", items)
    write_json(output / "transform-log.json", log)
    report.update(
        findings=sum(q["findings"] for q in report["questions"].values()),
        cards=sum(q["cards"] for q in report["questions"].values()),
        requests_per_pass=len(items),
        sent_bytes=sum(q["sent_bytes"] for q in report["questions"].values()),
        listing_rows_scanned=scan["scanned_rows"],
        oracle_lock_sha256=source_lock,
        production_preparation=os.path.relpath(prepared, output),
        production_seal_sha256=sha256_file(prepared / "preparation-seal.json"),
        generation_files_opened=opened,
        truth_sources_used=[],
        model_calls=0,
        reference_already_opened=(prepared / "admission").exists(),
        selected_questions=selected,
        level=LEVEL,
        options_sha256=sha256_bytes(canonical_json(options).encode()),
        elapsed_seconds=round(time.monotonic() - started, 1),
        built_utc=now(),
    )
    write_json(output / "build-report.json", report)
    write_json(
        output / "build-seal.json",
        {
            "sealed_utc": now(),
            "requests": seal,
            "files": {
                str(p.relative_to(output)): sha256_file(p)
                for p in sorted(output.rglob("*"))
                if p.is_file() and p.name != "build-seal.json"
            },
        },
    )
    return {
        "status": "built",
        "image": image,
        "output": str(output),
        "requests_per_pass": len(items),
        "findings": report["findings"],
        "sent_bytes": report["sent_bytes"],
        "seal_sha256": sha256_file(output / "build-seal.json"),
    }
