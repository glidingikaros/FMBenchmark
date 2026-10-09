from pathlib import Path
from fmb.core import paper_integrity as integrity
from fmb.core import paper_contract
from fmb.core.case_contract import validate_response
from fmb.core.case_contract import QIDS
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.paper_protocol import validate_condition, validate_request_settings
from fmb.core.paper_results import IDENTITY_FIELDS
from fmb.core.sealed_records import canonical_json, contained_path, parse_json, read_json, verify_seal
from fmb.interpretation.paper_payload import wire


def record_path(base: Path, value: str) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else Path(base) / path).resolve()


def preparation_folder(built: Path, report: dict) -> Path:
    return record_path(built, report["production_preparation"])


def build_generation(built: Path) -> Path:
    report = read_json(Path(built) / "build-report.json")
    return Path(read_json(preparation_folder(built, report) / "manifest.json")["generation"])


def guard_record(guard: dict) -> dict:
    root = Path(guard["generation"])
    return {"generation_files_opened": sorted(Path(p).relative_to(root).as_posix() for p in guard["opened"]),
            "denied_private_reads": list(guard["denied"])}


def condition_build(root: Path, protocol: dict) -> Path:
    return record_path(root, protocol["built"])


def condition_options(root: Path, protocol: dict) -> dict:
    build = condition_build(root, protocol) if protocol.get("built") else None
    return paper_contract.bind_options(protocol.get("options"), build)


def build_content_sha256(built: Path) -> str:
    built = Path(built)
    seal = read_json(built / "build-seal.json")
    options = dict(read_json(built / "view-options.json"))
    if options.get("stream_heads_path"):
        located = paper_contract.bind_options(options, built)["stream_heads_path"]
        options["stream_heads_path"] = "sha256:" + sha256_file(Path(located))
    body = {
        "requests": {request_id: {key: binding[key] for key in ("case_sha256", "sent_sha256", "findings")
                                  if key in binding}
                     for request_id, binding in sorted(seal["requests"].items())},
        "items": [[item["case_id"], item["question_id"]] for item in read_json(built / "items.json")],
        "view_options": options,
    }
    return sha256_bytes(canonical_json(body).encode())


def rule_result_bytes(built: Path, rid: str, binding: dict, options: dict) -> bytes:
    seal = read_json(built / "build-seal.json")
    if (
        "deterministic_sha256" not in binding
        or seal["files"].get("deterministic/" + rid + ".json") != binding["deterministic_sha256"]
        or seal["files"].get("sent/" + rid + ".json") != binding["sent_sha256"]
    ):
        raise ValueError("paper build lacks a sealed canonical deterministic result")
    path = contained_path(built, "deterministic/" + rid + ".json")
    if sha256_file(path) != binding.get("deterministic_sha256"):
        raise ValueError("canonical deterministic result differs from paper build")
    sent = read_json(contained_path(built, "sent/" + rid + ".json"))
    validate_response(paper_contract.decode_case(sent, options), read_json(path))
    return path.read_bytes()


def verify_preparation(prepared: Path, *, sources: bool = False) -> dict:
    verify_seal(prepared)
    manifest = read_json(prepared / "manifest.json")
    if (
        manifest.get("schema_version") not in {"paper_native_preparation.v1", "paper_native_preparation.v2"}
        or manifest.get("truth_sources_used") != []
    ):
        raise ValueError("not a truth-blind paper preparation")
    if integrity.source_manifest_sha256() != manifest["oracle_lock_sha256"]:
        raise ValueError("implementation changed after preparation")
    selected = (list(QIDS) if manifest["schema_version"] == "paper_native_preparation.v1"
                else manifest.get("selected_questions", []))
    if (not selected or selected != [qid for qid in QIDS if qid in selected]
            or [row["question_id"] for row in manifest["rows"]] != selected):
        raise ValueError("incomplete prepared question roster")
    planned = manifest["planned_counts"]
    for row in manifest["rows"]:
        if planned is not None and [row["subjects"], row["targets"]] != planned[row["question_id"]]:
            raise ValueError("prepared population differs from declared scope")
    if sources:
        for name, row in read_json(prepared / "source-records.json").items():
            path = Path(name)
            if (
                path.stat().st_size != row["size_bytes"]
                or sha256_file(path) != row["sha256"]
            ):
                raise ValueError("native source changed after preparation: " + name)
        current = integrity.source_files()
        frozen = read_json(prepared / "source-hashes.json")
        if set(current) != set(frozen) or any(
            sha256_file(current[name]) != digest for name, digest in frozen.items()
        ):
            raise ValueError("implementation snapshot changed")
    return manifest


def verify_prepared_condition(root: Path, *, built: Path | None = None):
    root = Path(root).resolve(strict=True)
    verify_seal(root)
    protocol = read_json(root / "protocol.json")
    validate_condition(protocol.get("settings"), condition=protocol.get("condition_id"))
    if (
        protocol.get("schema_version") != "paper_condition.v1"
        or protocol.get("truth_sources_used") != []
    ):
        raise ValueError("not a truth-blind prepared paper condition")
    if protocol["source_manifest_sha256"] != integrity.source_manifest_sha256():
        raise ValueError("implementation changed")
    source = condition_build(root, protocol)
    if not source.is_dir():
        raise ValueError("condition build is missing: " + str(source))
    if built is not None and source != Path(built).resolve(strict=True):
        raise ValueError("condition belongs to another build")
    verify_seal(source, "build-seal.json")
    if sha256_file(source / "build-seal.json") != protocol["build_seal_sha256"]:
        raise ValueError("build binding changed")
    expected = read_json(source / "build-seal.json")["requests"]
    rows = read_json(root / "manifest.json")["rows"]
    if len(rows) != len(expected) or {r["request_id"] for r in rows} != set(expected):
        raise ValueError("incomplete request universe")
    for row in rows:
        rid = row["request_id"]
        kwargs = read_json(contained_path(root, "requests/" + rid + ".kwargs.json"))
        body = wire(kwargs)
        validate_request_settings(parse_json(body.decode()), protocol["settings"], kwargs=kwargs)
        if (
            sha256_bytes(body) != row["request_sha256"]
            or sha256_file(contained_path(root, "requests/" + rid + ".json"))
            != row["request_sha256"]
        ):
            raise ValueError("request serialization differs from freeze")
        if (
            sha256_file(contained_path(root, "cases/" + rid + ".json"))
            != expected[rid]["sent_sha256"]
        ):
            raise ValueError("case differs from paper build")
        if "deterministic_sha256" in expected[rid]:
            baseline = rule_result_bytes(source, rid, expected[rid], condition_options(root, protocol))
            if contained_path(root, "deterministic/" + rid + ".json").read_bytes() != baseline:
                raise ValueError("condition deterministic result differs from paper build")
    schedule = read_json(root / "schedule.json")["rows"]
    keys = [(r["request_id"], r["pass"]) for r in schedule]
    if len(keys) != len(set(keys)) or set(keys) != {
        (rid, p) for rid in expected for p in (1, 2, 3)
    }:
        raise ValueError("incomplete three-pass schedule")
    by_id = {r["request_id"]: r for r in rows}
    if [r["call"] for r in schedule] != list(range(1, len(schedule) + 1)):
        raise ValueError("schedule call numbering changed")
    for row in schedule:
        if any(
            row.get(k) != by_id[row["request_id"]].get(k)
            for k in (*IDENTITY_FIELDS, "request_sha256", "case_sha256")
        ):
            raise ValueError("schedule row differs from frozen request")
    return protocol, rows, schedule
