import json
import time
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import now, write_json


def collect(args, *, profile: dict):
    from fmb.collection.analysis import collect_evidence_index

    started = now()
    clock_started = time.monotonic()
    timing_path = args.output.with_name(args.output.name + "-timing.json")
    if timing_path.exists():
        raise ValueError("this collection timing record already exists")
    timing = {
        "status": "running",
        "started_utc": started,
        "scope": "host collection, parser VM, native supplemental preparation",
    }
    write_json(timing_path, timing)
    primary_error = None
    try:
        index = collect_evidence_index(
            args.evidence,
            profile=profile,
            output_dir=args.output,
            run_id=args.output.name,
            windows_parsers=args.windows_parsers,
            host_toolchain_root=args.host_toolchain_root,
            vm_work_root=getattr(args, "vm_work_root", None),
        )
    except BaseException as error:
        primary_error = error
        timing.update(
            status="failed", error_type=type(error).__name__, error=str(error)
        )
        raise
    else:
        timing["status"] = "completed"
    finally:
        timing.update(
            finished_utc=now(), elapsed_seconds=time.monotonic() - clock_started
        )
        try:
            write_json(timing_path, timing)
        except BaseException as record_error:
            if primary_error is None:
                raise
            primary_error.add_note(
                f"Failed to write final collection timing record {timing_path}: "
                f"{type(record_error).__name__}: {record_error}"
            )
    write_json(args.output / "evidence_index.json", index)
    write_json(
        args.output / "factual-collection.json",
        {
            "status": "completed",
            "started_utc": started,
            "finished_utc": now(),
            "evidence_index_sha256": sha256_file(args.output / "evidence_index.json"),
            "evidence": str(args.evidence.resolve()),
            "truth_sources_used": [],
        },
    )
    print(json.dumps({"status": "collected", "output": str(args.output)}), flush=True)
