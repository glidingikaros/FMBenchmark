from __future__ import annotations
from dataclasses import asdict


from datetime import datetime, timezone


import hashlib


import json


from pathlib import Path


import threading


import time


from fmb.interpretation import paper_payload


from fmb.interpretation.provider import call_llm


def settings_record(call_kwargs: dict, wire: dict, response: dict | None = None) -> dict:
    raw = response or {}
    sampling = {}
    for name in ("temperature", "top_p", "seed"):
        configured = call_kwargs.get(name)
        sent = wire.get(name)
        sampling[name] = {
            "configured": configured, "request_state": "sent" if sent is not None else "omitted",
            "sent_value": sent,
            "provider_reported_value": raw.get(name),
            "provider_value_available": name in raw,
            "unreported_default": "unknown" if name not in raw and sent is None else None,
        }
        if configured is not None and sent != configured:
            raise ValueError(f"configured {name} differs from serialized request")
    return {
        "requested_model": call_kwargs["model"], "served_model": raw.get("model"),
        "provider": call_kwargs["provider"], "base_url": call_kwargs.get("base_url"),
        "requested_route": call_kwargs.get("route"), "served_provider": raw.get("provider"),
        "provider_request_id": raw.get("id"), "system_fingerprint": raw.get("system_fingerprint"),
        "sampling": sampling,
        "requested_reasoning_effort": call_kwargs.get("reasoning_effort"),
        "wire_reasoning": wire.get("reasoning"), "provider_reported_reasoning": raw.get("reasoning"),
        "maximum_output_tokens": call_kwargs.get("max_output_tokens"),
        "timeout_seconds": call_kwargs.get("timeout_seconds"),
        "structured_output": call_kwargs.get("structured_output"),
        "usage_as_returned": raw.get("usage"),
        "effort_comparability": "provider-specific labels; acceptance alone does not establish equivalent compute",
    }


class AuditedProviderCall:
    def __init__(self, directory: Path, delegate=call_llm):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.delegate = delegate
        self.lock = threading.Lock()
        self.count = 0

    def __call__(self, **kwargs):
        body = paper_payload.wire(kwargs)
        wire = json.loads(body)
        before = settings_record(kwargs, wire)
        with self.lock:
            self.count += 1
            folder = self.directory / f"attempt-{self.count:04d}"
            folder.mkdir()
        (folder / "request-body.json").write_bytes(body)
        started = datetime.now(timezone.utc).isoformat()
        monotonic = time.monotonic()
        record = {"schema_version": "model_attempt_audit.v1", "started_utc": started,
                  "request_body_sha256": hashlib.sha256(body).hexdigest(), "request_bytes": len(body),
                  "settings": before}
        (folder / "started.json").write_text(json.dumps(record, indent=2) + "\n")
        try:
            result = self.delegate(**kwargs)
        except BaseException as error:
            record.update(status="failed", error_type=type(error).__name__, error=str(error))
            raise
        else:
            (folder / "response.json").write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False) + "\n")
            record.update(status="returned", settings=settings_record(kwargs, wire, result.raw_response))
            return result
        finally:
            record.update(finished_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic()-monotonic)
            (folder / "finished.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")


