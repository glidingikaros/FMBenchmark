from __future__ import annotations

from datetime import datetime, timezone
import base64
import gzip
import hashlib
from pathlib import Path

PROFILE = "pilot_min.v1"
DAY_FILETIME = 864_000_000_000
PILOT_YEAR = 2026
CASE_CLASSES = {
    "BQ-TIME-01": ("same_year", "old_copy", "old_copy", "forward", "forward", "access_only"),
    "BQ-DELETE-01": ("deleted", "recreated", "entry_reused"),
    "BQ-EXEC-01": ("renamed", "recreated"),
    "BQ-SHELLBAG-01": ("deleted", "renamed", "recreated", "present_case"),
    "BQ-DIRECTORY-01": ("recreated_children", "renamed_children", "moved_children"),
    "BQ-STREAM-01": ("second_pe", "signature_decoy", "empty_zip"),
    "BQ-FILE-01": ("append_four", "valid_bmp"),
}
PARAMETERS_SCHEMA = "native_pilot_parameters.v1"
DEFAULT_CHILD_COUNT = 80
CHILD_OPERATION_INDEX = 13
MINIMUM_CHILD_COUNT = 22
DEFAULT_TIMESTAMP_DELTAS = {
    "same_year": {"creation_filetime": -14 * DAY_FILETIME - 1,
                  "modified_filetime": -14 * DAY_FILETIME - 1},
    "forward": {"modified_filetime": DAY_FILETIME},
    "access_only": {"access_filetime": -DAY_FILETIME},
    "old_copy": {},
}
_DELTA_FIELDS = {"forward": ("modified_filetime", 1), "access_only": ("access_filetime", -1)}


def is_pilot(contract: dict) -> bool:
    return contract.get("native_pilot_profile") == PROFILE


def validate_parameters(value) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != PARAMETERS_SCHEMA:
        raise ValueError("unsupported native pilot parameters")
    if set(value) - {"schema_version", "image_label", "case_classes", "directory_child_count", "timestamp_deltas"}:
        raise ValueError("native pilot parameters carry an unregistered field")
    if "image_label" in value and (not isinstance(value["image_label"], str) or not value["image_label"]):
        raise ValueError("native pilot image label is invalid")
    classes = value.get("case_classes")
    if classes is not None:
        if not isinstance(classes, dict) or not classes or set(classes) - set(CASE_CLASSES):
            raise ValueError("native pilot class selection names an unregistered question")
        for qid, kinds in classes.items():
            if not isinstance(kinds, list) or not kinds or any(not isinstance(kind, str) for kind in kinds):
                raise ValueError("native pilot class selection is invalid")
            if any(kinds.count(kind) > CASE_CLASSES[qid].count(kind) for kind in kinds):
                raise ValueError("native pilot class selection exceeds the released construction")
    count = value.get("directory_child_count")
    if count is not None and (type(count) is not int
                              or not max(MINIMUM_CHILD_COUNT, CHILD_OPERATION_INDEX + 1) <= count <= DEFAULT_CHILD_COUNT):
        raise ValueError("native pilot directory child count is outside its bounds")
    deltas = value.get("timestamp_deltas")
    if deltas is not None:
        if not isinstance(deltas, dict) or set(deltas) - set(_DELTA_FIELDS):
            raise ValueError("native pilot timestamp deltas name an unregistered control")
        for kind, fields in deltas.items():
            field, sign = _DELTA_FIELDS[kind]
            if (not isinstance(fields, dict) or set(fields) != {field} or type(fields[field]) is not int
                    or fields[field] * sign <= 0 or abs(fields[field]) > 400 * DAY_FILETIME
                    or fields[field] % 256 == 0):
                raise ValueError("native pilot control delta is invalid")


def resolve_parameters(value=None) -> dict:
    if value is not None:
        validate_parameters(value)
    value = value or {}
    deltas = {kind: dict(fields) for kind, fields in DEFAULT_TIMESTAMP_DELTAS.items()}
    for kind, fields in (value.get("timestamp_deltas") or {}).items():
        deltas[kind] = dict(fields)
    classes = value.get("case_classes")
    return {
        "case_classes": ({qid: tuple(kinds) for qid, kinds in classes.items()} if classes is not None
                         else dict(CASE_CLASSES)),
        "directory_child_count": value.get("directory_child_count", DEFAULT_CHILD_COUNT),
        "timestamp_deltas": deltas,
    }


def parameters_for_manifest(manifest) -> dict | None:
    from fmb.generation import population as population_support
    return population_support._contract_for_manifest(manifest).get("native_pilot_parameters")


def packed_helper(name: str) -> dict:
    source = (Path(__file__).parent / "ansible/roles/manipulation/files" / name).read_bytes()
    return {"native_helper_payload": base64.b64encode(gzip.compress(source, mtime=0)).decode(),
            "native_helper_sha256": hashlib.sha256(source).hexdigest()}


def media_layout(seed: int) -> list[dict]:
    result = []
    for index, port in enumerate((5, 3, 2)):
        token = hashlib.sha256(f"{PROFILE}:media:{seed}:{index}".encode()).hexdigest()[:12]
        result.append({
            "subject_ref": "virtual-usb:" + token,
            "binding_file": f"media_{token}.json",
            "companion_file": f"media_{token}.vmdk",
            "source_file": f"media_{token}_source.vmdk",
            "unit": 8 + index, "port": port, "disk_size_bytes": 67_108_864,
        })
    return result


def decorate_members(members: list[dict], token, parameters=None) -> None:
    resolved = resolve_parameters(parameters)
    for index, member in enumerate(members):
        kind, qid = member["operation_class"], member["question_id"]
        if qid == "BQ-STREAM-01":
            member["stream_names"] = sorted("n_" + token(f"stream:{index}:{n}") for n in range(2))
        if kind == "entry_reused":
            member["reuse_attempt_limit"] = 256
        if kind == "old_copy":
            member["copy_source"] = r"C:\Windows\System32\where.exe"
        if qid == "BQ-DIRECTORY-01":
            member["child_names"] = [f"f_{n:02d}" + (token(f"child:{index}:{n}") * 4)[:46] + ".txt"
                                     for n in range(resolved["directory_child_count"])]
            member["child_operation_index"] = CHILD_OPERATION_INDEX
        if qid == "BQ-TIME-01":
            member["timestamp_deltas"] = dict(resolved["timestamp_deltas"][kind])


def adjust_guest_plan(plan: dict, public: dict, contract: dict) -> dict:
    if not is_pilot(contract):
        return plan
    if set(public["scenarios"]) != set(contract["experiments"]["full_scale"]):
        raise ValueError("native pilot requires the complete fourteen-scenario population")
    inputs = plan["scenario_inputs"]
    if any(item["case"] != "positive" for item in inputs.values()):
        raise ValueError("native pilot is a mixed-component positive realization")
    plan["native_pilot_profile"] = PROFILE
    for item in inputs.values():
        item["native_pilot_profile"] = PROFILE
    time = inputs["timestomp_01"]
    time["timestamps"] = ["2026-09-02T10:17:23Z", "2025-08-11T13:29:41Z"]
    inputs["bitmap_trailing_data_01"]["bitmap_operations"][0]["byte_count"] = 1024
    typed = inputs["typed_path_residue_01"]
    typed["recreated_path"] = next(p for p in typed["population_paths"] if p not in typed["operation_refs"])
    layout = media_layout(public["population_seed"])
    inputs["usbstor_setupapi_discrepancy_01"]["native_helper"] = packed_helper("pilot_media_prepare.ps1")
    for sid in ("usbstor_setupapi_discrepancy_01", "usb_volume_activity_gap_01"):
        item = inputs[sid]
        item["media"] = []
        for index, volume in enumerate(layout):
            names = {}
            for name in ("file_name", "replacement_name", "before_name", "after_name", "shortcut_name"):
                token = hashlib.sha256(f"{PROFILE}:{public['population_seed']}:{index}:{name}".encode()).hexdigest()[:12]
                names[name] = "f_" + token + (".lnk" if name == "shortcut_name" else ".txt")
            item["media"].append({**volume, **names,
                "installation_discrepancy": volume["subject_ref"] in inputs["usbstor_setupapi_discrepancy_01"]["operation_refs"],
                "history_discrepancy": volume["subject_ref"] in inputs["usb_volume_activity_gap_01"]["operation_refs"],
            })
        for name in ("file_name", "replacement_name", "before_name", "after_name", "shortcut_name"):
            del item[name]
    clear = inputs["security_log_clear_event_01"]
    clear.update(case="benign", operation_refs=[], expected_operation_count=0)
    return plan


def _same_year(filetime: int, other: int) -> bool:
    epoch = 116_444_736_000_000_000
    return (datetime.fromtimestamp((filetime - epoch) / 10_000_000, timezone.utc).year
            == datetime.fromtimestamp((other - epoch) / 10_000_000, timezone.utc).year == PILOT_YEAR)


def validate_log_a_source(data: bytes) -> None:
    import xml.etree.ElementTree as ET
    from fmb.generation.event_sequence_injection import NS, _active_chunks
    from fmb.index.scanners.evtx_sequence import retained_record_ids
    identifiers = retained_record_ids(data)
    records = [r for chunk in _active_chunks(data) for r in chunk.records()]
    if tuple(r.record_num() for r in records) != identifiers:
        raise ValueError("pilot log inventory disagrees across native readers")
    for record in records:
        tree = ET.fromstring(record.xml())
        nodes = tree.findall("./e:System/e:EventID", NS)
        if len(nodes) != 1 or not nodes[0].text:
            raise ValueError("pilot log contains an unresolved native event identity")
        if int(nodes[0].text) == 1102:
            raise ValueError("pilot A inherited clearing evidence; preserve the realization")


def _validate_negative_timestamps(before: dict, after: dict) -> None:
    if any(type(state.get(field)) is not int for state in (before, after)
           for field in ("creation_filetime", "modified_filetime", "change_filetime")):
        raise ValueError("pilot negative timestamp control lacks complete native times")
    if any(after[field] != before[field] for field in ("creation_filetime", "modified_filetime")):
        raise ValueError("pilot negative timestamp control changed creation or modification time")
    if after["change_filetime"] < before["change_filetime"]:
        raise ValueError("pilot negative timestamp control moved metadata-change time backwards")


def validate_supplement(plan: dict, receipt: dict) -> None:
    if (receipt.get("schema_version") != "factual_challenge_receipt.v1"
            or receipt.get("public_manifest_sha256") != plan["public_manifest_sha256"]):
        raise ValueError("pilot receipt is not bound to its public population")
    expected = {r["path"]: r for r in plan["members"]}
    rows = receipt.get("members")
    if (not isinstance(rows, list) or len(rows) != len(expected)
            or {r.get("path") for r in rows} != set(expected)):
        raise ValueError("pilot receipt must cover every planned member exactly once")
    for row in rows:
        member = expected[row["path"]]
        kind, qid = member["operation_class"], member["question_id"]
        if row.get("operation_class") != kind or row.get("question_id") != qid or row.get("completed") is not True:
            raise ValueError("pilot operation does not match its frozen membership")
        before, after, alternative = row.get("before", {}), row.get("after", {}), row.get("alternative", {})
        if before.get("exists") is not True or not before.get("file_reference"):
            raise ValueError("pilot lacks the original native identity")
        if kind in {"deleted", "entry_reused"}:
            if after.get("exists") is not False:
                raise ValueError("pilot deletion retained its old path")
        elif kind == "renamed":
            if (after.get("exists") is not False or alternative.get("exists") is not True
                    or alternative.get("file_reference") != before["file_reference"]):
                raise ValueError("pilot rename did not preserve its original object")
        elif kind == "recreated":
            if after.get("exists") is not True or not after.get("file_reference") or after["file_reference"] == before["file_reference"]:
                raise ValueError("pilot recreation did not replace the old object")
        elif after.get("exists") is not True or after.get("file_reference") != before["file_reference"]:
            raise ValueError("pilot control did not preserve its object identity")
        witnesses = row.get("witnesses", [])
        if kind == "entry_reused":
            reuse = row.get("reuse", {})
            old_volume, old_ref = before["file_reference"].split(":")
            new_volume, new_ref = str(reuse.get("file_reference", ":")).split(":")
            if (old_volume != new_volume or not new_ref or old_ref == new_ref
                    or int(old_ref, 16) & ((1 << 48) - 1) != int(new_ref, 16) & ((1 << 48) - 1)
                    or type(reuse.get("attempt")) is not int
                    or not 1 <= reuse["attempt"] <= member["reuse_attempt_limit"]
                    or reuse.get("exists") is not True):
                raise ValueError("bounded pilot burst did not observe native entry reuse")
        if qid == "BQ-TIME-01":
            for field, delta in member["timestamp_deltas"].items():
                if type(before.get(field)) is not int or after.get(field) != before[field] + delta:
                    raise ValueError("pilot timestamp did not realize its frozen delta")
                if kind == "same_year" and not _same_year(before[field], after[field]):
                    raise ValueError("pilot same-year operation crossed the frozen calendar year")
            if before.get("sha256") != after.get("sha256") or not before.get("sha256"):
                raise ValueError("timestamp operation changed content or lacks readback hashes")
            if kind in {"access_only", "old_copy"}:
                _validate_negative_timestamps(before, after)
            if kind == "old_copy":
                source = row.get("copy_source", {})
                if (source.get("path") != member["copy_source"] or source.get("exists") is not True
                        or source.get("sha256") != before["sha256"]
                        or source.get("modified_filetime") != before.get("modified_filetime")
                        or datetime.fromtimestamp((source.get("modified_filetime", 0) - 116_444_736_000_000_000)
                                                  / 10_000_000, timezone.utc).year >= PILOT_YEAR):
                    raise ValueError("pilot old-copy control lacks unchanged old source metadata")
        if qid == "BQ-FILE-01":
            if after.get("length") != before.get("length", 0) + (4 if kind == "append_four" else 0):
                raise ValueError("pilot bitmap did not realize its exact byte count")
        if qid == "BQ-DIRECTORY-01":
            planned_children = len(member["child_names"])
            if (len(witnesses) != planned_children
                    or len({r.get("file_reference") for r in witnesses}) != planned_children):
                raise ValueError("pilot directory child identities are incomplete")
            transition = row.get("child_transition", {})
            old = witnesses[member["child_operation_index"]]
            current = transition.get("after", {})
            moved = transition.get("alternative", {})
            if transition.get("before") != old:
                raise ValueError("pilot directory transition is bound to another child")
            if kind == "recreated_children":
                if current.get("exists") is not True or not current.get("file_reference") or current["file_reference"] == old["file_reference"]:
                    raise ValueError("pilot child replacement lacks its distinct native identity")
            elif current.get("exists") is not False or moved.get("file_reference") != old["file_reference"] or moved.get("exists") is not True:
                raise ValueError("pilot child rename/move did not preserve its identity")
        if qid == "BQ-STREAM-01":
            expected_names = member["stream_names"] if kind == "second_pe" else member["stream_names"][:1]
            if [r.get("stream_name") for r in witnesses] != expected_names:
                raise ValueError("pilot stream readback does not cover the frozen names/order")
            if any(type(r.get("length")) is not int or not isinstance(r.get("sha256"), str)
                   or len(r["sha256"]) != 64 for r in witnesses):
                raise ValueError("pilot stream bytes lack complete native readback")
            if kind == "empty_zip" and witnesses[0]["length"] != 22:
                raise ValueError("pilot empty ZIP was not the complete empty ZIP32 representation")
            if kind == "signature_decoy" and witnesses[0]["length"] != 8:
                raise ValueError("pilot truncated MZ control differs from its frozen bytes")
            if kind == "second_pe" and witnesses[1]["length"] < 512:
                raise ValueError("pilot second PE stream is incomplete")


def validate_materialization(plan: dict, initial: dict, final: dict) -> None:
    if (initial.get("schema_version") != "native_pilot_materialization.v1"
            or initial.get("public_manifest_sha256") != plan["public_manifest_sha256"]):
        raise ValueError("pilot initial receipt belongs to another population")
    expected = {row["path"] for row in plan["members"]}
    rows = initial.get("members", [])
    if len(rows) != len(expected) or {row.get("path") for row in rows} != expected:
        raise ValueError("pilot initial receipt omits or repeats a member")
    by_path = {row["path"]: row for row in rows}
    for row in final["members"]:
        before = by_path[row["path"]]
        if (before.get("state", {}).get("exists") is not True
                or before["state"].get("file_reference") != row["before"]["file_reference"]):
            raise ValueError("pilot member changed identity before its scheduled operation")
        if row["operation_class"] in {"access_only", "old_copy"}:
            _validate_negative_timestamps(before["state"], row["before"])
        if row["operation_class"] == "old_copy":
            if (before.get("copy_source") != row.get("copy_source")
                    or any(before["state"].get(key) != row["before"].get(key)
                           for key in ("sha256", "length"))):
                raise ValueError("pilot old copy changed after initial materialization")
