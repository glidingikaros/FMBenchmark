from __future__ import annotations

import hashlib
import json

from fmb.generation import pilot_profile

PROFILE = pilot_profile.PROFILE

def build_plan(seed: int, *, shellbag_input: dict, profile: str = PROFILE, pilot_parameters: dict | None = None) -> dict:
    if profile != PROFILE:
        raise ValueError('only the paper construction is supported')
    case_classes = pilot_profile.resolve_parameters(pilot_parameters)['case_classes']

    def token(key: str) -> str:
        namespace = f"factual-challenge.v1:{profile}"
        return hashlib.sha256(f"{namespace}:{seed}:{key}".encode()).hexdigest()[:12]
    root = "C:\\Users\\vagrant\\Documents\\r_" + token("root")
    members = []
    for qid, classes in case_classes.items():
        for index, kind in enumerate(classes):
            suffix = ".exe" if qid == "BQ-EXEC-01" else ".bmp" if qid == "BQ-FILE-01" and kind != "preallocation_then_close" else ".txt"
            if qid in {"BQ-SHELLBAG-01", "BQ-DIRECTORY-01"}:
                suffix = ""
            path = root + "\\f_" + token(qid + ":" + str(index)) + suffix
            members.append({"question_id": qid, "path": path, "operation_class": kind,
                            "alternative_path": root + "\\f_" + token(qid + ":alt:" + str(index)) + suffix})
    pilot_profile.decorate_members(members, token, pilot_parameters)
    public = {"schema_version": "factual_challenge_population.v1", "profile": profile,
              "root": root, "members": [{"question_id": r["question_id"], "path": r["path"]} for r in members]}
    digest = hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "factual_challenge_plan.v1", "profile": profile,
            "public_manifest": public, "public_manifest_sha256": digest, "members": members,
            "factual_helper": pilot_profile.packed_helper("pilot_challenge.ps1"),
            "shellbag_helper": {**pilot_profile.packed_helper("native_shellbag.ps1"),
                                "visit_budgets": shellbag_input["visit_budgets"]}}


def validate_receipt(plan: dict, receipt: dict) -> None:
    if plan.get('profile') != PROFILE:
        raise ValueError('unsupported factual construction')
    pilot_profile.validate_supplement(plan, receipt)
