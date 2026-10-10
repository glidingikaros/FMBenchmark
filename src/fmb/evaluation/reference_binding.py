from __future__ import annotations
from collections.abc import Mapping


from typing import Any


from fmb.analysis.inputs import canonical_sha256


def _required_text(value: Mapping[str, Any], key: str, *, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{label} {key} must be a non-empty string")
    return item


def _population_candidate_subject_ids(
    analysis_inputs: Any,
    evidence_index: Mapping[str, Any],
    public_manifest: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    raw_populations = evidence_index.get("candidate_populations")
    if not isinstance(raw_populations, list) or any(
        not isinstance(item, Mapping) for item in raw_populations
    ):
        raise ValueError("generated evidence index has no candidate populations")
    populations: dict[tuple[str, str], Mapping[str, Any]] = {}
    for item in raw_populations:
        scope = (
            _required_text(item, "question_id", label="candidate population"),
            _required_text(item, "technique_id", label="candidate population"),
        )
        if scope in populations:
            raise ValueError("generated evidence index repeats a population scope")
        populations[scope] = item
    inputs = {(item.question_id, item.technique_id): item for item in analysis_inputs}
    if len(inputs) != len(analysis_inputs):
        raise ValueError("analysis inputs repeat a question/technique scope")
    result: dict[str, dict[str, str]] = {}
    raw_scenarios = public_manifest.get("scenarios")
    if not isinstance(raw_scenarios, Mapping):
        raise ValueError("population manifest scenarios must be an object")
    scenarios_by_scope: dict[tuple[str, str], tuple[str, Mapping[str, Any]]] = {}
    candidate_ids: set[str] = set()
    for scenario_id, raw_scenario in raw_scenarios.items():
        if not isinstance(scenario_id, str) or not isinstance(raw_scenario, Mapping):
            raise ValueError("population manifest scenario is invalid")
        scope = (
            _required_text(raw_scenario, "question_id", label=scenario_id),
            _required_text(raw_scenario, "technique_id", label=scenario_id),
        )
        if scope in scenarios_by_scope:
            raise ValueError("population manifest repeats a question/technique scope")
        scenarios_by_scope[scope] = (scenario_id, raw_scenario)
        members = raw_scenario.get("members")
        if not isinstance(members, list) or any(
            not isinstance(item, Mapping) for item in members
        ):
            raise ValueError(f"population manifest members are invalid: {scenario_id}")
        for member in members:
            candidate_id = _required_text(member, "candidate_id", label=scenario_id)
            if candidate_id in candidate_ids:
                raise ValueError(
                    f"population candidate ID is duplicated: {candidate_id}"
                )
            candidate_ids.add(candidate_id)
    if not set(populations).issubset(scenarios_by_scope) or not set(inputs).issubset(populations):
        raise ValueError(
            "generated candidate population scopes do not match the public manifest"
        )
    if not set(inputs).issubset(scenarios_by_scope):
        raise ValueError("analysis input scope is absent from the public population")

    for scope, analysis_input in inputs.items():
        scenario_id, raw_scenario = scenarios_by_scope[scope]
        population = populations.get(scope)
        if population is None or population.get("coverage_status") != "complete":
            raise ValueError(f"generated population is incomplete for {scenario_id}")
        members = raw_scenario.get("members")
        subjects = population.get("subjects")
        if (
            not isinstance(members, list)
            or not isinstance(subjects, list)
            or len(members) != len(subjects)
            or any(not isinstance(item, Mapping) for item in members)
            or any(not isinstance(item, Mapping) for item in subjects)
        ):
            raise ValueError(f"generated population does not match {scenario_id}")
        roster_by_identity = {
            canonical_sha256(subject.identity): subject.subject_id
            for subject in analysis_input.candidate_roster.subjects
        }
        if len(roster_by_identity) != len(analysis_input.candidate_roster.subjects):
            raise ValueError(f"analysis roster identity is ambiguous: {scenario_id}")
        candidate_map: dict[str, str] = {}
        mapped_subject_ids: list[str] = []
        for member, subject in zip(members, subjects, strict=True):
            candidate_id = _required_text(member, "candidate_id", label=scenario_id)
            if member.get("subject_ref") != subject.get("subject_ref"):
                raise ValueError(
                    f"generated population subject order does not match {scenario_id}"
                )
            identity = subject.get("identity")
            if not isinstance(identity, Mapping):
                raise ValueError(
                    f"generated population identity is invalid: {scenario_id}"
                )
            subject_id = roster_by_identity.get(canonical_sha256(dict(identity)))
            if subject_id is None:
                raise ValueError(
                    f"generated population is not bound to the analysis roster: {scenario_id}"
                )
            if candidate_id in candidate_map:
                raise ValueError(
                    f"population candidate ID is duplicated: {candidate_id}"
                )
            candidate_map[candidate_id] = subject_id
            mapped_subject_ids.append(subject_id)
        roster_ids = analysis_input.candidate_roster.subject_ids()
        if (
            len(mapped_subject_ids) != len(roster_ids)
            or len(set(mapped_subject_ids)) != len(mapped_subject_ids)
            or set(mapped_subject_ids) != set(roster_ids)
        ):
            raise ValueError(
                f"generated population is not a bijection with the roster: {scenario_id}"
            )
        result[scenario_id] = candidate_map
    return result

