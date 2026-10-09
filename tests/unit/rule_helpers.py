from fmb.analysis.deterministic import ANALYZERS, ANALYZER_VERSION, LOGFILE_TRANSITION_REASON
from fmb.analysis.domain import AnalysisInput, DeterministicResult, SubjectAssessment, SupportedSubjects, Finding
from fmb.analysis.inputs import assert_analysis_input_integrity, canonical_sha256
from fmb.analysis.catalog import sufficient_family_sets, technique_definition

def _result_id(value: AnalysisInput) -> str:
    digest = canonical_sha256(
        {
            "input_sha256": value.input_sha256,
            "roster_sha256": value.candidate_roster.roster_sha256,
            "technique_id": value.technique_id,
            "analyzer_version": ANALYZER_VERSION,
        }
    )
    return f"deterministic-result:{digest[:24]}"


def analyze_input(value: AnalysisInput) -> DeterministicResult:
    assert_analysis_input_integrity(value)
    coverage_by_family = {item.artifact_family: item.status for item in value.coverage}
    definition = technique_definition(value.technique_id)
    family_sets = (
        sufficient_family_sets(definition)
        if definition is not None
        else (tuple(value.required_artifact_families),)
    )
    satisfied = any(
        all(coverage_by_family.get(family) == "complete" for family in family_set)
        for family_set in family_sets
    )
    missing = (
        ()
        if satisfied
        else tuple(
            family
            for family in value.required_artifact_families
            if coverage_by_family.get(family) != "complete"
        )
    )
    reviewed_ids = value.candidate_roster.subject_ids()
    metadata = {"analyzer_id": value.technique_id, "version": ANALYZER_VERSION}
    if value.readiness != "ready" or missing:
        return DeterministicResult(
            schema_version="deterministic_result.v1",
            deterministic_result_id=_result_id(value),
            input_id=value.input_id,
            input_sha256=value.input_sha256,
            roster_sha256=value.candidate_roster.roster_sha256,
            question_id=value.question_id,
            technique_id=value.technique_id,
            status="insufficient_evidence",
            reviewed_subject_ids=reviewed_ids,
            supported_subjects=SupportedSubjects(),
            assessments=tuple(
                SubjectAssessment(
                    subject_id=subject.subject_id,
                    outcome="indeterminate",
                    reason_code="required_evidence_incomplete",
                    evidence_refs=subject.observation_ids,
                    limitations=("required artifact coverage is incomplete",),
                )
                for subject in value.candidate_roster.subjects
            ),
            findings=(),
            coverage_gaps=missing,
            analyzer_metadata=metadata,
        )
    try:
        analyzer = ANALYZERS[value.technique_id]
    except KeyError as error:
        raise ValueError(
            f"no deterministic analyzer for {value.technique_id}"
        ) from error
    decisions = tuple(
        (subject, analyzer(value, subject))
        for subject in value.candidate_roster.subjects
    )
    supported_ids = tuple(
        sorted(
            subject.subject_id
            for subject, decision in decisions
            if decision.outcome == "supported"
        )
    )
    timestamp_routes = {
        "coordinated_si_backdating_with_temporal_basic_info_change": "immediate_usn",
        "si_fn_backdating_with_later_basic_info_change": "late_usn",
        LOGFILE_TRANSITION_REASON: "logfile_si_transition",
    }
    metadata["support_routes"] = {
        subject.subject_id: timestamp_routes.get(decision.reason_code, decision.reason_code)
        for subject, decision in decisions if decision.outcome == "supported"
    }
    assessments = tuple(
        SubjectAssessment(
            subject_id=subject.subject_id,
            outcome=decision.outcome,
            reason_code=decision.reason_code,
            evidence_refs=tuple(sorted(set(decision.evidence_refs))),
            limitations=decision.limitations,
        )
        for subject, decision in decisions
    )
    findings = tuple(
        Finding(
            finding_id=f"finding:{value.technique_id}:{subject.subject_id.split(':', 1)[1]}",
            question_id=value.question_id,
            technique_id=value.technique_id,
            subject_id=subject.subject_id,
            outcome="supported",
            summary=f"{decision.reason_code.replace('_', ' ')}: {subject.display_name}",
            evidence_refs=tuple(sorted(set(decision.evidence_refs))),
            limitations=(value.claim_boundary, *decision.limitations),
        )
        for subject, decision in decisions
        if decision.outcome == "supported"
    )
    return DeterministicResult(
        schema_version="deterministic_result.v1",
        deterministic_result_id=_result_id(value),
        input_id=value.input_id,
        input_sha256=value.input_sha256,
        roster_sha256=value.candidate_roster.roster_sha256,
        question_id=value.question_id,
        technique_id=value.technique_id,
        status="completed",
        reviewed_subject_ids=reviewed_ids,
        supported_subjects=SupportedSubjects(supported_ids),
        assessments=assessments,
        findings=findings,
        coverage_gaps=(),
        analyzer_metadata=metadata,
    )

