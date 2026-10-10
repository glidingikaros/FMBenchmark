from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceCoverage:
    artifact_family: str
    status: str
    scope: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Observation:
    observation_id: str
    artifact_family: str
    observation_type: str
    subject_ref: str
    fields: dict[str, Any]
    source_record_ref: str


@dataclass(frozen=True)
class CandidateSubject:
    subject_id: str
    subject_type: str
    display_name: str
    identity: dict[str, str]
    observation_ids: tuple[str, ...]


@dataclass(frozen=True)
class CandidateRoster:
    roster_id: str
    question_id: str
    technique_id: str
    evidence_index_id: str
    evidence_index_hash: str
    subjects: tuple[CandidateSubject, ...]
    coverage_status: str
    roster_sha256: str

    def subject_ids(self) -> tuple[str, ...]:
        return tuple(subject.subject_id for subject in self.subjects)


@dataclass(frozen=True)
class AnalysisInput:
    schema_version: str
    input_id: str
    question_id: str
    question_title: str
    question_text: str
    technique_id: str
    claim_boundary: str
    evidence_index_ref: str
    evidence_index_sha256: str
    candidate_roster: CandidateRoster
    required_artifact_families: tuple[str, ...]
    optional_artifact_families: tuple[str, ...]
    coverage: tuple[EvidenceCoverage, ...]
    observations: tuple[Observation, ...]
    projected_observation_ids: tuple[str, ...]
    readiness: str
    input_sha256: str


@dataclass(frozen=True)
class SupportedSubjects:
    subject_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        canonical = tuple(sorted(set(self.subject_ids)))
        if self.subject_ids != canonical:
            raise ValueError("supported subjects must be sorted and unique")


@dataclass(frozen=True)
class SubjectAssessment:
    subject_id: str
    outcome: str
    reason_code: str
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    question_id: str
    technique_id: str
    subject_id: str
    outcome: str
    summary: str
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class DeterministicResult:
    schema_version: str
    deterministic_result_id: str
    input_id: str
    input_sha256: str
    roster_sha256: str
    question_id: str
    technique_id: str
    status: str
    reviewed_subject_ids: tuple[str, ...]
    supported_subjects: SupportedSubjects
    assessments: tuple[SubjectAssessment, ...]
    findings: tuple[Finding, ...]
    coverage_gaps: tuple[str, ...]
    analyzer_metadata: dict[str, Any]
    truth_sources_used: tuple[str, ...] = field(default_factory=tuple)
