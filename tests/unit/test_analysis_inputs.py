from __future__ import annotations

from dataclasses import replace

import pytest

from fmb.analysis.catalog import (
    TECHNIQUES,
    techniques_for_question,
)
from fmb.analysis.domain import CandidateSubject, Observation
from fmb.analysis.inputs import (
    active_mft_presence_fact,
    analysis_input_payload,
    assert_analysis_input_integrity,
    build_analysis_input,
    candidate_roster_payload,
    canonical_sha256,
    is_typed_paths_fields,
    setupapi_identity_lookup,
)


def parser_run(
    parser_kind: str, observations: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "parser_kind": parser_kind,
        "status": "consumed",
        "coverage_status": "complete",
        "observations": observations,
    }


def test_catalog_maps_original_targets_to_distinct_bounded_criteria() -> None:
    techniques = TECHNIQUES

    assert len({item.question_id for item in techniques}) == 10
    assert len(techniques) == 14
    assert [item.technique_id for item in techniques_for_question("Q-EXEC-01")] == [
        "prefetch_missing_executable",
        "shimcache_path_residue",
    ]


def test_timestomp_requires_mft_and_same_object_usn_corroboration() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]

    assert definition.required_artifact_families == ("ntfs.mft", "ntfs.usn")
    assert definition.optional_artifact_families == ("ntfs.logfile",)


def test_aligned_claim_boundaries_preserve_evidence_and_intent_limits() -> None:
    definitions = {
        item.technique_id: item for item in TECHNIQUES
    }
    required_phrases = {
        "i30_directory_residue": (
            "exact referenced object",
            "index-allocation stream with its bitmap",
            "incomplete scans are insufficient",
        ),
        "alternate_data_stream": (
            "complete PE image or a complete bounded ZIP archive",
            "Names, rarity, entropy and intended use do not decide",
            "A valid backup ZIP also satisfies it",
            "not execution, malicious intent or unauthorized concealment",
        ),
        "ntfs_allocation_inconsistency": (
            "Normal cluster rounding and preallocation are consistent",
            "special storage modes",
        ),
        "event_record_sequence_gap": (
            "complete unfiltered retained-log",
            "sequence discontinuity only",
        ),
        "shellbag_missing_directory": (
            "native SBECmd Directory",
            "Virtual shell namespace items, TypedPaths",
        ),
    }
    for technique_id, phrases in required_phrases.items():
        for phrase in phrases:
            assert phrase in definitions[technique_id].claim_boundary


def test_input_hashes_roster_with_explicit_complete_zero_observation_parsers() -> None:
    definition = techniques_for_question("Q-HIDE-01")[0]
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "run-1",
        "parser_runs": [
            parser_run("ntfs_ads", []),
            parser_run("ntfs_mft", []),
        ],
    }

    first = build_analysis_input(evidence_index, definition)
    second = build_analysis_input(evidence_index, definition)

    assert {item.artifact_family: item.status for item in first.coverage} == {
        "ntfs.ads": "complete",
        "ntfs.mft": "complete",
    }
    assert first.candidate_roster.subjects == ()
    assert first.candidate_roster.roster_sha256 == second.candidate_roster.roster_sha256
    assert first.input_sha256 == second.input_sha256


def test_parser_run_without_an_explicit_coverage_declaration_is_not_complete() -> None:
    definition = techniques_for_question("Q-HIDE-01")[0]
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "undeclared-parser-coverage",
            "parser_runs": [
                {
                    "parser_kind": "ntfs_ads",
                    "status": "consumed",
                    "observations": [],
                },
                {
                    "parser_kind": "ntfs_mft",
                    "status": "consumed",
                    "observations": [],
                },
            ],
        },
        definition,
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage} == {
        "ntfs.ads": "partial",
        "ntfs.mft": "partial",
    }
    assert analysis_input.readiness == "insufficient_evidence"


@pytest.mark.parametrize(
    "forbidden_payload",
    [
        {"ground_truth": {"offenders": ["subject:x"]}},
        {"parser_runs": [], "matched_ground_truth": True},
        {"parser_runs": [], "ground_truth_expectations": {"path": "x"}},
        {"parser_runs": [], "expected_path": r"C:\truth.txt"},
        {"parser_runs": [], "candidate_role": "offender"},
        {"parser_runs": [], "is_offender": True},
        {"parser_runs": [], "supported_subject_ids": ["subject:x"]},
        {"parser_runs": [], "expected_supported_subject_ids": ["subject:x"]},
        {"parser_runs": [{"observations": [{"fields": {"missing_binary": True}}]}]},
        {"parser_runs": [], "expected_offender_subject_ids": ["subject:x"]},
        {
            "parser_runs": [
                {
                    "parser_kind": "ntfs_mft",
                    "truth_sources_used": ["labels.json"],
                    "observations": [],
                }
            ]
        },
    ],
)
def test_input_builder_rejects_truth_bearing_evidence(
    forbidden_payload: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="truth-bearing"):
        build_analysis_input(
            {"schema_version": "evidence_index.v1", **forbidden_payload},
            techniques_for_question("Q-TIME-01")[0],
        )


def test_input_builder_rejects_generation_control_markers_before_analysis() -> None:
    with pytest.raises(
        ValueError,
        match="generation-control marker.*operation_refs",
    ):
        build_analysis_input(
            {
                "schema_version": "evidence_index.v1",
                "run_id": "generation-control-leak",
                "collection_note": "$input.operation_refs",
                "parser_runs": [
                    parser_run("ntfs_mft", []),
                    parser_run("ntfs_usn", []),
                ],
            },
            techniques_for_question("Q-TIME-01")[0],
        )


def test_input_builder_allows_operational_expected_fields() -> None:
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "operational-expectations",
            "sha256_expected": "a" * 64,
            "expected_artifact_families": ["ntfs.mft", "ntfs.usn"],
            "parser_runs": [
                parser_run("ntfs_mft", []),
                parser_run("ntfs_usn", []),
            ],
        },
        techniques_for_question("Q-TIME-01")[0],
    )

    assert analysis_input.readiness == "ready"


def test_input_builder_allows_only_false_ground_truth_allowed_safety_flag() -> None:
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "execution-envelope-safety",
        "collector_runs": [
            {
                "execution_envelope": {
                    "truth_firewall": {
                        "ground_truth_allowed": False,
                        "sha256_expected": "a" * 64,
                    }
                }
            }
        ],
        "parser_runs": [
            parser_run("ntfs_mft", []),
            parser_run("ntfs_usn", []),
        ],
    }

    assert (
        build_analysis_input(
            evidence_index, techniques_for_question("Q-TIME-01")[0]
        ).readiness
        == "ready"
    )

    evidence_index["collector_runs"][0]["execution_envelope"]["truth_firewall"][
        "ground_truth_allowed"
    ] = True
    with pytest.raises(ValueError, match="ground_truth_allowed"):
        build_analysis_input(evidence_index, techniques_for_question("Q-TIME-01")[0])


def test_analysis_input_integrity_covers_the_full_payload() -> None:
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "integrity",
            "parser_runs": [
                parser_run("ntfs_mft", []),
                parser_run("ntfs_usn", []),
            ],
        },
        techniques_for_question("Q-TIME-01")[0],
    )

    assert_analysis_input_integrity(analysis_input)
    tampered = replace(analysis_input, question_text="changed after preparation")
    with pytest.raises(ValueError, match="integrity hash"):
        assert_analysis_input_integrity(tampered)


def test_analysis_input_rejects_a_stale_nested_roster_hash() -> None:
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "nested-roster-integrity",
            "parser_runs": [
                parser_run("ntfs_mft", []),
                parser_run("ntfs_usn", []),
            ],
        },
        techniques_for_question("Q-TIME-01")[0],
    )
    stale_roster = replace(
        analysis_input.candidate_roster,
        coverage_status="partial",
    )
    unhashed = replace(
        analysis_input,
        input_id="",
        input_sha256="",
        candidate_roster=stale_roster,
    )
    outer_hash = canonical_sha256(analysis_input_payload(unhashed))
    tampered = replace(
        unhashed,
        input_id=f"input:{outer_hash[:24]}",
        input_sha256=outer_hash,
    )

    with pytest.raises(ValueError, match="candidate roster integrity hash"):
        assert_analysis_input_integrity(tampered)


def test_analysis_input_integrity_requires_exactly_one_owner_per_observation() -> None:
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "observation-ownership",
            "parser_runs": [
                parser_run(
                    "ntfs_mft",
                    [
                        {
                            "observation_id": "mft-1",
                            "artifact_family": "ntfs.mft",
                            "observation_type": "mft_file_record",
                            "subject_ref": r"C:\Users\alice\file.txt",
                            "fields": {"mismatch_count": 0},
                            "source_record_ref": "$MFT:1",
                        }
                    ],
                ),
                parser_run("ntfs_usn", []),
            ],
        },
        techniques_for_question("Q-TIME-01")[0],
    )
    subject = analysis_input.candidate_roster.subjects[0]
    unhashed_roster = replace(
        analysis_input.candidate_roster,
        roster_id="",
        roster_sha256="",
        subjects=(replace(subject, observation_ids=()),),
    )
    roster_hash = canonical_sha256(candidate_roster_payload(unhashed_roster))
    roster = replace(
        unhashed_roster,
        roster_id=f"roster:{roster_hash[:24]}",
        roster_sha256=roster_hash,
    )
    unhashed_input = replace(
        analysis_input,
        input_id="",
        input_sha256="",
        candidate_roster=roster,
    )
    input_hash = canonical_sha256(analysis_input_payload(unhashed_input))
    tampered = replace(
        unhashed_input,
        input_id=f"input:{input_hash[:24]}",
        input_sha256=input_hash,
    )

    with pytest.raises(ValueError, match="exactly one candidate subject"):
        assert_analysis_input_integrity(tampered)


def test_explicit_candidate_population_preserves_neutral_subjects() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    observation = {
        "observation_id": "mft-suspicious",
        "artifact_family": "ntfs.mft",
        "observation_type": "si_fn_timestamp_difference",
        "subject_ref": r"C:\suspicious.txt",
        "fields": {"mismatch_count": 3},
        "source_record_ref": "$MFT:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "explicit-population",
        "parser_runs": [
            parser_run("ntfs_mft", [observation]),
            parser_run("ntfs_usn", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:timestamp",
                "question_id": "Q-TIME-01",
                "technique_id": "timestamp_manipulation",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": r"C:\neutral.txt",
                        "identity": {"canonical_name": r"c:\neutral.txt"},
                        "observation_ids": [],
                    },
                    {
                        "subject_ref": r"C:\suspicious.txt",
                        "identity": {"canonical_name": r"c:\suspicious.txt"},
                        "observation_ids": ["mft-suspicious"],
                    },
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(evidence_index, definition)

    assert {
        subject.display_name: subject.observation_ids
        for subject in analysis_input.candidate_roster.subjects
    } == {
        r"C:\neutral.txt": (),
        r"C:\suspicious.txt": ("mft-suspicious",),
    }


def test_timestomp_population_is_not_ready_with_incomplete_mft_timestamps() -> None:
    observation = {
        "observation_id": "mft-incomplete",
        "artifact_family": "ntfs.mft",
        "observation_type": "mft_file_record",
        "subject_ref": r"C:\candidate.txt",
        "fields": {
            "si_created": "2026-01-01T00:00:00Z",
            "si_modified": "2026-01-01T00:00:00Z",
            "si_record_changed": "2026-01-01T00:00:00Z",
            "si_accessed": "2026-01-01T00:00:00Z",
            "fn_created": "",
            "fn_modified": "",
            "fn_record_changed": "",
            "fn_accessed": "",
        },
        "source_record_ref": "$MFT:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "incomplete-timestomp-card",
        "parser_runs": [
            parser_run("ntfs_mft", [observation]),
            parser_run("ntfs_usn", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:timestamp",
                "question_id": "Q-TIME-01",
                "technique_id": "timestamp_manipulation",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": r"C:\candidate.txt",
                        "identity": {"canonical_name": r"c:\candidate.txt"},
                        "observation_ids": ["mft-incomplete"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index, techniques_for_question("Q-TIME-01")[0]
    )

    assert analysis_input.readiness == "insufficient_evidence"
    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "partial"


def test_timestomp_population_is_not_ready_when_raw_mft_validation_failed() -> None:
    timestamp_fields = {
        field_name: "2026-01-01T00:00:00Z"
        for field_name in (
            "si_created",
            "si_modified",
            "si_record_changed",
            "si_accessed",
            "fn_created",
            "fn_modified",
            "fn_record_changed",
            "fn_accessed",
        )
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "failed-raw-mft-validation",
        "parser_runs": [
            parser_run(
                "ntfs_mft",
                [
                    {
                        "observation_id": "mft-unverified",
                        "artifact_family": "ntfs.mft",
                        "observation_type": "mft_file_record",
                        "subject_ref": r"C:\candidate.txt",
                        "fields": {
                            **timestamp_fields,
                            "raw_mft_timestamp_validation": "failed",
                        },
                        "source_record_ref": "$MFT:1",
                    }
                ],
            ),
            parser_run("ntfs_usn", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:timestamp",
                "question_id": "Q-TIME-01",
                "technique_id": "timestamp_manipulation",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": r"C:\candidate.txt",
                        "identity": {"canonical_name": r"c:\candidate.txt"},
                        "observation_ids": ["mft-unverified"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index, techniques_for_question("Q-TIME-01")[0]
    )

    assert analysis_input.readiness == "insufficient_evidence"
    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "partial"


@pytest.mark.parametrize(
    ("population_change", "message"),
    [
        ({"question_id": "Q-UNKNOWN"}, "unknown question/technique"),
        ({"technique_id": "unknown_technique"}, "unknown question/technique"),
        ({"subject_type": "device"}, "subject_type"),
        ({"coverage_status": "unknown"}, "coverage_status"),
    ],
)
def test_candidate_population_references_are_validated(
    population_change: dict[str, object], message: str
) -> None:
    population = {
        "population_id": "population:timestamp",
        "question_id": "Q-TIME-01",
        "technique_id": "timestamp_manipulation",
        "subject_type": "file",
        "coverage_status": "complete",
        "subjects": [],
        **population_change,
    }

    with pytest.raises(ValueError, match=message):
        build_analysis_input(
            {
                "schema_version": "evidence_index.v1",
                "run_id": "invalid-population",
                "parser_runs": [
                    parser_run("ntfs_mft", []),
                    parser_run("ntfs_usn", []),
                ],
                "candidate_populations": [population],
            },
            techniques_for_question("Q-TIME-01")[0],
        )


def test_candidate_population_rejects_duplicate_identities_and_unknown_observations() -> (
    None
):
    base_subject = {
        "subject_ref": r"C:\one.txt",
        "identity": {"canonical_name": r"c:\one.txt"},
        "observation_ids": [],
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "invalid-subjects",
        "parser_runs": [
            parser_run("ntfs_mft", []),
            parser_run("ntfs_usn", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:timestamp",
                "question_id": "Q-TIME-01",
                "technique_id": "timestamp_manipulation",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    base_subject,
                    {**base_subject, "subject_ref": r"C:\two.txt"},
                ],
            }
        ],
    }
    with pytest.raises(ValueError, match="duplicate subject identity"):
        build_analysis_input(evidence_index, techniques_for_question("Q-TIME-01")[0])

    evidence_index["candidate_populations"][0]["subjects"] = [
        {**base_subject, "observation_ids": ["missing-observation"]}
    ]
    with pytest.raises(ValueError, match="unknown observation_id"):
        build_analysis_input(evidence_index, techniques_for_question("Q-TIME-01")[0])


def test_candidate_population_observations_must_match_subject_identity() -> None:
    observation = {
        "observation_id": "mft-suspicious",
        "artifact_family": "ntfs.mft",
        "observation_type": "si_fn_timestamp_difference",
        "subject_ref": r"C:\suspicious.txt",
        "fields": {"mismatch_count": 3},
        "source_record_ref": "$MFT:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "misbound-population",
        "parser_runs": [
            parser_run("ntfs_mft", [observation]),
            parser_run("ntfs_usn", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:timestamp",
                "question_id": "Q-TIME-01",
                "technique_id": "timestamp_manipulation",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": r"C:\neutral.txt",
                        "identity": {"canonical_name": r"c:\neutral.txt"},
                        "observation_ids": ["mft-suspicious"],
                    }
                ],
            }
        ],
    }

    with pytest.raises(ValueError, match="does not match subject identity"):
        build_analysis_input(evidence_index, techniques_for_question("Q-TIME-01")[0])


def test_size_projection_cannot_satisfy_active_mft_coverage() -> None:
    definition = techniques_for_question("Q-DEL-01")[0]
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "run-coverage-role",
        "parser_runs": [
            {
                "parser_kind": "ntfs_usn",
                "status": "consumed",
                "coverage_status": "complete",
                "raw_outputs": [{"path": "$J"}],
                "observations": [],
            },
            {
                "parser_kind": "ntfs_file_size_allocation",
                "status": "consumed",
                "coverage_status": "complete",
                "raw_outputs": [{"path": "$MFT.csv"}],
                "observations": [],
            },
        ],
    }

    analysis_input = build_analysis_input(evidence_index, definition)

    assert analysis_input.readiness == "insufficient_evidence"
    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "missing"


def test_registry_population_uses_complete_per_path_mft_checks() -> None:
    observation = {
        "observation_id": "mru-path",
        "artifact_family": "windows.registry.typed_paths",
        "observation_type": "typed_path_seen",
        "subject_ref": r"C:\Users\vagrant\Desktop\candidate.txt",
        "fields": {
            "source_key": (
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
            ),
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "path_comparison",
            "mft_volume_id": "mft-source:test",
        },
        "source_record_ref": "registry.csv:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "registry-scoped-mft",
        "parser_runs": [
            {
                "parser_kind": "windows_typed_paths",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [observation],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:registry",
                "question_id": "Q-DEL-02",
                "technique_id": "typed_path_residue",
                "subject_type": "registry_path",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": "candidate.txt",
                        "identity": {
                            "canonical_name": (
                                r"c:\users\vagrant\desktop\candidate.txt"
                            )
                        },
                        "observation_ids": ["mru-path"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        techniques_for_question("Q-DEL-02")[0],
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "complete"
    assert analysis_input.readiness == "ready"


def test_typed_path_population_rejects_misclassified_registry_observation() -> None:
    path = r"C:\Users\vagrant\Desktop\candidate.txt"
    observation = {
        "observation_id": "misclassified-path",
        "artifact_family": "windows.registry.typed_paths",
        "observation_type": "shellbag_path_seen",
        "subject_ref": path,
        "fields": {
            "source_key": (
                r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer"
                r"\TypedPaths"
            ),
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "path_comparison",
            "mft_volume_id": "mft-source:test",
        },
        "source_record_ref": "registry.csv:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "registry-scoped-mft",
        "parser_runs": [
            parser_run("windows_typed_paths", [observation]),
            parser_run("ntfs_mft", []),
        ],
        "candidate_populations": [
            {
                "population_id": "population:registry",
                "question_id": "Q-DEL-02",
                "technique_id": "typed_path_residue",
                "subject_type": "registry_path",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": path,
                        "identity": {"canonical_name": path.casefold()},
                        "observation_ids": ["misclassified-path"],
                    }
                ],
            }
        ],
    }

    with pytest.raises(ValueError, match="outside the bounded claim"):
        build_analysis_input(
            evidence_index,
            techniques_for_question("Q-DEL-02")[0],
        )


def test_prefetch_population_uses_complete_per_path_mft_checks() -> None:
    path = r"C:\Users\vagrant\Desktop\candidate.exe"
    observation = {
        "observation_id": "prefetch-path",
        "artifact_family": "windows.prefetch",
        "observation_type": "prefetch_execution",
        "subject_ref": path,
        "fields": {
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_present",
            "mft_active_presence_basis": "path_comparison",
            "mft_volume_id": "mft-source:test",
        },
        "source_record_ref": "prefetch.csv:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "prefetch-scoped-mft",
        "parser_runs": [
            {
                "parser_kind": "windows_prefetch",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [observation],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:prefetch",
                "question_id": "Q-EXEC-01",
                "technique_id": "prefetch_missing_executable",
                "subject_type": "executable",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": "CANDIDATE.EXE",
                        "identity": {"canonical_name": path.casefold()},
                        "observation_ids": ["prefetch-path"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        next(
            item
            for item in techniques_for_question("Q-EXEC-01")
            if item.technique_id == "prefetch_missing_executable"
        ),
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "complete"
    assert analysis_input.readiness == "ready"


def test_shimcache_population_uses_complete_per_path_mft_checks() -> None:
    path = r"C:\Users\vagrant\Desktop\candidate.exe"
    observation = {
        "observation_id": "shimcache-path",
        "artifact_family": "windows.registry.shimcache",
        "observation_type": "shimcache_path_seen",
        "subject_ref": path,
        "fields": {
            "source_parser": "AppCompatCacheParser",
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "path_comparison",
            "mft_volume_id": "mft-source:test",
        },
        "source_record_ref": "shimcache.csv:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "shimcache-scoped-mft",
        "parser_runs": [
            {
                "parser_kind": "windows_registry_paths",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [observation],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:shimcache",
                "question_id": "Q-EXEC-01",
                "technique_id": "shimcache_path_residue",
                "subject_type": "executable",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": "candidate.exe",
                        "identity": {"canonical_name": path.casefold()},
                        "observation_ids": ["shimcache-path"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        next(
            item
            for item in techniques_for_question("Q-EXEC-01")
            if item.technique_id == "shimcache_path_residue"
        ),
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "complete"
    assert analysis_input.readiness == "ready"


def test_i30_population_uses_its_complete_raw_mft_scan_surface() -> None:
    observation = {
        "observation_id": "i30-scan",
        "artifact_family": "ntfs.i30",
        "observation_type": "i30_directory_scan",
        "subject_ref": r"C:\Users\vagrant\Documents\candidate",
        "fields": {
            "mft_volume_id": "mft-source:test",
            "mft_entry": 20,
            "sequence_number": 1,
            "scan_complete": True,
            "supported_surface": "resident_index_root_and_mft_record_slack",
            "resident_index_root_scanned": True,
            "mft_record_slack_scanned": True,
            "index_allocation_parsed": False,
            "residue_count": 0,
        },
        "source_record_ref": "$MFT:20",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "i30-scoped-mft",
        "parser_runs": [
            {
                "parser_kind": "ntfs_i30",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [observation],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:i30",
                "question_id": "Q-DEL-03",
                "technique_id": "i30_directory_residue",
                "subject_type": "directory_entry",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": observation["subject_ref"],
                        "identity": {"object_id": "ntfs:mft-source:test:20:1"},
                        "observation_ids": ["i30-scan"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        techniques_for_question("Q-DEL-03")[0],
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "complete"
    assert analysis_input.readiness == "ready"


def test_i30_population_is_not_ready_with_a_zero_scan_sequence() -> None:
    observation = {
        "observation_id": "i30-scan-zero-sequence",
        "artifact_family": "ntfs.i30",
        "observation_type": "i30_directory_scan",
        "subject_ref": r"C:\Users\vagrant\Documents\candidate",
        "fields": {
            "mft_volume_id": "mft-source:test",
            "mft_entry": 20,
            "sequence_number": 0,
            "scan_complete": True,
            "supported_surface": "resident_index_root_and_mft_record_slack",
            "resident_index_root_scanned": True,
            "mft_record_slack_scanned": True,
            "index_allocation_parsed": False,
            "residue_count": 0,
        },
        "source_record_ref": "$MFT:20",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "i30-zero-sequence",
        "parser_runs": [
            {
                "parser_kind": "ntfs_i30",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [observation],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:i30",
                "question_id": "Q-DEL-03",
                "technique_id": "i30_directory_residue",
                "subject_type": "directory_entry",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": observation["subject_ref"],
                        "identity": {"object_id": "ntfs:mft-source:test:20:0"},
                        "observation_ids": ["i30-scan-zero-sequence"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        techniques_for_question("Q-DEL-03")[0],
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"


def test_file_size_population_uses_its_exact_raw_mft_storage_projection() -> None:
    path = r"F:\Users\vagrant\Desktop\candidate.bmp"
    storage = {
        "observation_id": "storage-record",
        "artifact_family": "ntfs.file_size_allocation",
        "observation_type": "logical_allocated_size_record",
        "subject_ref": path,
        "fields": {
            "volume_id": "f",
            "mft_entry": 30,
            "sequence_number": 1,
            "stream_name": "",
            "resident_status": "resident",
            "attribute_flags": 0,
            "attribute_parse_error_count": 0,
            "is_sparse": False,
            "is_compressed": False,
            "is_encrypted": False,
            "mftecmd_identity_match": True,
            "attribute_chain_complete": True,
            "runlist_complete": None,
            "lowest_vcn": 0,
            "logical_size": 58,
            "mftecmd_file_size": 58,
        },
        "source_record_ref": "$MFT:30",
    }
    content = {
        "observation_id": "content-record",
        "artifact_family": "collected.file.content",
        "observation_type": "materialized_file_content_record",
        "subject_ref": path,
        "fields": {
            "volume_id": "f",
            "mft_entry": 30,
            "sequence_number": 1,
            "materialized_size": 58,
        },
        "source_record_ref": "content:30",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "file-size-scoped-mft",
        "parser_runs": [
            {
                "parser_kind": "ntfs_file_size_allocation",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [storage],
            },
            {
                "parser_kind": "materialized_file_content",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": [content],
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:file-size",
                "question_id": "Q-FILE-01",
                "technique_id": "bitmap_trailing_data",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": path,
                        "identity": {"object_id": "ntfs:f:30:1"},
                        "observation_ids": ["storage-record"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(
        evidence_index,
        techniques_for_question("Q-FILE-01")[0],
    )

    assert {item.artifact_family: item.status for item in analysis_input.coverage}[
        "ntfs.mft"
    ] == "complete"
    assert analysis_input.readiness == "ready"


def test_exact_object_identity_supersedes_renamed_paths() -> None:
    definition = techniques_for_question("Q-DEL-01")[0]
    observations = [
        {
            "observation_id": "old-name",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_file_delete",
            "subject_ref": r"C:\Users\alice\old.txt",
            "fields": {"file_reference_entry": 42, "file_reference_sequence": 3},
            "source_record_ref": "$J:1",
        },
        {
            "observation_id": "new-name",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_file_delete",
            "subject_ref": r"C:\Users\alice\new.txt",
            "fields": {"file_reference_entry": 42, "file_reference_sequence": 3},
            "source_record_ref": "$J:2",
        },
    ]
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "rename",
        "parser_runs": [
            parser_run("ntfs_usn", observations),
            parser_run("ntfs_mft", []),
        ],
    }

    analysis_input = build_analysis_input(evidence_index, definition)

    assert len(analysis_input.candidate_roster.subjects) == 1
    assert analysis_input.candidate_roster.subjects[0].observation_ids == (
        "new-name",
        "old-name",
    )


def test_drive_letter_is_part_of_path_identity() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    observations = [
        {
            "observation_id": f"obs-{drive}",
            "artifact_family": "ntfs.mft",
            "observation_type": "si_fn_timestamp_difference",
            "subject_ref": rf"{drive}:\same.txt",
            "fields": {"mismatch_count": 1},
            "source_record_ref": f"$MFT:{drive}",
        }
        for drive in ("C", "E")
    ]
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "volumes",
            "parser_runs": [
                parser_run("ntfs_mft", observations),
                parser_run("ntfs_usn", []),
            ],
        },
        definition,
    )

    assert len(analysis_input.candidate_roster.subjects) == 2


def test_ntfs_reference_identity_remains_scoped_to_its_volume() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    observations = [
        {
            "observation_id": f"obs-{drive}",
            "artifact_family": "ntfs.mft",
            "observation_type": "si_fn_timestamp_difference",
            "subject_ref": rf"{drive}:\same.txt",
            "fields": {
                "mismatch_count": 3,
                "mft_entry": 42,
                "sequence_number": 3,
            },
            "source_record_ref": f"$MFT:{drive}",
        }
        for drive in ("C", "E")
    ]

    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "volume-scoped-references",
            "parser_runs": [
                parser_run("ntfs_mft", observations),
                parser_run("ntfs_usn", []),
            ],
        },
        definition,
    )

    assert len(analysis_input.candidate_roster.subjects) == 2


def test_device_identity_supersedes_friendly_name() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    observations = [
        {
            "observation_id": f"usb-{index}",
            "artifact_family": "windows.registry.usbstor",
            "observation_type": "usb_device_seen",
            "subject_ref": display_name,
            "fields": {
                "serial_number": "SERIAL-1",
                "device_instance_id": r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
                "control_set": "ControlSet001",
            },
            "source_record_ref": f"SYSTEM:{index}",
        }
        for index, display_name in enumerate(("Old label", "New label"), start=1)
    ]
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "device-label",
            "parser_runs": [
                parser_run("windows_usbstor", observations),
                parser_run("windows_setupapi", []),
                parser_run("ntfs_usn", []),
                parser_run("ntfs_mft", []),
            ],
        },
        definition,
    )

    assert len(analysis_input.candidate_roster.subjects) == 1


def test_device_subject_keeps_exact_and_partial_setupapi_identity_relations() -> None:
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instance = r"USBSTOR\DISK&VEN_ACME\SERIAL-1"
    observations = [
        {
            "observation_id": "usbstor-subject",
            "artifact_family": "windows.registry.usbstor",
            "observation_type": "usb_device_seen",
            "subject_ref": "Bounded USB device",
            "fields": {
                "serial_number": "SERIAL-1",
                "device_instance_id": instance,
                "control_set": "ControlSet001",
            },
            "source_record_ref": "SYSTEM:1",
        },
        {
            "observation_id": "setupapi-exact",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": instance,
            "fields": {
                "serial_number": "SERIAL-1",
                "device_instance_id": instance,
            },
            "source_record_ref": "setupapi.dev.log:1",
        },
        {
            "observation_id": "setupapi-same-serial",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": r"USBSTOR\DISK&VEN_OTHER\SERIAL-1",
            "fields": {
                "serial_number": "SERIAL-1",
                "device_instance_id": r"USBSTOR\DISK&VEN_OTHER\SERIAL-1",
            },
            "source_record_ref": "setupapi.dev.log:2",
        },
        {
            "observation_id": "setupapi-same-instance",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": instance,
            "fields": {
                "serial_number": "SERIAL-OTHER",
                "device_instance_id": instance,
            },
            "source_record_ref": "setupapi.dev.log:3",
        },
        {
            "observation_id": "setupapi-unrelated",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": r"USBSTOR\DISK&VEN_OTHER\UNRELATED",
            "fields": {
                "serial_number": "UNRELATED",
                "device_instance_id": r"USBSTOR\DISK&VEN_OTHER\UNRELATED",
            },
            "source_record_ref": "setupapi.dev.log:4",
        },
    ]
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "device-relations",
        "parser_runs": [
            parser_run("windows_usbstor", [observations[0]]),
            parser_run("windows_setupapi", observations[1:]),
        ],
        "candidate_populations": [
            {
                "population_id": "population:device-relations",
                "question_id": "Q-MEDIA-01",
                "technique_id": "usbstor_setupapi_discrepancy",
                "subject_type": "device",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": "Bounded USB device",
                        "identity": {
                            "device_instance_id": instance.casefold(),
                            "serial_number": "serial-1",
                        },
                        "observation_ids": ["usbstor-subject"],
                    }
                ],
            }
        ],
    }

    analysis_input = build_analysis_input(evidence_index, definition)

    subject = analysis_input.candidate_roster.subjects[0]
    assert subject.observation_ids == (
        "setupapi-exact",
        "setupapi-same-instance",
        "setupapi-same-serial",
        "setupapi-unrelated:device:1f25e2786554",
        "usbstor-subject",
    )
    assert analysis_input.projected_observation_ids == subject.observation_ids
    assert any(x.startswith("setupapi-unrelated:device:") for x in analysis_input.projected_observation_ids)


def test_device_observation_that_partially_matches_multiple_subjects_fails_closed() -> (
    None
):
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instances = (
        r"USBSTOR\DISK&VEN_ONE\SHARED-SERIAL",
        r"USBSTOR\DISK&VEN_TWO\SHARED-SERIAL",
    )
    usbstor_observations = [
        {
            "observation_id": f"usbstor-{index}",
            "artifact_family": "windows.registry.usbstor",
            "observation_type": "usb_device_seen",
            "subject_ref": instance,
            "fields": {
                "serial_number": "SHARED-SERIAL",
                "device_instance_id": instance,
                "control_set": "ControlSet001",
            },
            "source_record_ref": f"SYSTEM:{index}",
        }
        for index, instance in enumerate(instances, start=1)
    ]
    ambiguous = {
        "observation_id": "setupapi-ambiguous",
        "artifact_family": "windows.setupapi",
        "observation_type": "setupapi_usb_event",
        "subject_ref": instances[1],
        "fields": {
            "serial_number": "SHARED-SERIAL",
            "device_instance_id": instances[1],
        },
        "source_record_ref": "setupapi.dev.log:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "ambiguous-device-relation",
        "parser_runs": [
            parser_run("windows_usbstor", usbstor_observations),
            parser_run("windows_setupapi", [ambiguous]),
        ],
        "candidate_populations": [
            {
                "population_id": "population:ambiguous-device-relation",
                "question_id": "Q-MEDIA-01",
                "technique_id": "usbstor_setupapi_discrepancy",
                "subject_type": "device",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": instance,
                        "identity": {
                            "device_instance_id": instance.casefold(),
                            "serial_number": "shared-serial",
                        },
                        "observation_ids": [f"usbstor-{index}"],
                    }
                    for index, instance in enumerate(instances, start=1)
                ],
            }
        ],
    }

    with pytest.raises(ValueError, match="matches more than one candidate subject"):
        build_analysis_input(evidence_index, definition)


def test_unscoped_device_observation_with_multiple_partial_matches_fails_closed() -> (
    None
):
    definition = techniques_for_question("Q-MEDIA-01")[0]
    observations = [
        {
            "observation_id": f"usbstor-{index}",
            "artifact_family": "windows.registry.usbstor",
            "observation_type": "usb_device_seen",
            "subject_ref": instance,
            "fields": {
                "serial_number": "SHARED-SERIAL",
                "device_instance_id": instance,
                "control_set": "ControlSet001",
            },
            "source_record_ref": f"SYSTEM:{index}",
        }
        for index, instance in enumerate(
            (
                r"USBSTOR\DISK&VEN_ONE\SHARED-SERIAL",
                r"USBSTOR\DISK&VEN_TWO\SHARED-SERIAL",
            ),
            start=1,
        )
    ]
    observations.append(
        {
            "observation_id": "setupapi-ambiguous",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": r"USBSTOR\DISK&VEN_TWO\SHARED-SERIAL",
            "fields": {
                "serial_number": "SHARED-SERIAL",
                "device_instance_id": r"USBSTOR\DISK&VEN_TWO\SHARED-SERIAL",
            },
            "source_record_ref": "setupapi.dev.log:1",
        }
    )

    with pytest.raises(ValueError, match="matches more than one candidate subject"):
        build_analysis_input(
            {
                "schema_version": "evidence_index.v1",
                "run_id": "unscoped-ambiguous-device-relation",
                "parser_runs": [
                    parser_run("windows_usbstor", observations[:2]),
                    parser_run("windows_setupapi", observations[2:]),
                ],
            },
            definition,
        )


def test_duplicate_observation_ids_fail_closed() -> None:
    duplicate = {
        "observation_id": "duplicate",
        "artifact_family": "ntfs.mft",
        "observation_type": "mft_file_record",
        "subject_ref": r"C:\one.txt",
        "fields": {"mismatch_count": 0},
        "source_record_ref": "$MFT:1",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "duplicates",
        "parser_runs": [
            parser_run("ntfs_mft", [duplicate]),
            parser_run("ntfs_mft", [{**duplicate, "subject_ref": r"D:\two.txt"}]),
            parser_run("ntfs_usn", []),
        ],
    }

    with pytest.raises(ValueError, match="duplicate observation_id"):
        build_analysis_input(evidence_index, techniques_for_question("Q-TIME-01")[0])


def test_partial_size_projection_does_not_degrade_complete_mft_coverage() -> None:
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "mixed-coverage",
        "parser_runs": [
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "complete",
                "coverage_families": ["ntfs.mft"],
                "raw_outputs": [{"path": "$MFT.csv"}],
                "observations": [],
            },
            {
                "parser_kind": "ntfs_file_size_allocation",
                "status": "consumed",
                "coverage_status": "partial",
                "coverage_families": ["ntfs.file_size_allocation"],
                "raw_outputs": [{"path": "$MFT.csv"}],
                "observations": [],
            },
            {
                "parser_kind": "ntfs_usn",
                "status": "consumed",
                "coverage_status": "complete",
                "coverage_families": ["ntfs.usn"],
                "raw_outputs": [{"path": "$J.csv"}],
                "observations": [],
            },
        ],
    }

    time_input = build_analysis_input(
        evidence_index, techniques_for_question("Q-TIME-01")[0]
    )
    file_input = build_analysis_input(
        evidence_index, techniques_for_question("Q-FILE-01")[0]
    )

    assert time_input.readiness == "ready"
    assert file_input.readiness == "insufficient_evidence"


def test_candidate_roster_uses_the_techniques_exact_observation_types() -> None:
    definition = techniques_for_question("Q-DEL-01")[0]
    observations = [
        {
            "observation_id": "delete",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_file_delete",
            "subject_ref": r"C:\Users\alice\deleted.txt",
            "fields": {"file_reference_entry": 42, "file_reference_sequence": 3},
            "source_record_ref": "$J:1",
        },
        {
            "observation_id": "ordinary-write",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_filesystem_activity",
            "subject_ref": r"C:\Users\alice\ordinary.txt",
            "fields": {"file_reference_entry": 43, "file_reference_sequence": 3},
            "source_record_ref": "$J:2",
        },
        {
            "observation_id": "basic-info-change",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_basic_info_change",
            "subject_ref": r"C:\Users\alice\ordinary.txt",
            "fields": {"file_reference_entry": 43, "file_reference_sequence": 3},
            "source_record_ref": "$J:3",
        },
    ]

    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "exact-candidate-types",
            "parser_runs": [
                parser_run("ntfs_usn", observations),
                parser_run("ntfs_mft", []),
            ],
        },
        definition,
    )

    assert [item.display_name for item in analysis_input.candidate_roster.subjects] == [
        r"C:\Users\alice\deleted.txt"
    ]


def test_ads_named_stream_records_attach_to_one_exact_host_file_subject() -> None:
    definition = techniques_for_question("Q-HIDE-01")[0]
    observations = [
        {
            "observation_id": "base-plus-field",
            "artifact_family": "ntfs.ads",
            "observation_type": "named_data_stream",
            "subject_ref": r"C:\Users\alice\host.txt",
            "fields": {
                "stream_name": "payload",
                "stream_size": 12,
                "mft_volume_id": "volume:test",
                "mft_entry": 42,
                "sequence_number": 7,
            },
            "source_record_ref": "$MFT:1",
        },
        {
            "observation_id": "second-stream",
            "artifact_family": "ntfs.ads",
            "observation_type": "named_data_stream",
            "subject_ref": r"C:\Users\alice\host.txt:metadata:$DATA",
            "fields": {
                "base_path": r"C:\Users\alice\host.txt",
                "stream_name": "metadata",
                "stream_size": 4,
                "mft_volume_id": "volume:test",
                "mft_entry": 42,
                "sequence_number": 7,
            },
            "source_record_ref": "$MFT:2",
        },
    ]

    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "ads-spelling",
            "parser_runs": [
                parser_run("ntfs_ads", observations),
                parser_run("ntfs_mft", []),
            ],
        },
        definition,
    )

    assert len(analysis_input.candidate_roster.subjects) == 1
    subject = analysis_input.candidate_roster.subjects[0]
    assert subject.display_name == r"C:\Users\alice\host.txt"
    assert subject.identity == {"object_id": "ntfs:volume:test:42:7"}
    assert subject.observation_ids == ("base-plus-field", "second-stream")


def _reference_lookup_pair():
    subject = CandidateSubject(
        "subject:test",
        "file",
        r"C:\case\target.txt",
        {"object_id": "ntfs:volume:test:42:3"},
        ("obs:lookup",),
    )
    record = Observation(
        "obs:lookup",
        "ntfs.usn",
        "usn_file_delete",
        subject.display_name,
        {
            "mft_volume_id": "volume:test",
            "file_reference_entry": 42,
            "file_reference_sequence": 3,
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "file_reference_entry_reused",
            "mft_active_reference_match": False,
            "mft_lookup_target": {
                "mft_volume_id": "volume:test",
                "object_id": "ntfs:volume:test:42:3",
                "target_role": "candidate",
            },
            "mft_lookup_observed": {"entry": 42, "sequence": 4, "in_use": True},
        },
        "source:mft-and-usn",
    )
    return subject, record


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("mft_volume_id", "volume:other"),
        ("file_reference_entry", 43),
        ("file_reference_sequence", True),
        ("file_reference_sequence", 0),
        ("file_reference_number", 42 + (4 << 48)),
        ("mft_active_presence_check_supported", "true"),
        ("mft_active_presence_basis", "path_comparison"),
        ("mft_active_presence_basis", None),
        ("mft_active_presence_status", "active_mft_present"),
        ("mft_active_reference_match", True),
        (
            "mft_lookup_target",
            {
                "mft_volume_id": "volume:test",
                "object_id": "ntfs:volume:test:43:3",
                "target_role": "candidate",
            },
        ),
        ("mft_lookup_observed", {"entry": 42, "sequence": 3, "in_use": True}),
    ],
)
def test_mft_lookup_rejects_unbound_or_contradictory_reference_facts(field, invalid):
    subject, record = _reference_lookup_pair()
    record = replace(record, fields={**record.fields, field: invalid})
    assert (
        active_mft_presence_fact(record, subject, collection_status="complete")[
            "status"
        ]
        == "unresolved"
    )


def test_exact_generation_lookup_preserves_reuse_and_does_not_prove_partial_absence():
    subject, record = _reference_lookup_pair()
    assert (
        active_mft_presence_fact(record, subject, collection_status="complete")[
            "status"
        ]
        == "absent"
    )
    assert (
        active_mft_presence_fact(record, subject, collection_status="partial")["status"]
        == "unresolved"
    )
    assert (
        active_mft_presence_fact(
            replace(record, source_record_ref=""), subject, collection_status="complete"
        )["status"]
        == "unresolved"
    )
    present = replace(
        record,
        fields={
            **record.fields,
            "mft_active_presence_status": "active_mft_present",
            "mft_active_presence_basis": "file_reference_in_use",
            "mft_active_reference_match": True,
            "mft_lookup_observed": {"entry": 42, "sequence": 3, "in_use": True},
        },
    )
    assert (
        active_mft_presence_fact(present, subject, collection_status="partial")[
            "status"
        ]
        == "present"
    )
    assert (
        active_mft_presence_fact(present, subject, collection_status="missing")[
            "status"
        ]
        == "unresolved"
    )


def test_path_lookup_rejects_wrong_path_basis_and_native_path_conflict():
    subject = CandidateSubject(
        "subject:path",
        "executable",
        r"C:\case\run.exe",
        {"canonical_name": r"c:\case\run.exe"},
        ("obs:path",),
    )
    record = Observation(
        "obs:path",
        "windows.registry.shimcache",
        "shimcache_path_seen",
        subject.display_name,
        {
            "mft_volume_id": "volume:test",
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "path_comparison",
        },
        "source:shimcache",
    )
    assert (
        active_mft_presence_fact(record, subject, collection_status="complete")[
            "status"
        ]
        == "absent"
    )
    for fields in (
        {"mft_active_presence_basis": "basename_volume_search"},
        {"path": r"C:\other\run.exe"},
        {"mft_active_path_match": True},
    ):
        assert (
            active_mft_presence_fact(
                replace(record, fields={**record.fields, **fields}),
                subject,
                collection_status="complete",
            )["status"]
            == "unresolved"
        )


def test_i30_lookup_is_bound_to_child_generation_and_directory_association():
    child, record = _reference_lookup_pair()
    directory = CandidateSubject(
        "subject:directory",
        "directory_entry",
        r"C:\case",
        {"object_id": "ntfs:volume:test:50:2"},
        (record.observation_id,),
    )
    record = replace(
        record,
        artifact_family="ntfs.i30",
        observation_type="i30_filename_residue",
        subject_ref=directory.display_name,
        fields={
            **record.fields,
            "mft_entry": 50,
            "sequence_number": 2,
            "parent_reference_entry": 50,
            "parent_reference_sequence": 2,
            "mft_lookup_target": {
                **record.fields["mft_lookup_target"],
                "target_role": "referenced_object",
            },
        },
    )
    fact = active_mft_presence_fact(
        record, directory, collection_status="complete", referenced_object=True
    )
    assert fact["status"] == "absent"
    assert fact["target_identity"]["object_id"] == child.identity["object_id"]
    assert fact["target_role"] == "referenced_object"
    assert (
        active_mft_presence_fact(record, directory, collection_status="complete")[
            "status"
        ]
        == "unresolved"
    )
    wrong_parent = replace(
        record, fields={**record.fields, "parent_reference_sequence": 3}
    )
    assert (
        active_mft_presence_fact(
            wrong_parent,
            directory,
            collection_status="complete",
            referenced_object=True,
        )["status"]
        == "unresolved"
    )


def test_typed_paths_key_aliases_must_not_conflict():
    key = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    assert is_typed_paths_fields({"source_key": key})
    assert is_typed_paths_fields({"source_key": key, "key_path": key.upper()})
    assert not is_typed_paths_fields(
        {"source_key": key, "key_path": r"ROOT\Software\Other"}
    )
    assert not is_typed_paths_fields({"source_key": key, "key_path": None})


def test_setupapi_lookup_preserves_partial_collection_and_identity_conflicts():
    definition = techniques_for_question("Q-MEDIA-01")[0]
    instance = r"USBSTOR\DISK&VEN_ACME\SERIAL-1"
    usb = {
        "observation_id": "usb",
        "artifact_family": "windows.registry.usbstor",
        "observation_type": "usb_device_seen",
        "subject_ref": instance,
        "fields": {
            "device_instance_id": instance,
            "serial_number": "SERIAL-1",
            "control_set": "ControlSet001",
        },
        "source_record_ref": "source:registry",
    }
    setup = {
        "observation_id": "setup",
        "artifact_family": "windows.setupapi",
        "observation_type": "setupapi_usb_event",
        "subject_ref": instance,
        "fields": {"device_instance_id": instance, "serial_number": "SERIAL-1"},
        "source_record_ref": "source:setupapi",
    }
    index = {
        "schema_version": "evidence_index.v1",
        "run_id": "lookup-test",
        "parser_runs": [
            parser_run("windows_usbstor", [usb]),
            parser_run("windows_setupapi", [setup]),
        ],
    }
    value = build_analysis_input(index, definition)
    subject = value.candidate_roster.subjects[0]
    assert setupapi_identity_lookup(value, subject)["status"] == "present"
    partial = replace(
        value,
        coverage=tuple(
            replace(item, status="partial")
            if item.artifact_family == "windows.setupapi"
            else item
            for item in value.coverage
        ),
    )
    assert setupapi_identity_lookup(partial, subject)["status"] == "present"
    absent = replace(
        value,
        observations=tuple(
            item for item in value.observations if item.observation_id != "setup"
        ),
    )
    assert setupapi_identity_lookup(absent, subject)["status"] == "absent"
    assert (
        setupapi_identity_lookup(replace(absent, coverage=partial.coverage), subject)[
            "status"
        ]
        == "unresolved"
    )
    conflict = replace(
        value.observations[-1],
        observation_id="partial",
        artifact_family="windows.setupapi",
        observation_type="setupapi_usb_event",
        fields={"device_instance_id": instance, "serial_number": "OTHER"},
    )
    lookup = setupapi_identity_lookup(
        replace(value, observations=(*value.observations, conflict)), subject
    )
    assert lookup["status"] == "conflicting"
    assert lookup["exact_match_count"] == lookup["partial_match_count"] == 1


def test_shellbag_coverage_lists_every_source_hive():
    from fmb.analysis.evidence_projection import _model_coverage_scope
    from fmb.analysis.inputs import _merge_coverage_scopes

    ntuser = {"kind": "shellbag_hives", "source_file": "vagrant_NTUSER.csv", "user": "vagrant", "hive": "NTUSER",
              "hive_present": True, "hive_path": "targets/F/Users/vagrant/NTUSER.DAT",
              "directory_record_count": 0, "unresolved_record_count": 0}
    usrclass = {**ntuser, "source_file": "vagrant_UsrClass.csv", "hive": "UsrClass",
                "hive_path": "targets/F/Users/vagrant/AppData/Local/Microsoft/Windows/UsrClass.dat",
                "directory_record_count": 24}
    merged = _merge_coverage_scopes(_merge_coverage_scopes(None, ntuser), usrclass)
    assert [hive["hive"] for hive in merged["hives"]] == ["NTUSER", "UsrClass"]
    assert merged["directory_record_count"] == 24 and merged["hive_present"] is True
    assert "source_file" not in merged
    projected = _model_coverage_scope(merged)
    assert [hive["directory_record_count"] for hive in projected["hives"]] == [0, 24]
