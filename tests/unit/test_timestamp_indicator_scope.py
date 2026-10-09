from datetime import datetime, timedelta, timezone

import pytest

from fmb.analysis.catalog import techniques_for_question
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from test_deterministic_analysis import _timestomp_index


@pytest.mark.parametrize('delay', [0, 1, 2, 3, 5, 60])
def test_creation_proximity_neither_proves_benignity_nor_vetoes_logged_transition(delay):
    when = (datetime(2026, 1, 1, 12, tzinfo=timezone.utc) + timedelta(seconds=delay)).isoformat()
    index = _timestomp_index(usn=(), record_changed=when,
                            logfile=({'new_si_record_changed': when},))
    assessment = analyze_input(build_analysis_input(index, techniques_for_question('Q-TIME-01')[0])).assessments[0]
    assert assessment.outcome == 'supported'
    assert assessment.reason_code == 'coordinated_si_backdating_with_logged_si_transition'
    assert any('restoration' in note and 'indistinguishable' in note for note in assessment.limitations)


@pytest.mark.parametrize('creation_delta', [0, 1, 2, 3, 5, 60])
def test_attribute_only_basic_info_and_existing_discrepancy_are_an_indicator_not_transition_proof(creation_delta):
    event = datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc)
    created = event - timedelta(seconds=creation_delta)
    index = _timestomp_index(
        record_changed=event.isoformat(),
        usn=(('usn_filesystem_activity', 'FILE_CREATE|CLOSE', created.isoformat()),
             ('usn_basic_info_change', 'BASIC_INFO_CHANGE|CLOSE', event.isoformat())))
    assessment = analyze_input(build_analysis_input(index, techniques_for_question('Q-TIME-01')[0])).assessments[0]
    assert assessment.outcome == 'supported'
    assert assessment.reason_code == 'coordinated_si_backdating_with_temporal_basic_info_change'
    assert any('does not prove which SI fields changed' in note for note in assessment.limitations)
    assert not any('whose undo values' in note for note in assessment.limitations)
