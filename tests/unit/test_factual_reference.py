import pytest

from fmb.evaluation.factual_reference import native_reference, supplemental_status


def test_reference_preserves_native_entry_and_generation_separately():
    assert native_reference('6486c650:0003000000000444') == ('6486c650', (1092, 3))
    assert native_reference('6486c650:0004000000000444') == ('6486c650', (1092, 4))
    with pytest.raises(ValueError, match='complete native'):
        native_reference('1092')


@pytest.mark.parametrize('operation', ['renamed', 'moved', 'hardlink_survives'])
def test_surviving_original_object_is_not_absent(operation):
    assert supplemental_status('BQ-DELETE-01', operation) == 'not_supported'


def test_same_path_replacement_has_distinct_object_and_path_truth():
    assert supplemental_status('BQ-DELETE-01', 'recreated', original=True) == 'supported'
    assert supplemental_status('BQ-DELETE-01', 'recreated', original=False) == 'not_supported'
    assert supplemental_status('BQ-EXEC-01', 'recreated') == 'not_supported'
    assert supplemental_status('BQ-SHELLBAG-01', 'recreated') == 'not_supported'
    assert supplemental_status('BQ-EXEC-01', 'renamed') == 'supported'
    assert supplemental_status('BQ-SHELLBAG-01', 'moved') == 'supported'


def test_superseded_backdating_is_in_scope_but_access_only_is_not():
    assert supplemental_status('BQ-TIME-01', 'superseded') == 'supported'
    assert supplemental_status('BQ-TIME-01', 'access_only') == 'not_supported'


def test_unregistered_generation_action_does_not_become_a_negative():
    with pytest.raises(ValueError, match='undeclared'):
        supplemental_status('BQ-TIME-01', 'new_unknown_mode')
