import shutil

import pytest

from fmb.paper.replay import example_root, inspect_records, replay
from fmb.evaluation.scoring import score_run
from fmb.core.paper_protocol import condition_settings, validate_completion_policy
from fmb.evaluation.admission import reference_file
from fmb.core.sealed_records import read_json, write_json
from fmb.core.hashing import sha256_file

pytestmark = pytest.mark.skipif(not example_root().is_dir(), reason="the study's I1 records are kept out of the public repository")


def test_example_recomputes_the_declared_full_i1_roster():
    root = example_root()
    info = inspect_records(root)
    assert (info['requests'], info['findings'], info['questions']) == (30, 57, 9)
    result = replay(root)
    assert result['exact_requests'] == 30 and result['provider_calls'] == 0
    scores = score_run(root)
    assert scores['planned_requests'] == 90
    assert scores['planned_question_passes'] == 27
    assert scores['exact_all_passes']['denominator'] == 9


def test_changed_case_bytes_fail_before_replay(tmp_path):
    root = tmp_path / 'records'
    shutil.copytree(example_root(), root)
    path = next((root / 'cases').glob('*.json'))
    path.write_text('{}')
    with pytest.raises(ValueError, match='sealed file changed'):
        replay(root)


def test_reference_substitution_is_rejected(tmp_path):
    substitute = tmp_path / 'references.json'
    refs = read_json(example_root() / 'references.json')
    row = next(iter(refs.values()))['expected_status']
    row[next(iter(row))] = 'supported'
    write_json(substitute, refs)
    with pytest.raises(ValueError, match='substituted reference'):
        reference_file(example_root(), substitute)


def test_unsealed_response_cannot_fill_a_missing_call(tmp_path):
    root = tmp_path / 'records'
    shutil.copytree(example_root(), root)
    source = next((root / 'run').glob('call-*/outcome.json'))
    write_json(root / 'run/call-added/outcome.json', read_json(source))
    with pytest.raises(ValueError, match='unsealed outcome'):
        score_run(root)


def test_completion_is_limited_to_the_paper_policies():
    glm = condition_settings('glm53flash-high')
    validate_completion_policy(glm, {**glm, 'route': 'fireworks'})
    for other in ({**glm, 'route': 'other'}, {**glm, 'reasoning_effort': 'max'}):
        with pytest.raises(ValueError):
            validate_completion_policy(glm, other)
    luna = condition_settings('luna-max')
    validate_completion_policy(luna, {**luna, 'context_window_tokens': 2100000})
    with pytest.raises(ValueError):
        validate_completion_policy(luna, luna)


def test_resealed_metadata_cannot_relabel_saved_answers(tmp_path):
    root = tmp_path / 'records'
    shutil.copytree(example_root(), root)
    protocol = read_json(root / 'protocol.json')
    protocol['settings'].update(condition_settings('luna-max'))
    protocol.pop('condition_id', None)
    write_json(root / 'protocol.json', protocol)
    seal = read_json(root / 'preparation-seal.json')
    seal['files']['protocol.json'] = sha256_file(root / 'protocol.json')
    write_json(root / 'preparation-seal.json', seal)
    with pytest.raises(ValueError, match='request model/effort/output cap'):
        score_run(root)
