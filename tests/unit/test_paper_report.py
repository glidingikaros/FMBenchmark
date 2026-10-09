from copy import deepcopy
import csv
import json
from pathlib import Path

import pytest

from fmb.evaluation import report as paper_report
from fmb.core.paths import PROJECT_ROOT


def study_fixture():
    protocol = json.loads((PROJECT_ROOT / 'contracts/paper/protocol.json').read_text())
    study = {
        'schema_version': 'paper_study.v1',
        'conditions': [dict(image=image, condition=condition, primary=f'{image}/{condition}', companion=None)
                       for image in protocol['images'] for condition in protocol['conditions']],
        'analyses': {'i3_focus_findings': [f'finding:{i}' for i in range(8)],
                     'i3_access_only_finding': 'finding:example'},
        'supplemental_findings': {image: [] for image in protocol['images']},
        'source_inputs': [{'path': 'source.json', 'sha256': 'a' * 64}],
        'measurements': {image: dict.fromkeys(('generation', 'collection', 'image_manifest', 'preparation'), 'source.json')
                         for image in protocol['images']},
    }
    return study, protocol


@pytest.mark.parametrize('change', ['missing_condition', 'duplicate_condition', 'reuse_primary',
                                  'missing_image', 'missing_measurement', 'missing_sources',
                                  'duplicate_source', 'invalid_hash', 'duplicate_focus'])
def test_incomplete_or_ambiguous_index_is_rejected(change):
    study, protocol = study_fixture()
    paper_report.validate_study(study, protocol)
    if change == 'missing_condition':
        study['conditions'].pop()
    elif change == 'duplicate_condition':
        study['conditions'].append(deepcopy(study['conditions'][0]))
    elif change == 'reuse_primary':
        study['conditions'][1]['primary'] = study['conditions'][0]['primary']
    elif change == 'missing_image':
        del study['measurements']['I3']
    elif change == 'missing_measurement':
        del study['measurements']['I3']['collection']
    elif change == 'missing_sources':
        study['source_inputs'] = []
    elif change == 'duplicate_source':
        study['source_inputs'] *= 2
    elif change == 'invalid_hash':
        study['source_inputs'][0]['sha256'] = 'unverified'
    else:
        study['analyses']['i3_focus_findings'][-1] = 'finding:0'
    with pytest.raises(ValueError):
        paper_report.validate_study(study, protocol)


def test_corpus_binding_includes_case_identity_and_reference_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(paper_report, 'reference_file', lambda root: root / 'references.json')
    (tmp_path / 'references.json').write_text('{"label":"original"}')
    manifest = {'rows': [dict(request_id='r1', question_id='BQ-FILE-01', case_id='c1', case_sha256='a' * 64)]}
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest))
    original = paper_report._corpus_binding(tmp_path)
    manifest['rows'][0]['case_sha256'] = 'b' * 64
    path.write_text(json.dumps(manifest))
    assert paper_report._corpus_binding(tmp_path) != original
    manifest['rows'][0]['case_sha256'] = 'a' * 64
    path.write_text(json.dumps(manifest))
    (tmp_path / 'references.json').write_text('{"label":"changed"}')
    assert paper_report._corpus_binding(tmp_path) != original


def test_report_keeps_missing_and_unusable_question_passes(tmp_path, monkeypatch):
    row = dict(image='I3', condition='glm53flash-high', every_pass=0, f1=0,
               finding_counts={'fn': 1, 'fp': 0}, cost_per_pass='0.0025',
               summed_request_seconds_per_pass='1.12345',
               per_question={q: {'exact_passes': []} for q in paper_report.QIDS},
               selection=[{'question_id': paper_report.QIDS[0], 'pass': 1, 'state': 'invalid_response'}])
    row.update(provenance={'selection_policy': {'id': 'historical_not_completed'}},
               lineage={'runs': {'primary': {'status': 'historical_lineage_not_fully_verified'}}})
    monkeypatch.setattr(paper_report, 'build_report', lambda **_: {
        'conditions': [row], 'corpus': {}, 'claim_boundary': 'Test report',
    })
    output = tmp_path / 'report'
    paper_report.write_report(index=Path('unused'), archive_root=tmp_path, output=output)
    with (output / 'question-passes.csv').open() as stream:
        cells = list(csv.DictReader(stream))
    assert len(cells) == 27 and all(c['exact'] == 'False' for c in cells)
    assert cells[0]['execution_states'] == 'invalid_response:1'
    assert cells[1]['execution_states'] == ''
    assert '0.003' in (output / 'figure-f1-cost.csv').read_text()
    assert 'historical_not_completed' in (output / 'results.md').read_text()
    assert 'historical_lineage_not_fully_verified' in (output / 'table-results.csv').read_text()
    assert json.loads((output / 'results.json').read_text())['conditions'][0]['lineage'] == row['lineage']


def test_report_leaves_an_undefined_f1_empty_instead_of_failing(tmp_path, monkeypatch):
    row = dict(image='I1', condition='luna-high', every_pass=0, f1=None,
               finding_counts={'fn': 0, 'fp': 0}, cost_per_pass='0.0025',
               summed_request_seconds_per_pass='1.12345',
               per_question={q: {'exact_passes': []} for q in paper_report.QIDS}, selection=[])
    monkeypatch.setattr(paper_report, 'build_report', lambda **_: {
        'conditions': [row], 'corpus': {}, 'claim_boundary': 'Test report',
    })
    output = tmp_path / 'report'
    paper_report.write_report(index=Path('unused'), archive_root=tmp_path, output=output)
    for name in ('table-results.csv', 'figure-f1-cost.csv'):
        with (output / name).open() as stream:
            [cells] = list(csv.DictReader(stream))
        assert cells['f1_percent'] == ''
