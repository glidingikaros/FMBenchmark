from __future__ import annotations

import json
from copy import deepcopy

import pytest

from test_generation_population import PROJECT_ROOT, load_population_module


def test_native_stream_names_do_not_encode_payload_or_metadata_role():
    module = load_population_module()
    contract = module.load_population_contract()
    for seed in (1,2,19):
        manifest = module.build_public_manifest(experiment='full_scale', seed=seed, contract=contract)
        assignment = module.select_private_assignment(manifest, entropy=b'name-policy-fixture' * 2)
        plans = [module.build_guest_plan(manifest,assignment,case=case)['scenario_inputs']['ads_injection_01']
                 for case in ('positive','benign')]
        names = [plans[0][k] for k in ('stream_name','zip_stream_name','benign_stream_name')]
        import re
        assert all(re.fullmatch('n_[0-9a-f]{12}', n) for n in names)
        assert len(set(names)) == 3
        assert all(plans[0][k] == plans[1][k] for k in ('stream_name','zip_stream_name','benign_stream_name'))


@pytest.mark.parametrize('case', ['positive','benign'])
def test_factual_reference_counts_restoration_without_calling_benign_purpose_negative(verified_receipts, case):
    from test_generation_archive_control import receipt
    module = load_population_module()
    manifest = module.build_public_manifest(experiment='full_scale', seed=2)
    assignment = module.select_private_assignment(manifest, entropy=b'finding-reference-fixture' * 2)
    plan = module.build_guest_plan(manifest,assignment,case=case)
    operation_truth = module.build_ground_truth(manifest,assignment,verified_receipts(module,plan,case=case),case=case)
    _, control = receipt()
    control['schema_version'] = 'native_archive_restore_receipt.v2'
    timestamp = plan['scenario_inputs']['timestomp_01']
    restored = set(timestamp['archive_restore_paths'])
    assert len(restored) == 27
    for row,path in zip(control['records'],timestamp['population_paths'],strict=True):
        row['path'] = path
        row['restored'] = path in restored
        if not row['restored']:
            row['write_after_utc'] = row['archive_effective_write_utc'] = row['write_before_utc']
    reference = module.build_finding_reference(manifest,operation_truth,control)
    time = next(s for s in reference['scenarios'] if s['scenario_id'] == 'timestomp_01')
    assert 27 <= len(time['candidate_ids']) <= 29
    assert len(time['candidate_ids']) == 27 if case == 'benign' else True
    assert next(s for s in operation_truth['scenarios'] if s['scenario_id'] == 'timestomp_01')['candidate_ids'] == (
        [] if case == 'benign' else [m['candidate_id'] for m in assignment['bindings']['timestomp_01']])
    assert reference['case'] == case


@pytest.mark.parametrize('case', ['positive', 'benign'])
def test_current_ads_receipts(verified_receipts, case):
    module = load_population_module()
    contract = module.load_population_contract(PROJECT_ROOT / 'tests/fixtures/generation/populations.v1.json')
    manifest = module.build_public_manifest(experiment='full_scale', seed=2, contract=contract)
    assignment = module.select_private_assignment(manifest, entropy=b'public-byte-fixture' * 2)
    plan = module.build_guest_plan(manifest, assignment, case=case)
    inputs = plan['scenario_inputs']['ads_injection_01']
    assert len(manifest['scenarios']['ads_injection_01']['members']) == 130
    assert len(inputs['operation_refs']) == (2 if case == 'positive' else 0)
    assert inputs['content_kind'] == 'native_windows_pe_zip.v2'
    receipts = verified_receipts(module, plan, case=case)
    receipt = next(row for row in receipts if row['scenario_id'] == 'ads_injection_01')
    module.validate_guest_receipts(plan, receipts, case=case)
    assert [row['format'] for row in receipt['streams']] == (['pe', 'zip'] if case == 'positive' else [])
    assert receipt['content_contract'] == 'named_stream_pe_zip.v2'
    assert contract['contract_revision'] == 'stefan_content_formats.v2'
    schema = json.loads((PROJECT_ROOT / 'src/fmb/contracts/schemas/generation_recipe.schema.json').read_text())
    from jsonschema import Draft202012Validator
    Draft202012Validator(schema['$defs']['generation_inputs']['properties']['scenario_inputs']['additionalProperties']).validate(inputs)


@pytest.mark.parametrize('mutation', ['missing', 'reverse', 'hash', 'format', 'size', 'contract'])
def test_new_ads_receipt_cannot_downgrade_or_reorder(verified_receipts, mutation):
    module = load_population_module()
    manifest = module.build_public_manifest(experiment='full_scale', seed=0)
    assignment = module.select_private_assignment(manifest, entropy=b'public-contract-fixture' * 2)
    plan = module.build_guest_plan(manifest, assignment)
    receipts = deepcopy(verified_receipts(module, plan, case='positive'))
    receipt = next(row for row in receipts if row['scenario_id'] == 'ads_injection_01')
    if mutation == 'missing':
        receipt['streams'].pop()
    elif mutation == 'reverse':
        receipt['streams'].reverse()
    elif mutation == 'hash':
        receipt['streams'][1]['stream_sha256'] = 'not-a-hash'
    elif mutation == 'format':
        receipt['streams'][1]['format'] = 'pe'
    elif mutation == 'size':
        receipt['streams'][1]['stream_length'] = True
    elif mutation == 'contract':
        receipt['content_contract'] = 'legacy'
    with pytest.raises(module.PopulationError):
        module.validate_guest_receipts(plan, receipts, case='positive')
