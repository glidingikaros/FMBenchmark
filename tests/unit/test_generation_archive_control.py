from __future__ import annotations

import os
import copy
import importlib.util
import json
from pathlib import Path
import pytest

SOURCE = Path(__file__).resolve().parents[2] / "src/fmb/generation"
spec = importlib.util.spec_from_file_location("archive_control_pipeline_test", SOURCE / "pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
controlled = pipeline.archive_control

def extract(output):
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    return controlled.extract_receipt(output, instance.parse_ground_truth_chunk)

def receipt():
    paths = [f'C:\\Users\\vagrant\\Desktop\\f_{i:012x}.txt' for i in range(55)]
    rows = []
    for i, path in enumerate(paths):
        rows.append({'path': path, 'file_id_before': f'0x{i:016x}', 'file_id_after': f'0x{i:016x}',
                     'content_sha256_before': 'a' * 64, 'content_sha256_after': 'a' * 64,
                     'creation_before_utc': '2026-09-08T01:00:00.1234567Z',
                     'creation_after_utc': '2026-09-08T01:00:00.1234567Z',
                     'write_before_utc': '2026-09-08T01:00:00.1234567Z',
                     'write_after_utc': '2018-06-10T12:00:00.0000000Z',
                     'archive_effective_write_utc': '2018-06-10T12:00:00.0000000Z'})
    return paths, {'schema_version': 'native_archive_restore_receipt.v1',
                   'archive_requested_write_utc': '2018-06-10T12:00:00.0000000+00:00',
                   'operation': 'ZipFileExtensions.ExtractToFile_overwrite_existing',
                   'count': 55, 'records': rows, 'postconditions_verified': True}


def test_receipt_round_trip_ignores_separate_ground_truth_markers():
    paths, value = receipt()
    output = '\n'.join(['GROUND_TRUTH_BEGIN', '{"opaque":"not parsed"}', 'GROUND_TRUTH_END',
                        '        "ARCHIVE_RESTORE_CONTROL_BEGIN",',
                        '        ' + json.dumps(json.dumps(value)) + ',',
                        '        "ARCHIVE_RESTORE_CONTROL_END"'])
    result = extract(output)
    controlled.validate_receipt(result, paths)
    assert result == value


def test_partitioned_receipt_uses_recipe_bound_population_and_restore_counts():
    paths, value = receipt()
    paths = paths[:13]
    restore_paths = paths[:6]
    restored = {path.casefold() for path in restore_paths}
    records = value['records'][:13]
    for row in records:
        row['restored'] = row['path'].casefold() in restored
        if not row['restored']:
            row['write_after_utc'] = row['write_before_utc']
            row['archive_effective_write_utc'] = row['write_before_utc']
    value.update({
        'schema_version': 'native_archive_restore_receipt.v2',
        'count': len(paths),
        'records': records,
    })

    controlled.validate_receipt(value, paths, restore_paths=restore_paths)
    with pytest.raises(ValueError, match='header'):
        controlled.validate_receipt({**value, 'count': 55}, paths, restore_paths=restore_paths)


@pytest.mark.parametrize('field,changed', [
    ('file_id_after', '0x9999'), ('content_sha256_after', 'b' * 64),
    ('creation_after_utc', '2026-09-08T01:00:01.1234567Z'),
    ('write_after_utc', '2018-06-10T12:00:02.0000000Z'),
])
def test_native_control_rejects_changed_identity_content_or_wrong_metadata(field, changed):
    paths, value = receipt()
    value['records'][0][field] = changed
    with pytest.raises(ValueError):
        controlled.validate_receipt(value, paths)


def test_receipt_rejects_duplicate_and_missing_population_members():
    paths, value = receipt()
    value['records'][-1] = copy.deepcopy(value['records'][0])
    with pytest.raises(ValueError, match='duplicate'):
        controlled.validate_receipt(value, paths)
    paths, value = receipt()
    with pytest.raises(ValueError, match='complete'):
        controlled.validate_receipt({**value, 'records': value['records'][:-1]}, paths)


def test_receipt_framing_rejects_truncation_or_multiple_receipts():
    with pytest.raises(ValueError):
        extract('ARCHIVE_RESTORE_CONTROL_BEGIN\n{}')
    with pytest.raises(ValueError):
        extract(('ARCHIVE_RESTORE_CONTROL_BEGIN\n{}\nARCHIVE_RESTORE_CONTROL_END\n') * 2)


def test_control_receipt_persisted_privately_before_export(tmp_path):
    paths, value = receipt()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.population_guest_plan = {"scenario_inputs": {"timestomp_01": {"population_paths": paths}}}
    instance.output_dir = tmp_path
    output = "ARCHIVE_RESTORE_CONTROL_BEGIN\n" + json.dumps(value) + "\nARCHIVE_RESTORE_CONTROL_END"
    instance.capture_archive_control(output)
    saved = tmp_path / controlled.RECEIPT_NAME
    assert json.loads(saved.read_text()) == value
    assert os.name == "nt" or saved.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        instance.capture_archive_control(output)

def test_non_timestamp_plan_requires_no_archive_receipt(tmp_path):
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.population_guest_plan = {"scenario_inputs": {"ads_injection_01": {}}}
    instance.output_dir = tmp_path
    instance.capture_archive_control("no marker")
    assert not list(tmp_path.iterdir())

def test_population_control_precedes_manipulation_and_never_uses_targets():
    text = (SOURCE / "ansible/roles/manipulation/tasks/main.yml").read_text()
    assert text.index("materialize_population.yml") < text.index("execute_scenario.yml")
    scenario = (SOURCE / "ansible/roles/manipulation/tasks/execute_scenario.yml").read_text()
    assert scenario.index("archive_restore_controls.yml") < scenario.index("Execute the selected scenario operation")
    task = (SOURCE / "ansible/roles/manipulation/tasks/archive_restore_controls.yml").read_text()
    assert "population_paths" in task and "operation_refs" not in task and "candidate_id" not in task
