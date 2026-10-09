from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest
import yaml

from fmb.index.adapters.file_content import bmp_content_observation, storage_observation
from fmb.index.scanners.mft import parse_mft_record
from paper_fixtures import projected_input
from test_file_content_adapter import bmp_bytes
from test_ntfs_surfaces import _record, _resident
from test_rule_analysis import assess


def native_records(data, *, native_size=None):
    path = r'C:\Users\alice\Documents\Public.bmp'
    stored = data if native_size is None else data.ljust(native_size, b'\0')
    raw = parse_mft_record(_record(42, [_resident(0x80, stored)]), record_offset=42 * 1024)
    storage = storage_observation(row={'FullPath': path, 'EntryNumber': '42',
        'SequenceNumber': '1', 'FileSize': str(len(stored))}, raw_record=raw, volume_id='volume:public')
    content = bmp_content_observation(content=data, subject_ref=path, volume_id='volume:public',
                                      mft_entry=42, sequence_number=1)
    assert storage['fields']['resident_status'] == 'resident'
    return [storage, content]


@pytest.mark.parametrize(('data', 'expected'), [
    (bmp_bytes(), 'not_supported'), (bmp_bytes()[:54], 'supported'),
    (bmp_bytes(trailing=b'PUBLIC TRAILER'), 'supported'),
])
def test_native_resident_header_and_logical_bytes(data, expected):
    records = native_records(data)
    value, outcome = assess('bitmap_trailing_data', records)
    assert outcome == expected
    packet = projected_input(value)
    card = next(r['fields'] for r in packet['candidate_roster'][0]['evidence_records']
                if r['record_type'] == 'file_content')
    for key in ('width', 'height', 'dib_size', 'pixel_offset', 'planes', 'bits_per_pixel',
                'compression', 'reserved1', 'reserved2', 'image_size', 'colors_used'):
        assert card[key] == records[1]['fields'][key]
    assert 'structure_validation' not in card


def test_short_collection_is_not_native_truncation():
    records = native_records(bmp_bytes()[:54], native_size=58)
    _, outcome = assess('bitmap_trailing_data', records)
    assert outcome == 'indeterminate'


def test_normal_resizing_and_top_down_image_are_consistent():
    for height in (2, -2):
        data = bytearray(bmp_bytes()) + bytes(4)
        struct.pack_into('<I', data, 2, 62)
        struct.pack_into('<i', data, 22, height)
        struct.pack_into('<I', data, 34, 8)
        assert assess('bitmap_trailing_data', native_records(bytes(data)))[1] == 'not_supported'


@pytest.mark.parametrize(('offset', 'fmt', 'value'), [
    (6, '<H', 1), (8, '<H', 1), (14, '<I', 124), (28, '<H', 8),
    (30, '<I', 1), (46, '<I', 1), (34, '<I', 8), (2, '<I', 62),
])
def test_unsupported_or_inconsistent_header_is_not_cropping(offset, fmt, value):
    data = bytearray(bmp_bytes()[:54])
    struct.pack_into(fmt, data, offset, value)
    with pytest.raises(ValueError):
        native_records(bytes(data))


@pytest.mark.parametrize(('key', 'value'), [('width', 2), ('reserved1', 1), ('image_size', 8), ('planes', True)])
def test_detector_checks_native_geometry_independently(key, value):
    records = native_records(bmp_bytes()[:54])
    records[1]['fields'][key] = value
    assert assess('bitmap_trailing_data', records)[1] == 'indeterminate'


@pytest.mark.parametrize('variant', ['positive', 'benign'])
def test_actual_guest_body_and_strict_receipt_with_public_files(tmp_path, variant):
    pwsh = shutil.which('pwsh')
    if not pwsh:
        pytest.skip('PowerShell not installed')
    from fmb.generation.population import validate_guest_receipts
    from test_generation_scenario_truth_blindness import render_public_helper_lookups
    task = Path(__file__).resolve().parents[2] / 'src/fmb/generation/ansible/roles/manipulation/tasks/pilot_bitmap_trailing_data_01.yml'
    body = render_public_helper_lookups(yaml.safe_load(task.read_text())[0]['ansible.windows.win_shell'])
    paths = [str(tmp_path / f'Public{i:03}.bmp') for i in range(4)]
    for path in paths:
        Path(path).write_bytes(bmp_bytes())
    case = 'benign' if variant == 'benign' else 'positive'
    inputs = {'case': case, 'population_paths': paths,
              'expected_population_count': 4, 'native_pilot_profile': 'pilot_min.v1',
              'expected_operation_count': 2 if case == 'positive' else 0,
              'operation_refs': paths[:2] if case == 'positive' else []}
    inputs['bitmap_operations'] = [{'mode': 'append', 'byte_count': 1024}, {'mode': 'truncate', 'length': 54}]
    script = tmp_path / 'guest.ps1'
    script.write_text(body)
    completed = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                               input=json.dumps(inputs), capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    plan = {'schema_version': 'generation_inputs.v1', 'scenario_inputs': {'bitmap_trailing_data_01': inputs}}
    assert validate_guest_receipts(plan, [receipt], case=case) == [receipt]
    expected = [1082, 54] if case == 'positive' else [58, 58]
    assert [Path(p).stat().st_size for p in paths[:2]] == expected
    assert all(Path(p).read_bytes() == bmp_bytes() for p in paths[2:])
    if variant == 'positive':
        assert Path(paths[1]).read_bytes() == bmp_bytes()[:54]
        for key, value in [('materialized_length', 58), ('declared_length', 54), ('mode', 'append')]:
            bad = deepcopy(receipt)
            bad['instances'][1][key] = value
            with pytest.raises(ValueError):
                validate_guest_receipts(plan, [bad], case=case)
