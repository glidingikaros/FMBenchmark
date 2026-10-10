from __future__ import annotations

import hashlib
import io
import json
import struct
import zipfile
from copy import deepcopy

import pytest

from fmb.analysis.catalog import TECHNIQUES
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.analysis.structured_content import zip_content_evidence
from fmb.index.adapters.stream_content import named_stream_content_parser_run
from fmb.index.scanners.mft import parse_mft_record
from fmb.index.scanners.ntfs import parse_boot_sector
from fmb.index.scanners.zip_content import zip_content_fields
from paper_fixtures import projected_input
from test_ntfs_surfaces import _record, _resident


def archive(*, method=zipfile.ZIP_DEFLATED, empty=False, count=1, descriptor=False):
    class Unseekable(io.BytesIO):
        def seekable(self):
            return False
        def seek(self, *args):
            raise OSError("public descriptor fixture")
    output = Unseekable() if descriptor else io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=method) as stream:
        if not empty:
            for ordinal in range(count):
                member = zipfile.ZipInfo(f'records{ordinal}.csv', date_time=(2026, 1, 1, 0, 0, 0))
                member.compress_type, member.external_attr = method, 0o600 << 16
                stream.writestr(member, b'record,value\n1,public-backup\n')
    return output.getvalue()


@pytest.mark.parametrize('method', [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize('descriptor', [False, True])
def test_complete_archive_native_measurements(method, descriptor):
    data = archive(method=method, descriptor=descriptor)
    fields = zip_content_fields(data)
    assert fields['zip_structure_status'] == 'complete'
    assert zip_content_evidence(fields, len(data)) is True
    entry = fields['zip_entries'][0]
    assert entry['crc32'] == entry['observed_crc32']
    assert entry['uncompressed_size'] == entry['observed_uncompressed_size'] == len(b'record,value\n1,public-backup\n')
    assert entry['flags'] & 8 == (8 if descriptor else 0)


@pytest.mark.parametrize('change', ['truncate', 'crc', 'local_name', 'central_offset', 'encryption', 'zip64', 'method', 'oversized_member'])
def test_format_shaped_incomplete_or_unsupported_archives_fail_closed(change):
    data = bytearray(archive())
    central = data.index(b'PK\x01\x02')
    if change == 'truncate':
        del data[-1:]
    elif change == 'crc':
        data[14] ^= 1
    elif change == 'local_name':
        data[30] ^= 1
    elif change == 'central_offset':
        struct.pack_into('<I', data, central + 42, 1)
    elif change == 'encryption':
        struct.pack_into('<H', data, 6, 1)
        struct.pack_into('<H', data, central + 8, 1)
    elif change == 'zip64':
        struct.pack_into('<H', data, 4, 45)
        struct.pack_into('<H', data, central + 6, 45)
    elif change == 'method':
        struct.pack_into('<H', data, 8, 99)
        struct.pack_into('<H', data, central + 10, 99)
    elif change == 'oversized_member':
        struct.pack_into('<I', data, central + 24, 8 * 1024 * 1024 + 1)
    fields = zip_content_fields(data)
    assert fields['zip_structure_status'] == 'incomplete_or_unsupported'
    assert zip_content_evidence(fields, len(data)) is None


def test_archive_bound_and_independent_fact_validation():
    data = archive(count=33)
    assert zip_content_evidence(zip_content_fields(data), len(data)) is None
    data = archive()
    fields = zip_content_fields(data)
    for key in ('observed_crc32', 'observed_uncompressed_size', 'record_end'):
        altered = deepcopy(fields)
        altered['zip_entries'][0][key] += 1
        assert zip_content_evidence(altered, len(data)) is None
    missing = deepcopy(fields)
    del missing['zip_entries'][0]['crc32']
    assert zip_content_evidence(missing, len(data)) is None
    data = archive(empty=True)
    assert zip_content_evidence(zip_content_fields(data), len(data)) is False


def native_input(tmp_path, data, stream_name='backup'):
    def write(name, value):
        path = tmp_path / name
        path.write_bytes(value)
        return path, hashlib.sha256(value).hexdigest()
    raw_record = _record(30, [_resident(0x80, data, name=stream_name, identity=3)])
    mft, mft_hash = write('public.mft', bytes(30 * 1024) + raw_record)
    _, record_hash = write('record.bin', raw_record)
    _, content_hash = write('stream.bin', data)
    boot = bytearray(512)
    boot[3:11] = b'NTFS    '
    struct.pack_into('<H', boot, 11, 512)
    boot[13] = 8
    struct.pack_into('<QQQ', boot, 40, 1024, 4, 2)
    struct.pack_into('<b', boot, 64, -10)
    struct.pack_into('<b', boot, 68, -12)
    boot[510:512] = b'\x55\xaa'
    _, boot_hash = write('boot.bin', boot)
    identity = {'mft_entry': 30, 'sequence_number': 1, 'mft_volume_id': 'volume:public'}
    parsed = parse_mft_record(raw_record, record_offset=30 * 1024, record_size=1024)
    [attribute] = parsed['data_attributes']
    assert attribute['stream_name'] == stream_name
    manifest = tmp_path / 'native.json'
    manifest.write_text(json.dumps({
        'schema_version': 'native_ntfs_surfaces.v1', 'raw_mft_sha256': mft_hash,
        'boot_sector_file': 'boot.bin', 'boot_sector_sha256': boot_hash,
        'geometry': parse_boot_sector(boot),
        'records': [{'kind': 'ads', 'mft_entry': 30, 'sequence_number': 1,
                     'subject_ref': r'C:\Records\document.txt', 'native_identity_verified': True,
                     'record_file': 'record.bin', 'record_sha256': record_hash,
                     'named_streams': [{'stream_name': attribute['stream_name'],
                        'logical_size': attribute['logical_size'], 'attribute_id': attribute['attribute_id'],
                        'content_complete': True, 'content_file': 'stream.bin', 'content_sha256': content_hash}]}],
    }))
    run = named_stream_content_parser_run(native_manifest_path=manifest, raw_mft_path=mft,
        normalized_output_dir=tmp_path / 'normalized', collector_run={'collector': 'kape'},
        filesystem_scope_id='volume:public')
    inventory = {'observation_id': 'native-inventory', 'artifact_family': 'ntfs.ads',
        'observation_type': 'named_data_stream', 'subject_ref': r'C:\Records\document.txt',
        'source_record_ref': f'native-mft:{record_hash}:attribute=3',
        'fields': {**identity, 'stream_name': attribute['stream_name'], 'stream_size': attribute['logical_size']}}
    definition = next(item for item in TECHNIQUES if item.technique_id == 'alternate_data_stream')
    value = build_analysis_input({'schema_version': 'evidence_index.v1', 'run_id': 'public-fixture',
        'artifact_coverage': [{'artifact_family': 'ntfs.ads', 'status': 'complete'}],
        'parser_runs': [run, {'parser_kind': 'ntfs_mft', 'status': 'consumed',
                             'coverage_status': 'complete', 'observations': [inventory]}]}, definition)
    return value, run


@pytest.mark.parametrize(('data', 'expected'), [
    (archive(), 'supported'),
    (archive(method=zipfile.ZIP_STORED), 'supported'),
    (archive(empty=True), 'not_supported'),
    (b'{"backup_revision":3}', 'not_supported'),
    (archive()[:-1], 'indeterminate'),
])
def test_native_bytes_to_adapter_card_and_detector(tmp_path, data, expected):
    value, run = native_input(tmp_path, data)
    [result] = analyze_input(value).assessments
    assert result.outcome == expected
    packet = projected_input(value)
    [content] = [item for item in packet['candidate_roster'][0]['evidence_records']
                 if item['record_type'] == 'named_stream_native_content']
    for key, fact in zip_content_fields(data).items():
        if key == 'zip_structure_status':
            assert key not in content['fields']
        else:
            assert content['fields'][key] == fact
    assert 'named_stream_contains_zip_archive_structure' not in str(packet)
    assert 'supported' not in content['fields']
    assert content['fields']['stream_name'] == 'backup'


def test_nested_format_annotation_is_not_model_evidence(tmp_path):
    value, _ = native_input(tmp_path, archive())
    from fmb.analysis.evidence_projection import _model_format_entries
    fields = zip_content_fields(archive())['zip_entries']
    annotated = deepcopy(fields)
    annotated[0]['deterministic_verdict'] = 'supported'
    assert _model_format_entries('zip_entries', annotated) == fields
    annotated[0]['future_native_fact'] = 1
    with pytest.raises(ValueError):
        _model_format_entries('zip_entries', annotated)
    assert analyze_input(value).assessments[0].outcome == 'supported'


def test_legacy_non_pe_measurements_cannot_certify_new_archive_absence():
    from test_rule_analysis import ads_records, assess
    records = ads_records(b'{"ordinary_metadata":3}')
    records[1]['fields'].pop('zip_signature_hex')
    records[1]['fields'].pop('zip_structure_status')
    _, outcome = assess('alternate_data_stream', records)
    assert outcome == 'indeterminate'


def test_exact_native_ziparchive_creation_block(tmp_path):
    import base64
    import shutil
    import subprocess
    from pathlib import Path
    import yaml

    pwsh = shutil.which('pwsh')
    if pwsh is None:
        pytest.skip('PowerShell is unavailable')
    task = Path(__file__).resolve().parents[2] / 'src/fmb/generation/ansible/roles/manipulation/tasks/ads_injection_01.yml'
    script = yaml.safe_load(task.read_text())[0]['ansible.windows.win_shell']
    start = script.index('  Add-Type -AssemblyName System.IO.Compression', script.index("'archive_file_create'"))
    stop = script.index('  $hasher = [Security.Cryptography.SHA256]::Create()', start)
    block = script[start:stop]
    prefix = "$ErrorActionPreference='Stop';$scenarioInput=[Console]::In.ReadToEnd()|ConvertFrom-Json\n"
    suffix = '\n[Convert]::ToBase64String($archiveBytes)\n'
    path = tmp_path / 'native-zip.ps1'
    path.write_text(prefix + block + suffix)
    import os
    environment = dict(os.environ, TEMP=str(tmp_path))
    result = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', str(path)],
        input=json.dumps({'zip_stage_name': 'public.zip', 'zip_member_name': 'records.csv',
                          'zip_member_content': 'record,value\n1,public-document\n2,retained-data\n'}),
        env=environment, text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    data = base64.b64decode(result.stdout.strip(), validate=True)
    assert data == (tmp_path / 'public.zip').read_bytes()
    fields = zip_content_fields(data)
    assert fields['zip_structure_status'] == 'complete'
    assert zip_content_evidence(fields, len(data)) is True
    assert fields['zip_expanded_size'] == len(b'record,value\n1,public-document\n2,retained-data\n')
    assert fields['zip_entry_count'] == 1


def _truncated_pe() -> bytes:
    data = bytearray(128)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 68, 0xAA64, 1, 0, 0, 0, 240, 0x22)
    return bytes(data)


@pytest.mark.parametrize(('data', 'expected'), [
    (b'MZ' + bytes(126), 'not_supported'),
    (_truncated_pe(), 'indeterminate'),
])
def test_mz_prefix_without_a_pe_header_is_not_pe_content(tmp_path, data, expected):
    from fmb.analysis.shared_rules import _ads_witness_local

    value, _run = native_input(tmp_path, data)
    assert _ads_witness_local(value, value.candidate_roster.subjects[0]).outcome == expected


@pytest.mark.parametrize(('path', 'stream', 'host'), [
    ('a:records', 'records', 'a'),
    (r'C:\Records\b:z', 'z', r'C:\Records\b'),
    (r'C:\Records\document.txt:backup', 'backup', r'C:\Records\document.txt'),
    (r'C:\Records\document.txt', '', r'C:\Records\document.txt'),
])
def test_stream_names_on_one_character_hosts(path, stream, host):
    from fmb.index.adapters.ntfs_files import ads_base_subject_ref, ads_stream_name_from_path

    assert ads_stream_name_from_path(path) == stream
    assert ads_base_subject_ref(path, stream) == host
