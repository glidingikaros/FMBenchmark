from __future__ import annotations

import hashlib
import json
import struct

import pytest

from fmb.analysis.catalog import TECHNIQUES
from rule_helpers import analyze_input
from fmb.analysis.inputs import build_analysis_input
from fmb.index.adapters.ntfs_allocation import ntfs_allocation_parser_run
from fmb.index.scanners.ntfs import parse_boot_sector
from paper_fixtures import projected_input
from test_ntfs_surfaces import _nonresident, _record


@pytest.mark.parametrize(('pairs', 'overlap'), [
    (bytes((0x11, 1, 50, 0x11, 1, 0, 0)), True),
    (bytes((0x11, 2, 50, 0x11, 1, 1, 0)), True),
    (bytes((0x11, 1, 50, 0x11, 1, 255, 0)), False),
    (bytes((0x11, 1, 50, 0x11, 1, 1, 0)), False),
])
def test_raw_mft_adapter_and_rule_distinguish_aliases_from_fragmentation(tmp_path, pairs, overlap):
    count = pairs[1] + pairs[4]
    attr = bytearray(_nonresident(0x80, count=count, logical=count * 4096))
    attr[64:72] = pairs.ljust(8, b'\0')
    record = _record(30, [bytes(attr)])
    mft = tmp_path / 'public.mft'
    mft.write_bytes(bytes(30 * 1024) + record)
    record_path = tmp_path / 'record.bin'
    record_path.write_bytes(record)
    boot = bytearray(512)
    boot[3:11] = b'NTFS    '
    struct.pack_into('<H', boot, 11, 512)
    boot[13] = 8
    struct.pack_into('<QQQ', boot, 40, 1024, 4, 2)
    struct.pack_into('<bb', boot, 64, -10, 0)
    struct.pack_into('<b', boot, 68, -12)
    boot[510:512] = b'\x55\xaa'
    boot_path = tmp_path / 'boot.bin'
    boot_path.write_bytes(boot)
    def sha(data):
        return hashlib.sha256(data).hexdigest()
    manifest = tmp_path / 'native.json'
    manifest.write_text(json.dumps({
        'schema_version': 'native_ntfs_surfaces.v1', 'raw_mft_sha256': sha(mft.read_bytes()),
        'boot_sector_file': boot_path.name, 'boot_sector_sha256': sha(boot),
        'geometry': parse_boot_sector(boot),
        'records': [{'kind': 'file', 'mft_entry': 30, 'sequence_number': 1,
                     'subject_ref': r'C:\Public\ordinary.bin', 'native_identity_verified': True,
                     'record_file': record_path.name, 'record_sha256': sha(record)}],
    }))
    run = ntfs_allocation_parser_run(
        native_manifest_path=manifest, raw_mft_path=mft,
        normalized_output_dir=tmp_path / 'normalized', collector_run={'collector': 'kape'},
        filesystem_scope_id='volume:public',
    )
    fields = run['observations'][0]['fields']
    assert fields['runlist_complete'] is True and fields['runlist_in_volume'] is True
    assert fields['runlist_physical_overlap'] is overlap
    assert len(fields['data_runs']) == 2
    assert fields['allocated_size'] == fields['allocated_cluster_count'] * 4096
    definition = next(t for t in TECHNIQUES if t.technique_id == 'ntfs_allocation_inconsistency')
    value = build_analysis_input({'schema_version': 'evidence_index.v1', 'run_id': 'public-fixture',
        'parser_runs': [run], 'artifact_coverage': [{'artifact_family': 'ntfs.mft', 'status': 'complete'}]}, definition)
    result = analyze_input(value)
    [assessment] = result.assessments
    assert assessment.outcome == ('supported' if overlap else 'not_supported')
    assert assessment.reason_code == ('ntfs_allocation_physical_runs_overlap' if overlap else 'ordinary_allocation_consistent')
    packet = projected_input(value)
    [native_record] = [item for item in packet['candidate_roster'][0]['evidence_records']
                       if item['record_type'] == 'ntfs_allocation_attribute']
    projected = native_record['fields']
    assert projected['data_runs'] == fields['data_runs']
    for key in ('bytes_per_cluster', 'total_clusters', 'allocated_size', 'logical_size',
                'valid_data_length', 'allocated_cluster_count'):
        assert projected[key] == fields[key]
    assert 'runlist_physical_overlap' not in projected
    assert mft.read_bytes()[30 * 1024:] == record
