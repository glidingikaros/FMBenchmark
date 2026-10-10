from __future__ import annotations

import gzip
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src/fmb/generation' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def native_evtx():
    pytest.importorskip('Evtx')
    return gzip.decompress((ROOT / 'src/fmb/fixtures/native-event-sequence/security-native.evtx.gz').read_bytes())


def test_native_sequence_tamper_preserves_records_and_other_xml():
    from fmb.index.scanners.evtx_sequence import retained_record_ids
    mutation = module('event_sequence_injection')
    original = native_evtx()
    changed, receipt = mutation.mutate_evtx_bytes(original)
    before = retained_record_ids(original)
    after = retained_record_ids(changed)
    assert len(original) == len(changed)
    assert after == before[:-2] + tuple(value + 1 for value in before[-2:])
    assert receipt['record_count_unchanged'] is True
    assert receipt['xml_only_id_changes_verified'] is True
    assert receipt['native_crc_verified'] is True
    assert receipt['retained_record_count'] == 47
    assert receipt['internal_gap_count'] == 1
    with pytest.raises(ValueError, match='contiguous'):
        mutation.mutate_evtx_bytes(changed)


def test_sequence_refuses_partial_or_crc_damaged_native_input():
    mutation = module('event_sequence_injection')
    data = native_evtx()
    with pytest.raises(ValueError):
        mutation.mutate_evtx_bytes(data[:-8])
    damaged = bytearray(data)
    damaged[4096 + 600] ^= 1
    with pytest.raises(ValueError, match='checksum'):
        mutation.mutate_evtx_bytes(bytes(damaged))


def test_post_export_mutation_requires_bound_guest_preparation(tmp_path):
    pipeline = module('pipeline')
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.export_format = 'vmdk'
    instance.population_guest_plan = {'scenario_inputs': {'ntfs_allocation_01': {'operation_refs': []}}}
    instance.ground_truth = None
    with pytest.raises(ValueError, match='verified guest preparation'):
        instance.apply_post_export_interventions(tmp_path / 'not-opened.vmdk')


@pytest.mark.parametrize('encoding', ['ascii', 'utf-16le'])
def test_native_setupapi_intervention_preserves_structure_and_other_devices(encoding):
    mutation = module('native_media_generation')
    serial = 'ABCDEF0123456789ABCDEF0123456789'
    identity = 'USBSTOR\\Disk&Ven_VMware&Prod_Virtual_Storage&Rev_1.00\\' + serial + '&0'
    wrapper = 'SWD\\WPDBUSENUM\\_??_' + identity.replace('\\', '#') + '#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'
    original = ('>>>  [Device Install (Hardware initiated) - ' + wrapper + ']\r\n'
                '>>> Section start 2026/09/11 19:02:44\r\n' + serial.lower() + '\r\n'
                'another USBSTOR serial 11112222333344445555666677778888\r\n').encode(encoding)
    changed, receipt = mutation.alter_setupapi_identity(original, identity)
    assert len(changed) == len(original)
    assert receipt['matching_native_serial_occurrences'] == 2
    decoded = changed.decode(encoding)
    assert serial.lower() not in decoded.lower()
    assert '11112222333344445555666677778888' in decoded
    assert '>>> Section start 2026/09/11 19:02:44' in decoded
    with pytest.raises(ValueError, match='no same-device'):
        mutation.alter_setupapi_identity(changed, identity)


def test_native_media_preparation_is_owned_and_dependency_checked(tmp_path):
    pipeline = module("pipeline")
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.population_guest_plan = {}
    instance.run_command = lambda *_a, **_k: pytest.fail("nonpaper media dispatch")
    with pytest.raises(ValueError, match="native profile"):
        instance.prepare_native_media()
