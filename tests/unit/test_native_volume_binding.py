from copy import deepcopy
import uuid

from fmb.index.adapters.volume_binding import drive_letters_from_proof
from fmb.analysis.mft_comparison import comparison_fields, comparison_evidence_refs


def test_gpt_drive_binding_requires_exact_native_partition_identifier():
    identifier = uuid.UUID('01234567-89ab-cdef-0123-456789abcdef')
    entry = bytearray(128)
    entry[16:32] = identifier.bytes_le
    proof = {"gpt_partition_id": str(identifier), "gpt_partition_entry_hex": entry.hex(),
             "mounted_device_values": [
                 {"name": r"\DosDevices\C:", "bytes_hex": (b'DMIO:ID:' + identifier.bytes_le).hex()},
                 {"name": r"\DosDevices\D:", "bytes_hex": (b'DMIO:ID:' + bytes(16)).hex()}]}
    assert drive_letters_from_proof(proof) == {'c'}


def test_native_relative_mft_path_is_present_only_on_its_bound_volume():
    pool = {"mft_volume_id": "native:test", "source_record_ref": "mft:scan",
            "path_complete": True, "volume_aliases": ["c"], "path_prefixes": ["work\\"],
            "native_volume_observations": [],
            "records": [{"entry": 42, "sequence": 3, "path": r".\Work\tool.exe",
                         "in_use": True, "source_record_ref": "mft:row=42"}]}
    payload = {"current_mft_pools": [pool]}
    card = {"identity": {"path": r"C:\Work\tool.exe"}}
    record = {"subject_ref": r"C:\Work\tool.exe", "fields": {}}
    assert comparison_fields(payload, card, record)["mft_active_presence_status"] == 'active_mft_present'
    assert 'mft:row=42' in comparison_evidence_refs(payload, card, record)
    foreign = deepcopy(record)
    foreign['subject_ref'] = r"D:\Work\tool.exe"
    assert not comparison_fields(payload, card, foreign)["mft_active_presence_check_supported"]
