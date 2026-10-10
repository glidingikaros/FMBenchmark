from __future__ import annotations
import hashlib
import re


def alter_setupapi_identity(data: bytes, device_instance_id: str) -> tuple[bytes, dict]:
    if not device_instance_id.upper().startswith('USBSTOR\\'):
        raise ValueError('native SetupAPI intervention requires a USBSTOR identity')
    serial = device_instance_id.rsplit('\\', 1)[1].split('&', 1)[0]
    if not re.fullmatch(r'[A-Fa-f0-9]{32}', serial):
        raise ValueError('native VMware USB serial has an unsupported representation')
    replacement = ('0' if serial[0] != '0' else '1') + serial[1:]
    ascii_pattern = re.compile(re.escape(serial.encode('ascii')), re.IGNORECASE)
    utf16_pattern = re.compile(re.escape(serial.encode('utf-16le')), re.IGNORECASE)
    changed, count = ascii_pattern.subn(replacement.encode('ascii'), data)
    if not count:
        changed, count = utf16_pattern.subn(replacement.encode('utf-16le'), data)
    if not count or len(changed) != len(data):
        raise ValueError('native SetupAPI has no same-device identity to alter')
    if ascii_pattern.search(changed) or utf16_pattern.search(changed):
        raise ValueError('native SetupAPI identity alteration was incomplete')
    return changed, {'schema_version': 'generation_native_setupapi_intervention.v1',
                     'matching_native_serial_occurrences': count,
                     'byte_length_unchanged': True,
                     'registry_unchanged': True,
                     'original_serial': serial, 'replacement_serial': replacement,
                     'source_sha256': hashlib.sha256(data).hexdigest(),
                     'result_sha256': hashlib.sha256(changed).hexdigest()}
