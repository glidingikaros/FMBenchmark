from datetime import datetime
import re

ARCHIVE_LAST_WRITE_UTC = '2018-06-10T12:00:00+00:00'
MINIMUM_BACKDATING_SECONDS = 60

BEGIN = 'ARCHIVE_RESTORE_CONTROL_BEGIN'
END = 'ARCHIVE_RESTORE_CONTROL_END'
RECEIPT_NAME = 'archive_restore_control_receipt.json'


def extract_receipt(output: str, parse_chunk) -> dict:
    chunks, current, collecting = [], [], False
    for line in output.splitlines():
        if BEGIN in line:
            if collecting:
                raise ValueError('nested archive restore receipt')
            collecting, current = True, []
        elif END in line:
            if not collecting:
                raise ValueError('unmatched archive restore receipt end')
            chunks.append('\n'.join(current))
            collecting = False
        elif collecting:
            current.append(line)
    if collecting or len(chunks) != 1:
        raise ValueError('exactly one complete archive restore receipt is required')
    return parse_chunk(chunks[0])


def validate_receipt(receipt: dict, expected_paths: list[str], *, restore_paths: list[str] | None = None) -> None:
    if set(receipt) != {'schema_version', 'archive_requested_write_utc', 'operation',
                        'count', 'records', 'postconditions_verified'}:
        raise ValueError('archive restore receipt fields differ from its contract')
    partitioned = receipt['schema_version'] == 'native_archive_restore_receipt.v2'
    expected_count = len(expected_paths)
    if (receipt['schema_version'] not in {'native_archive_restore_receipt.v1', 'native_archive_restore_receipt.v2'}
            or receipt['operation'] != 'ZipFileExtensions.ExtractToFile_overwrite_existing'
            or receipt['postconditions_verified'] is not True
            or expected_count < 1 or receipt['count'] != expected_count):
        raise ValueError('archive restore receipt header is invalid')
    if partitioned != (restore_paths is not None):
        raise ValueError('archive restoration scope must match the frozen receipt version')
    restored_paths = {p.casefold() for p in (restore_paths if partitioned else expected_paths)}
    if (not restored_paths <= {p.casefold() for p in expected_paths}
            or (partitioned and (
                len(restored_paths) != len(restore_paths)
                or not 0 < len(restored_paths) < expected_count
            ))):
        raise ValueError('archive restore scope is outside the population')
    requested = datetime.fromisoformat(receipt['archive_requested_write_utc'].replace('Z', '+00:00'))
    if requested != datetime.fromisoformat(ARCHIVE_LAST_WRITE_UTC):
        raise ValueError('archive restore timestamp differs from the frozen plan')
    records = receipt['records']
    fields = {'path', 'file_id_before', 'file_id_after', 'content_sha256_before',
              'content_sha256_after', 'creation_before_utc', 'creation_after_utc',
              'write_before_utc', 'write_after_utc', 'archive_effective_write_utc'}
    if partitioned:
        fields.add('restored')
    if not isinstance(records, list) or len(records) != expected_count:
        raise ValueError('archive restore records are incomplete')
    seen = set()
    for row in records:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError('archive restore record fields are invalid')
        path = row['path'].casefold()
        if path in seen:
            raise ValueError('duplicate archive restore path')
        seen.add(path)
        restored = path in restored_paths
        if partitioned and row['restored'] is not restored:
            raise ValueError('archive control assignment differs from the frozen scope')
        if (not re.fullmatch(r'0x[0-9a-f]+', row['file_id_before'])
                or row['file_id_before'] != row['file_id_after']
                or not re.fullmatch(r'[0-9a-f]{64}', row['content_sha256_before'])
                or row['content_sha256_before'] != row['content_sha256_after']
                or row['creation_before_utc'] != row['creation_after_utc']
                or row['write_after_utc'] != row['archive_effective_write_utc']):
            raise ValueError('archive restore identity/content/time postcondition failed')
        created = datetime.fromisoformat(row['creation_before_utc'].replace('Z', '+00:00'))
        written = datetime.fromisoformat(row['write_after_utc'].replace('Z', '+00:00'))
        before = datetime.fromisoformat(row['write_before_utc'].replace('Z', '+00:00'))
        if (created.tzinfo is None or written.tzinfo is None or before.tzinfo is None
                or (restored and (written >= created or written >= before))):
            raise ValueError('archive restore must preserve creation and restore an older write time')
        if not restored and row['write_before_utc'] != row['write_after_utc']:
            raise ValueError('an untouched timestamp control changed its last-write time')
    if seen != {path.casefold() for path in expected_paths}:
        raise ValueError('archive restore population does not match public operational paths')
