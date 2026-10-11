from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
import hashlib
from importlib.metadata import version
import multiprocessing
import os
import struct
import xml.etree.ElementTree as ET
import zlib

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# python-evtx takes a few milliseconds to render one record, and a Security log holds thousands of them. Chunks are
# self-contained, so a large log is rendered in worker processes, one chunk per job, in the same order.
PARALLEL_RENDER_MIN_CHUNKS = 16
_RENDER_SOURCES: tuple[bytes, ...] = ()


def _xml_id(xml: str) -> tuple[ET.Element, ET.Element, int]:
    tree = ET.fromstring(xml)
    nodes = tree.findall("./e:System/e:EventRecordID", NS)
    if len(nodes) != 1 or nodes[0].text is None:
        raise ValueError("native XML has no unique System/EventRecordID")
    return tree, nodes[0], int(nodes[0].text)


def _active_chunks(data: bytes):
    from Evtx.Evtx import ChunkHeader
    capacity = (len(data) - 4096) // 65536
    first = struct.unpack_from("<Q", data, 8)[0]
    count = struct.unpack_from("<H", data, 42)[0]
    for ordinal in range(count):
        yield ChunkHeader(data, 4096 + ((first + ordinal) % capacity) * 65536)


def _start_renderer(sources: tuple[bytes, ...]) -> None:
    global _RENDER_SOURCES
    _RENDER_SOURCES = sources


def _render_chunk(job: tuple[int, int]) -> list[str]:
    from Evtx.Evtx import ChunkHeader
    source, offset = job
    return [record.xml() for record in ChunkHeader(_RENDER_SOURCES[source], offset).records()]


def _render_workers() -> int:
    try:
        available = len(os.sched_getaffinity(0))
    except AttributeError:
        available = os.cpu_count() or 1
    return min(available, 8)


def rendered_xml(*sources: tuple[bytes, list]) -> list[list[str]]:
    """The XML of every record in each (data, chunks of that data) source, in chunk and record order."""
    count = sum(len(chunks) for _, chunks in sources)
    workers = min(count, _render_workers())
    if count >= PARALLEL_RENDER_MIN_CHUNKS and workers > 1:
        jobs = [(index, chunk.offset()) for index, (_, chunks) in enumerate(sources) for chunk in chunks]
        try:
            with ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context("spawn"),
                                     initializer=_start_renderer,
                                     initargs=(tuple(data for data, _ in sources),)) as pool:
                parts = list(pool.map(_render_chunk, jobs, chunksize=max(1, len(jobs) // (workers * 4))))
        except (BrokenProcessPool, OSError):
            pass
        else:
            result: list[list[str]] = [[] for _ in sources]
            for (index, _), part in zip(jobs, parts, strict=True):
                result[index].extend(part)
            return result
    return [[record.xml() for chunk in chunks for record in chunk.records()] for _, chunks in sources]


def _substitution_patch(data: bytes, record, new_id: int) -> tuple[int, bytes]:
    from Evtx.Evtx import Record, ChunkHeader
    from Evtx.Nodes import UnsignedQwordTypeNode
    before, node, old_id = _xml_id(record.xml())
    if old_id != record.record_num():
        raise ValueError("native envelope/XML IDs disagree before mutation")
    node.text = str(new_id)
    expected_xml = ET.tostring(before)
    matches = []
    for substitution in record.root().substitutions():
        if not isinstance(substitution, UnsignedQwordTypeNode) or substitution.qword() != old_id:
            continue
        offset = substitution.offset()
        if not record.offset() + 24 <= offset <= record.offset() + record.size() - 12:
            raise ValueError("record ID substitution is outside its record")
        trial = bytearray(data)
        struct.pack_into("<Q", trial, offset, new_id)
        chunk = ChunkHeader(trial, record._chunk.offset())
        trial_record = Record(trial, record.offset(), chunk)
        if ET.tostring(ET.fromstring(trial_record.xml())) == expected_xml:
            matches.append(offset)
    if len(matches) != 1:
        raise ValueError("cannot uniquely locate the native EventRecordID substitution")
    return matches[0], struct.pack("<Q", new_id)


def mutate_evtx_bytes(data: bytes, *, source_xml: list[str] | None = None) -> tuple[bytes, dict]:
    """source_xml, when given, is rendered_xml's output for data (as validate_log_a_source returns it)."""
    __import__("Evtx.Evtx")
    from fmb.index.scanners.evtx_sequence import retained_record_ids

    before_ids = retained_record_ids(data)
    if len(before_ids) < 3 or any(b != a + 1 for a, b in zip(before_ids, before_ids[1:])):
        raise ValueError("sequence canary requires at least three contiguous retained records")
    chunks = list(_active_chunks(data))
    records = [record for chunk in chunks for record in chunk.records()]
    if tuple(record.record_num() for record in records) != before_ids:
        raise ValueError("independent native parsers disagree about retained records")
    selected = records[-2:]
    if selected[-1].record_num() >= (1 << 64) - 2:
        raise ValueError("record identifier increment would overflow")
    changed = bytearray(data)
    patches = []
    expected_xml = {}
    for record in selected:
        old_id = record.record_num()
        tree, node, _ = _xml_id(record.xml())
        node.text = str(old_id + 1)
        expected_xml[record.offset()] = ET.tostring(tree)
        offset, value = _substitution_patch(data, record, old_id + 1)
        changed[offset:offset + 8] = value
        struct.pack_into("<Q", changed, record.offset() + 8, old_id + 1)
        patches.append({"record_offset": record.offset(), "xml_value_offset": offset,
                        "before_id": old_id, "after_id": old_id + 1})
    threshold = selected[0].record_num()
    for chunk in chunks:
        offset = chunk.offset()
        for field in (24, 32):
            original = struct.unpack_from("<Q", changed, offset + field)[0]
            if original >= threshold:
                struct.pack_into("<Q", changed, offset + field, original + 1)
        free = struct.unpack_from("<I", changed, offset + 48)[0]
        struct.pack_into("<I", changed, offset + 52,
                         zlib.crc32(changed[offset + 512:offset + free]))
        header = changed[offset:offset + 120] + changed[offset + 128:offset + 512]
        struct.pack_into("<I", changed, offset + 124, zlib.crc32(header))
    next_id = struct.unpack_from("<Q", changed, 24)[0]
    if next_id <= before_ids[-1]:
        raise ValueError("native next-record identifier does not exceed retained records")
    struct.pack_into("<Q", changed, 24, next_id + 1)
    struct.pack_into("<I", changed, 124, zlib.crc32(changed[:120]))
    result = bytes(changed)
    after_ids = retained_record_ids(result)
    expected_ids = before_ids[:-2] + tuple(value + 1 for value in before_ids[-2:])
    if len(result) != len(data) or after_ids != expected_ids:
        raise ValueError("native sequence mutation failed structural postconditions")
    after_chunks = list(_active_chunks(result))
    after_records = [record for chunk in after_chunks for record in chunk.records()]
    if source_xml is None:
        before_xml, after_xml = rendered_xml((data, chunks), (result, after_chunks))
    else:
        if len(source_xml) != len(records):
            raise ValueError("rendered source XML does not cover the retained records")
        before_xml, [after_xml] = source_xml, rendered_xml((result, after_chunks))
    for before, after, before_text, after_text in zip(records, after_records, before_xml, after_xml, strict=True):
        after_tree, _, after_id = _xml_id(after_text)
        original_xml = ET.tostring(ET.fromstring(before_text))
        if (ET.tostring(after_tree) != expected_xml.get(before.offset(), original_xml)
                or after_id != after.record_num()):
            raise ValueError("native XML round trip changed unintended event content")
    return result, {"schema_version": "generation_event_sequence_mutation.v1",
                    "mutation": "two_tail_identifiers_incremented_once",
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "result_sha256": hashlib.sha256(result).hexdigest(),
                    "retained_record_count": len(before_ids), "internal_gap_count": 1,
                    "record_count_unchanged": True, "xml_only_id_changes_verified": True,
                    "native_crc_verified": True, "patches": patches,
                    "python_evtx_version": version("python-evtx")}
