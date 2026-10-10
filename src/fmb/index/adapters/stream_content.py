from __future__ import annotations

from pathlib import Path
from typing import Any

import pefile

from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.json_io import write_json
from fmb.index.adapters.ntfs_allocation import (
    load_native_surfaces,
    native_sidecar_files,
    sidecar_file,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.zip_content import zip_content_fields

PE_MAGICS = {pefile.OPTIONAL_HEADER_MAGIC_PE, pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS}


def _pe_header(header_format: tuple, data: bytes, offset: int) -> pefile.Structure:
    header = pefile.Structure(header_format, file_offset=offset)
    size = header.sizeof()
    header.__unpack__(data[offset:offset + size].ljust(size, b"\0"))
    return header


def executable_content_fields(data: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "materialized_size": len(data), "content_sha256": sha256_bytes(data),
        "dos_signature_hex": data[:2].hex(), "pe_structure_status": "not_pe",
    }
    if data[:2] != b"MZ":
        return fields
    fields["pe_structure_status"] = "incomplete_or_malformed"
    if len(data) < 64:
        return fields
    offset = _pe_header(pefile.PE.__IMAGE_DOS_HEADER_format__, data, 0).e_lfanew
    fields["pe_header_offset"] = offset
    if offset < 64 or offset + 24 > len(data):
        return fields
    signature = _pe_header(pefile.PE.__IMAGE_NT_HEADERS_format__, data, offset).Signature
    fields["pe_signature_hex"] = signature.to_bytes(4, "little").hex()
    if signature != pefile.IMAGE_NT_SIGNATURE:
        return fields
    header = _pe_header(pefile.PE.__IMAGE_FILE_HEADER_format__, data, offset + 4)
    sections, optional_size = header.NumberOfSections, header.SizeOfOptionalHeader
    fields.update({"pe_machine": header.Machine, "pe_section_count": sections,
                   "pe_optional_header_size": optional_size, "pe_characteristics": header.Characteristics})
    optional = offset + 24
    table = optional + optional_size
    if not 1 <= sections <= 96 or optional_size < 64 or table + 40 * sections > len(data):
        return fields
    magic = _pe_header(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__, data, optional).Magic
    headers_size = _pe_header(pefile.PE.__IMAGE_OPTIONAL_HEADER64_format__
                              if magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
                              else pefile.PE.__IMAGE_OPTIONAL_HEADER_format__, data, optional).SizeOfHeaders
    fields.update({"pe_optional_magic": magic, "pe_size_of_headers": headers_size})
    if magic not in PE_MAGICS or not table + 40 * sections <= headers_size <= len(data):
        return fields
    section_fields = []
    for index in range(sections):
        section = _pe_header(pefile.PE.__IMAGE_SECTION_HEADER_format__, data, table + index * 40)
        size, pointer = section.SizeOfRawData, section.PointerToRawData
        if size and (pointer < headers_size or pointer + size > len(data)):
            return fields
        section_fields.append({"raw_size": size, "raw_offset": pointer, "characteristics": section.Characteristics})
    fields["pe_sections"] = section_fields
    fields["pe_structure_status"] = "complete"
    return fields


def named_stream_content_parser_run(*, native_manifest_path: Path, raw_mft_path: Path,
                                    normalized_output_dir: Path, collector_run: dict[str, Any],
                                    filesystem_scope_id: str) -> dict[str, Any]:
    manifest = load_native_surfaces(native_manifest_path, raw_mft_path)
    observations = []
    raw_outputs = [native_manifest_path, raw_mft_path, *native_sidecar_files(native_manifest_path, manifest)]
    for member in manifest["records"]:
        if member.get("kind") != "ads":
            continue
        entry, sequence = member["mft_entry"], member["sequence_number"]
        for stream in member.get("named_streams", []):
            fields = {"mft_entry": entry, "sequence_number": sequence,
                      "mft_volume_id": filesystem_scope_id, "stream_name": stream["stream_name"],
                      "stream_size": stream["logical_size"], "attribute_id": stream["attribute_id"],
                      "content_complete": stream.get("content_complete") is True,
                      "native_identity_verified": True}
            if fields["content_complete"]:
                path = sidecar_file(native_manifest_path, stream["content_file"], stream["content_sha256"])
                raw_outputs.append(path)
                data = path.read_bytes()
                fields.update(executable_content_fields(data))
                fields.update(zip_content_fields(data))
                if fields["materialized_size"] != fields["stream_size"]:
                    raise ValueError("native ADS size disagrees with its retained bytes")
            observations.append({"observation_id": f"obs:native-ads-content:{entry}:{sequence}:{stream['attribute_id']}",
                "artifact_family": "ntfs.ads", "observation_type": "named_stream_content",
                "subject_ref": member["subject_ref"], "fields": fields,
                "source_record_ref": f"native-mft:{member['record_sha256']}:attribute={stream['attribute_id']}"})
    output = normalized_output_dir / (sha256_file(native_manifest_path)[:16] + ".native-stream-content.json")
    write_json(output, {"schema_version": "parser_observation_index.v1", "parser": "fmb_bounded_parser",
                       "parser_kind": "ntfs_ads", "record_count": len(observations),
                       "observations": observations, "truth_sources_used": []})
    return normalize_parser_output(parser="fmb_bounded_parser", parser_kind="ntfs_ads",
        source_collector=str(collector_run["collector"]), source_module="FMBNativeStreamContent",
        raw_outputs=raw_outputs, normalized_output=output, observations=observations,
        tool_identity={"name": "fmb.ads.native_content_parser", "version": "2",
                       "source": "native named DATA bytes; PE/COFF headers decoded by pefile, bounded ZIP32 structural measurements"},
        observation_families=["ntfs.ads"], coverage_status="complete", coverage_families=["ntfs.ads"])
