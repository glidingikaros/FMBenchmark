from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueDefinition:
    question_id: str
    question_title: str
    question_text: str
    technique_id: str
    subject_type: str
    candidate_artifact_families: tuple[str, ...]
    candidate_observation_types: tuple[str, ...]
    required_artifact_families: tuple[str, ...]
    optional_artifact_families: tuple[str, ...]
    projected_artifact_families: tuple[str, ...]
    claim_boundary: str
    alternative_required_artifact_families: tuple[tuple[str, ...], ...] = ()


def technique_definition(technique_id: str) -> TechniqueDefinition | None:
    for item in TECHNIQUES:
        if item.technique_id == technique_id:
            return item
    return None


def sufficient_family_sets(definition: TechniqueDefinition) -> tuple[tuple[str, ...], ...]:
    return (
        tuple(definition.required_artifact_families),
        *definition.alternative_required_artifact_families,
    )


QUESTION_TEXT = {
    "Q-TIME-01": (
        "Coordinated NTFS timestamp inconsistency",
        "Does one exact NTFS object show SI created and modified backdated by at "
        "least one minute relative to its FN timestamps, corroborated either by a "
        "same-object USN BasicInfoChange (within one second after the SI "
        "record-change time, or as the object's last journaled record a minute or "
        "more after it) or by a committed $STANDARD_INFORMATION update retained in "
        "$LogFile that rewrote the original values to the current backdated ones?",
    ),
    "Q-DEL-01": (
        "Deleted-file journal residue",
        "Does an exact-reference USN FILE_DELETE record remain for an object "
        "explicitly absent from the active $MFT?",
    ),
    "Q-DEL-02": (
        "TypedPaths residue and active absence",
        "Does a structured TypedPaths registry value reference an absolute local "
        "path proven absent from the active filesystem?",
    ),
    "Q-DEL-03": (
        "Bounded NTFS directory-index residue",
        "Is there filename residue in resident $INDEX_ROOT, MFT-record slack or "
        "nonresident $INDEX_ALLOCATION that references an object absent from the active $MFT?",
    ),
    "Q-DEL-04": (
        "Shellbag directory residue and active absence",
        "Does a native Shellbag directory record identify an absolute local path "
        "that a complete active filesystem lookup proves absent?",
    ),
    "Q-HIDE-01": (
        "PE or ZIP-format content in a named NTFS stream",
        "Does a native named DATA stream contain a complete executable PE image "
        "or bounded ZIP archive with validated member content, independently of "
        "its name or intended use?",
    ),
    "Q-FILE-01": (
        "File content and NTFS allocation consistency",
        "Does a file show the separately specified BMP content-length or native "
        "NTFS allocation inconsistency, after accounting for its storage mode?",
    ),
    "Q-EXEC-01": (
        "Executable residue and active absence",
        "Is there Prefetch execution residue or Shimcache path residue for an "
        "executable absent from the active filesystem?",
    ),
    "Q-LOG-01": (
        "Security log clearing and record-sequence observations",
        "Does the Security log contain Event 1102, or a separately assessed "
        "internal record-ID discontinuity confirmed in a complete native log?",
    ),
    "Q-MEDIA-01": (
        "USB identity and referenced-volume history",
        "Does native USB evidence show the separately specified SetupAPI identity "
        "discrepancy or an inconsistent link-to-volume filename history?",
    ),
}


def technique(
    question_id: str,
    technique_id: str,
    subject_type: str,
    candidate_families: tuple[str, ...],
    candidate_observation_types: tuple[str, ...],
    required_families: tuple[str, ...],
    optional_families: tuple[str, ...],
    claim_boundary: str,
    alternative_required_families: tuple[tuple[str, ...], ...] = (),
) -> TechniqueDefinition:
    title, text = QUESTION_TEXT[question_id]
    return TechniqueDefinition(
        question_id=question_id,
        question_title=title,
        question_text=text,
        technique_id=technique_id,
        subject_type=subject_type,
        candidate_artifact_families=candidate_families,
        candidate_observation_types=candidate_observation_types,
        required_artifact_families=required_families,
        optional_artifact_families=optional_families,
        projected_artifact_families=tuple(
            dict.fromkeys((*required_families, *optional_families))
        ),
        claim_boundary=claim_boundary,
        alternative_required_artifact_families=tuple(
            tuple(item) for item in alternative_required_families
        ),
    )


TECHNIQUES = (
    technique(
        "Q-TIME-01",
        "timestamp_manipulation",
        "file",
        ("ntfs.mft",),
        ("mft_file_record", "si_fn_timestamp_difference"),
        ("ntfs.mft", "ntfs.usn"),
        ("ntfs.logfile",),
        (
            "Support a candidate only when the same exact NTFS object has SI "
            "created and modified timestamps that are each at least one minute "
            "earlier than their corresponding FN timestamp, and a same-object "
            "USN BasicInfoChange either is logged at or after the SI "
            "record-change timestamp and less than one second later, or is the "
            "object's highest retained USN record and follows the SI record-change "
            "timestamp by a minute or more, or the retained $LogFile holds a "
            "committed same-object $STANDARD_INFORMATION update whose undo values "
            "are the original created and modified times and whose redo values "
            "are the current backdated ones, each at least one minute earlier (a "
            "logged backdating transition, independent of the journal); that "
            "transition also supports an object when the SI-versus-FN predicate "
            "does not hold. These intervals are study indicator thresholds, not "
            "NTFS timing guarantees. USN BasicInfoChange may describe ordinary "
            "attributes or timestamps: correlation alone does not prove which SI "
            "fields changed, that record-change was backdated, or the purpose of "
            "the event. FILE_CREATE or proximity to creation does not veto a "
            "qualifying indicator; copying/restoration may produce the same facts. A "
            "shared created/modified offset and whole-second SI values are "
            "reported as descriptive patterns without tool attribution or gating; SI last-access is "
            "reported but not required, because NTFS rewrites it on ordinary "
            "reads. Mismatch count, uncorroborated SI-FN drift, or filesystem "
            "activity without that bounded correlation is insufficient. A missing "
            "BasicInfoChange counts as absence only when the SI record-change "
            "time lies inside the retained USN journal window reported by the "
            "collection; outside that window, or without one, the decision is "
            "indeterminate. The finding is the bounded timestamp indicator or "
            "verified logged transition; cause and intent remain unresolved."
        ),
        alternative_required_families=(("ntfs.mft", "ntfs.logfile"),),
    ),
    technique(
        "Q-DEL-01",
        "deleted_file_journal_residue",
        "file",
        ("ntfs.usn",),
        ("usn_file_delete", "usn_rename_old_name"),
        ("ntfs.usn", "ntfs.mft"),
        ("ntfs.logfile",),
        (
            "Support a candidate only when same-entity USN FileDelete residue "
            "exists and every delete record has a supported active-$MFT check "
            "reporting the object absent. Rename-old-name residue alone, an active "
            "object, or an unresolved absence check is insufficient. This does not "
            "attribute deletion."
        ),
    ),
    technique(
        "Q-DEL-02",
        "typed_path_residue",
        "registry_path",
        ("windows.registry.typed_paths",),
        ("typed_path_seen",),
        ("windows.registry.typed_paths", "ntfs.mft"),
        ("ntfs.usn",),
        (
            "Support a candidate only when the subject is an absolute local drive "
            "path, a registry record identifies the exact Explorer TypedPaths key, "
            "any supplied registry value agrees with that path, and every residue "
            "record has a supported active-$MFT check reporting the path object "
            "absent. Other registry and shell-artifact records do not satisfy this "
            "bounded claim. Non-local paths, active objects, or unresolved "
            "absence checks are insufficient. This does not establish deletion, "
            "user intent, or recover content."
        ),
    ),
    technique(
        "Q-DEL-03",
        "i30_directory_residue",
        "directory_entry",
        ("ntfs.i30",),
        ("i30_directory_scan", "i30_filename_residue"),
        ("ntfs.i30", "ntfs.mft"),
        ("ntfs.usn",),
        (
            "Support a candidate only when at least one candidate $I30 filename "
            "residue record is explicitly slack or unlinked, has a nonnegative file-reference entry "
            "and a positive sequence value, and has a supported active-$MFT check "
            "targeting the exact referenced object on the same volume and reporting "
            "that object absent. This is the referenced child's lookup, not the "
            "parent directory's presence. If a scan record exists, it must be the only "
            "scan, completely cover resident index-root, MFT-record slack and every "
            "present index-allocation stream with its bitmap, and report the observed residue "
            "count. Other children may remain active. Contradictory lookups for the "
            "same child, invalid identities and incomplete scans are insufficient. "
            "This does not establish deletion "
            "intent."
        ),
    ),
    technique(
        "Q-HIDE-01",
        "alternate_data_stream",
        "file",
        ("ntfs.ads",),
        ("named_data_stream",),
        ("ntfs.ads", "ntfs.mft"),
        (),
        (
            'Support an exact NTFS host only when all enumerated named DATA streams have '
            'complete native bytes and matching content identities, and at least one '
            'contains either a complete PE image or a complete bounded ZIP archive. PE '
            'requires MZ, bounded PE/optional headers, executable-image characteristics, '
            '1 to 96 complete sections and nonempty executable section data. ZIP requires '
            'one disk, ZIP32 stored or deflate data, at most 32 entries, matching '
            'local/central/end records with complete nonoverlapping byte coverage, '
            'verified decompressed sizes and CRC32 for every member, at most 32 MiB stream '
            'bytes, 8 MiB per member and 16 MiB expanded total, and at least one nonempty member. Names, '
            'rarity, entropy and intended use do not decide this content claim. A valid '
            'backup ZIP also satisfies it. Empty archives and ordinary metadata do not; '
            'incomplete or unsupported ZIP/PE-shaped content is insufficient. This '
            'establishes format content in a named stream, not execution, malicious '
            'intent or unauthorized concealment.'
        ),
    ),
    technique(
        "Q-FILE-01",
        "bitmap_trailing_data",
        "file",
        ("ntfs.file_size_allocation",),
        ("logical_allocated_size_record",),
        ("ntfs.file_size_allocation", "ntfs.mft", "collected.file.content"),
        (),
        (
            "Support a candidate only when exactly one unnamed base-DATA storage "
            "record and one materialized BMP-content record resolve to the same exact "
            "file; the storage record must be parse-clean, resident or nonresident, non-sparse, "
            "non-compressed, non-encrypted, and have valid flags, matching MFTECmd "
            "identity, a complete attribute chain and runlist, and lowest VCN zero. "
            "Valid nonnegative logical, MFTECmd, and materialized lengths must be "
            "equal. For the current 40-byte DIB, 24-bit BI_RGB subset with no palette, "
            "require zero reserved fields, pixel offset 54, and a declared end equal "
            "to 54 plus DWORD-aligned row bytes times absolute height. A complete "
            "native file ending before that boundary supports truncation; bytes "
            "after it support trailing content. Retain at least the complete 54-byte "
            "header. Historical records lacking the numeric geometry retain only "
            "their former nonresident trailing-content scope. Compare the "
            "numeric measurements; a precomputed mismatch label is not evidence. "
            "Special-storage modes, unsupported BMP layouts, "
            "incomplete contracts, or disagreement among measured lengths are "
            "insufficient. This does not establish intent."
        ),
    ),
    technique(
        "Q-EXEC-01",
        "prefetch_missing_executable",
        "executable",
        ("windows.prefetch",),
        ("prefetch_execution",),
        ("windows.prefetch", "ntfs.mft"),
        (),
        (
            "Support a candidate only when a parsed Prefetch record identifies the "
            "candidate executable by its native executable name, has a positive "
            "integer run count and a parseable last-run timestamp, and "
            "every matching residue record has a supported active-$MFT check reporting "
            "the executable absent. An active executable or unresolved absence check "
            "is insufficient. When the collection shows application prefetching "
            "disabled (EnablePrefetcher other than 1 or 3, or SysMain disabled), a "
            "candidate without a Prefetch record is indeterminate; a retained "
            "Prefetch record is still assessed, because the current policy cannot "
            "erase records from an earlier policy state. This is execution "
            "residue, not generalized deletion proof."
        ),
    ),
    technique(
        "Q-EXEC-01",
        "shimcache_path_residue",
        "executable",
        ("windows.registry.shimcache",),
        ("shimcache_path_seen",),
        ("windows.registry.shimcache", "ntfs.mft"),
        ("windows.registry.amcache", "windows.prefetch"),
        (
            "Support a candidate only when a parsed Shimcache record identifies the "
            "candidate path and "
            "every matching residue record has a supported active-$MFT check reporting "
            "the executable absent. An active executable or unresolved absence check "
            "is insufficient. Shimcache residue does not prove execution or execution "
            "time; the hive holds only entries persisted at the last recorded "
            "shutdown, which is reported with the decision."
        ),
    ),
    technique(
        "Q-LOG-01",
        "security_log_clear_event",
        "event_log",
        ("windows.event_log.security", "windows.event_log.record_sequence"),
        ("event_id_1102", "event_record_id_gap"),
        ("windows.event_log.security",),
        ("windows.event_log.record_sequence",),
        (
            "Support a candidate only when a same-log event record on the Security "
            "channel carries a non-boolean event ID whose normalized value is exactly 1102. "
            "Record-ID gaps alone or any contradictory 1102 event field are "
            "insufficient. This does not attribute the clearing action."
        ),
    ),
    technique(
        "Q-DEL-04",
        "shellbag_missing_directory",
        "registry_path",
        ("windows.registry.shellbag",),
        ("shellbag_path_seen",),
        ("windows.registry.shellbag", "ntfs.mft"),
        ("ntfs.usn",),
        (
            "Support only a native SBECmd Directory shell item with a BagMRU "
            "path and an absolute local directory path resolved either directly "
            "from AbsolutePath or through an exact shell-item MFT reference. "
            "Every record must agree with the candidate path and have a complete "
            "active-MFT path lookup reporting absence. Virtual shell namespace "
            "items, TypedPaths, unresolved paths and active folders are insufficient. "
            "Coverage requires the parsed UsrClass.dat or NTUSER.DAT hive retained "
            "in the collection next to the SBECmd output. This establishes "
            "directory-history residue (the folder existed and was visited, then "
            "removed) and current path absence, not who deleted it, when it was "
            "deleted, or malicious intent."
        ),
    ),
    technique(
        "Q-FILE-01",
        "ntfs_allocation_inconsistency",
        "file",
        ("ntfs.file_size_allocation",),
        ("ntfs_allocation_record",),
        ("ntfs.file_size_allocation", "ntfs.mft"),
        (),
        (
            "Assess one exact unnamed DATA attribute using native NTFS boot-sector "
            "geometry, complete in-volume extents and verified object identity. "
            "For ordinary nonresident, non-sparse, non-compressed, non-encrypted "
            "storage, support an allocated length inconsistent with the mapped "
            "cluster bytes, a logical length exceeding mapped capacity, or an "
            "allocated length not divisible by the cluster size, or distinct "
            "logical extents reusing overlapping physical clusters. Normal cluster "
            "rounding and preallocation are consistent. Resident data uses no "
            "external clusters. Unresolved chains, geometry or special storage modes "
            "are insufficient. An inconsistency is not evidence of malicious intent "
            "and is separate from BMP header/trailing-content analysis."
        ),
    ),
    technique(
        "Q-LOG-01",
        "event_record_sequence_gap",
        "event_log",
        ("windows.event_log.record_sequence",),
        ("event_log_scope_seen", "event_record_id_gap"),
        ("windows.event_log.record_sequence",),
        ("windows.event_log.security",),
        (
            "Support only an internal gap between two increasing Security log "
            "record identifiers in the same exact native EVTX source. Require a "
            "complete unfiltered retained-log projection independently matched to "
            "the native record envelopes, no duplicate or malformed records, and "
            "one scope summary with first/last IDs and counts consistent with every "
            "gap. A retained prefix starting above one is not an internal gap; "
            "filtered, truncated, merged or unverified collections are insufficient. "
            "A gap is supported even when the log also reports dropped audit "
            "events (Event 1101). "
            "This supports a sequence discontinuity only. Retention, missing "
            "historical records and the cause of a gap remain unresolved; clearing "
            "is assessed separately through Event 1102."
        ),
    ),
    technique(
        "Q-MEDIA-01",
        "usbstor_setupapi_discrepancy",
        "device",
        ("windows.registry.usbstor",),
        ("usb_device_seen",),
        ("windows.registry.usbstor", "windows.setupapi"),
        (),
        (
            "Support a candidate only when all scoped USBSTOR records resolve to one "
            "self-consistent instance-and-serial identity, at least one supplies a "
            "native SYSTEM ControlSet, all supplied ControlSets agree, and the bounded "
            "SetupAPI surface contains neither an exact identity match nor a partial "
            "serial or instance conflict. An exact SetupAPI match is consistent; no "
            "scoped USBSTOR record, malformed identities, conflicting identities, or "
            "ambiguous ControlSets are insufficient. The SetupAPI collection must "
            "report complete retained log intervals. Use the first parseable "
            "first_install or installed value from each device record that supplies "
            "installation evidence; arrival or key-write times cannot substitute. "
            "The RECmd USBSTOR plugin's installation values use UTC, including "
            "offset-free values labeled plugin_naive_clock; retain that raw "
            "basis label and apply this explicit comparison convention. Convert "
            "installation times to the guest's local clock with the recorded "
            "guest_utc_offset_minutes. If that offset is unavailable, "
            "containment must hold for every offset from -14 to +14 hours. Each "
            "installation time must fit wholly inside one retained interval, "
            "allowing ten minutes beyond that interval's final section timestamp "
            "and no extension before its start. Missing installation evidence, "
            "incompatible time bases, installation times in a gap between "
            "retained intervals, or unverifiable containment are "
            "indeterminate. "
            "This discrepancy does not establish device use or file transfer."
        ),
    ),
    technique(
        "Q-MEDIA-01", "usb_volume_activity_gap", "device",
        ("usb_volume",), ("usb_volume_reference_history",),
        ("usb_volume",), ("windows.registry.usbstor", "windows.setupapi"),
        (
            "Assess a hash-bound native virtual USB volume and native Shell Link. "
            "The NTFS boot volume serial is 64-bit; compare its low 32 bits "
            "(last eight hexadecimal digits) with the 32-bit LinkInfo and binding "
            "volume serials. Require those 32-bit values to match, along with the "
            "target path and exact historical Link/USN/binding file reference, "
            "complete active MFT and retained USN scans, and a journal interval "
            "covering the bound activity. The current MFT entry must be either "
            "the exact inactive reference or the same inactive entry at the "
            "immediate successor sequence after freeing, corroborated by a "
            "matching native filename and parent in historical-reference "
            "FILE_DELETE records. Keep current and historical sequences distinct; "
            "active entries with a nonmatching reference, sequence wrap or larger "
            "jumps are unresolved. "
            "Support only when the resolved prior object is inactive, the original "
            "path is absent, no same-reference original-name USN record remains, "
            "and same-reference alternative-name deletion history remains. A "
            "rename reason, unresolved reference, changed journal identity or "
            "incomplete retained interval is insufficient. Active original paths "
            "or retained original-name history are consistent. This is a bounded "
            "link-to-volume filename-history inconsistency, not absence of all "
            "object activity, proof of transfer, physical USB hardware, or intent."
        ),
    ),
)


def techniques_for_question(question_id: str) -> tuple[TechniqueDefinition, ...]:
    matches = tuple(item for item in TECHNIQUES if item.question_id == question_id)
    if not matches:
        raise ValueError(f"unknown analysis question: {question_id}")
    return matches
