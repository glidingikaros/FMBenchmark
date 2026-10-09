from __future__ import annotations
from dataclasses import dataclass

BROAD_QUESTION_GROUP_VERSION = "stefan_broad_questions_20260912.v1"


@dataclass(frozen=True)
class BroadQuestion:
    question_id: str
    group_id: str
    title: str
    question_text: str
    technique_ids: tuple[str, ...]


BROAD_QUESTIONS = (
    BroadQuestion(
        "BQ-TIME-01",
        "stefan_timestamp_backdating",
        "Timestamp backdating",
        "Assess whether these files show evidence of timestamp backdating.",
        ("timestamp_manipulation",),
    ),
    BroadQuestion(
        "BQ-DELETE-01",
        "stefan_deleted_file_or_path_history",
        "Deleted file or path history",
        (
            "Assess whether these files or paths retain evidence that they were "
            "deleted or are no longer present."
        ),
        ("deleted_file_journal_residue", "typed_path_residue"),
    ),
    BroadQuestion(
        "BQ-SHELLBAG-01",
        "stefan_shellbag_path_history",
        "Shellbag path history",
        (
            "Assess whether these directory paths retain Shellbag history despite "
            "no longer being present."
        ),
        ("shellbag_missing_directory",),
    ),
    BroadQuestion(
        "BQ-DIRECTORY-01",
        "stefan_directory_index_residue",
        "Directory index residue",
        (
            "Assess whether these directory entries retain index evidence for "
            "objects that are no longer present."
        ),
        ("i30_directory_residue",),
    ),
    BroadQuestion(
        "BQ-STREAM-01",
        "stefan_named_stream_content",
        "Named stream content",
        (
            "Assess whether these files contain PE or ZIP content in a named "
            "NTFS stream."
        ),
        ("alternate_data_stream",),
    ),
    BroadQuestion(
        "BQ-USB-01",
        "stefan_usb_history_consistency",
        "USB history consistency",
        (
            "Assess whether this USB device and referenced volume show "
            "inconsistencies in installation identity or filename history."
        ),
        ("usbstor_setupapi_discrepancy", "usb_volume_activity_gap"),
    ),
    BroadQuestion(
        "BQ-FILE-01",
        "stefan_file_integrity",
        "File integrity",
        (
            "Assess whether these files show content-length or NTFS allocation "
            "inconsistencies."
        ),
        ("bitmap_trailing_data", "ntfs_allocation_inconsistency"),
    ),
    BroadQuestion(
        "BQ-EXEC-01",
        "stefan_executable_residue",
        "Executable residue",
        (
            "Assess whether these executables have Prefetch or Shimcache residue "
            "despite no longer being present."
        ),
        ("prefetch_missing_executable", "shimcache_path_residue"),
    ),
    BroadQuestion(
        "BQ-LOG-01",
        "stefan_security_log_history",
        "Security log history",
        (
            "Assess whether this Security log shows evidence of clearing or an "
            "internal record-sequence discontinuity."
        ),
        ("security_log_clear_event", "event_record_sequence_gap"),
    ),
)


def broad_question(question_id: str) -> BroadQuestion:
    for item in BROAD_QUESTIONS:
        if item.question_id == question_id:
            return item
    raise KeyError(f"unknown broad question: {question_id}")
