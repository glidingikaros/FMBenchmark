from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from fmb.index.contract import constants


def assert_value_error(message: str, call: Callable[[], Any]) -> None:
    with pytest.raises(ValueError) as error:
        call()
    assert str(error.value) == message


def test_contract_vocabulary_validators_return_existing_values() -> None:
    assert constants.collection_tool_for_contract("kape", label="case") == "kape"
    assert constants.parser_tool_for_contract(" MFTECmd ", label="case") == "mftecmd"
    assert constants.artifact_families_for_parser_kind("ntfs_mft", label="case") == {
        "ntfs.mft"
    }
    assert (
        constants.observation_type_for_contract(
            "si_fn_timestamp_difference", label="case"
        )
        == "si_fn_timestamp_difference"
    )


def test_contract_vocabulary_validators_preserve_missing_value_messages() -> None:
    assert_value_error(
        "case has no collection tool",
        lambda: constants.collection_tool_for_contract("", label="case"),
    )
    assert_value_error(
        "case has no parser",
        lambda: constants.parser_tool_for_contract("  ", label="case"),
    )
    assert_value_error(
        "case has no parser_kind",
        lambda: constants.artifact_families_for_parser_kind("\t", label="case"),
    )
    assert_value_error(
        "case has no observation_type",
        lambda: constants.observation_type_for_contract("", label="case"),
    )


def test_contract_vocabulary_validators_preserve_unsupported_value_messages() -> None:
    assert_value_error(
        "unsupported collection tool: other",
        lambda: constants.collection_tool_for_contract("other", label="case"),
    )
    assert_value_error(
        "case uses unsupported parser tool: MFTECmd.exe",
        lambda: constants.parser_tool_for_contract("MFTECmd.exe", label="case"),
    )
    assert_value_error(
        "case uses unsupported parser_kind: ntfs_unknown",
        lambda: constants.artifact_families_for_parser_kind(
            "ntfs_unknown", label="case"
        ),
    )
    assert_value_error(
        "case has unsupported observation_type: unknown",
        lambda: constants.observation_type_for_contract("unknown", label="case"),
    )
