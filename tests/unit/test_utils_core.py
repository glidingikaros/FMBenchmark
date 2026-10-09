from __future__ import annotations
import hashlib


import json


import re


from datetime import datetime, timezone


from pathlib import Path


import pytest


from fmb.core.errors import ConfigurationError, FmbError, FmbInputError, SchemaValidationError, add_exception_note, exception_notes, run_cli


from fmb.core import coercion, hashing, json_io, ntfs_time, path_policy, processes, schemas


from fmb.core import env_lookup


def test_core_coercion_rejects_non_finite_numbers() -> None:
    assert coercion.parse_integral_int("0x10") == 16
    assert coercion.parse_integral_int("-0x10") == -16
    assert coercion.parse_integral_int(" +42 ") == 42
    assert coercion.parse_integral_int("1e3") == 1000
    assert coercion.parse_truncated_int("1e3") == 1000
    assert coercion.parse_integral_int("10.0") == 10
    assert coercion.parse_integral_int("10.5") is None
    assert coercion.parse_truncated_int("10.5") == 10
    assert coercion.parse_integral_int("9007199254740993.0") == 9007199254740993
    assert coercion.parse_integral_int("18446744073709551615.0") == 18446744073709551615
    assert coercion.parse_truncated_int("9007199254740993.9") == 9007199254740993
    assert coercion.parse_integral_int(True) is None
    assert coercion.parse_truncated_int(False) is None
    assert coercion.parse_integral_int("inf") is None
    assert coercion.parse_truncated_int("inf") is None


def test_hashing_helpers_use_canonical_json_and_file_chunks(tmp_path: Path) -> None:
    payload = {"b": 2, "a": [1, 2]}
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"abcdef")
    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")

    assert hashing.sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert hashing.sha256_text("abc") == hashing.sha256_bytes(b"abc")
    assert (
        hashing.sha256_text("café")
        == hashlib.sha256("café".encode("utf-8")).hexdigest()
    )
    assert hashing.sha256_file(empty_path) == hashlib.sha256(b"").hexdigest()
    assert (
        hashing.sha256_file(file_path, chunk_size=2)
        == hashlib.sha256(b"abcdef").hexdigest()
    )
    symlink_path = tmp_path / "payload-link.bin"
    try:
        symlink_path.symlink_to(file_path)
    except (NotImplementedError, OSError):
        pass
    else:
        assert (
            hashing.sha256_file(symlink_path) == hashlib.sha256(b"abcdef").hexdigest()
        )
    assert hashing.canonical_json_bytes(payload) == (
        json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    assert (
        hashing.sha256_json(payload)
        == hashlib.sha256(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        ).hexdigest()
    )
    assert hashing.sha256_json({"a": 1, "b": 2}) == hashing.sha256_json(
        {"b": 2, "a": 1}
    )
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        hashing.sha256_file(file_path, chunk_size=0)
    with pytest.raises(FileNotFoundError):
        hashing.sha256_file(tmp_path / "missing.bin")
    with pytest.raises((IsADirectoryError, PermissionError)):
        hashing.sha256_file(tmp_path)
    with pytest.raises(ValueError, match="Out of range float values"):
        hashing.sha256_json({"value": float("nan")})
    with pytest.raises(TypeError):
        hashing.sha256_json({1: "numeric key", "1": "string key"})


def test_hashing_validates_sha256_hex_strings() -> None:
    assert hashing.valid_sha256("a" * 64)
    assert hashing.valid_sha256("0123456789abcdef" * 4)
    assert not hashing.valid_sha256("A" * 64)
    assert not hashing.valid_sha256("a" * 63)
    assert not hashing.valid_sha256(None)


def test_json_io_loads_bom_objects_and_writes_atomically(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "payload.json"
    json_io.write_json(target, {"z": 1, "a": 2}, sort_keys=True)

    assert target.read_text(encoding="utf-8").startswith('{\n  "a"')
    assert json_io.load_json(target) == {"a": 2, "z": 1}
    assert json_io.load_json_object(target, label="config") == {"a": 2, "z": 1}
    assert not target.with_name("payload.json.tmp").exists()

    array_path = tmp_path / "array.json"
    array_path.write_text("[1]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        json_io.load_json_object(array_path)

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        json_io.load_json_object(invalid_path, error_type=ConfigurationError)

    non_finite_path = tmp_path / "non-finite.json"
    non_finite_path.write_text('{"value": NaN}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON constant: NaN"):
        json_io.load_json_object(non_finite_path)
    with pytest.raises(ValueError, match="Out of range float values"):
        json_io.write_json(tmp_path / "nan.json", {"value": float("nan")})

    json_io.write_json(target, {"replacement": True})
    assert json_io.load_json(target) == {"replacement": True}
    bad_target = tmp_path / "bad.json"
    with pytest.raises(TypeError):
        json_io.write_json(bad_target, {"value": object()})
    assert not bad_target.exists()
    assert list(tmp_path.glob(".bad.json.*.tmp")) == []


def test_ntfs_filetime_conversion_handles_epoch_fraction_and_invalid_values() -> None:
    filetime = (11644473601 * 10_000_000) + 1

    assert ntfs_time.filetime_to_utc_iso(1) == "1601-01-01T00:00:00.0000001Z"
    assert ntfs_time.filetime_to_utc_iso(10) == "1601-01-01T00:00:00.000001Z"
    assert ntfs_time.filetime_to_utc_iso(116444736000000000) == "1970-01-01T00:00:00Z"
    assert ntfs_time.filetime_to_utc_iso(filetime) == "1970-01-01T00:00:01.0000001Z"
    max_datetime = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    ntfs_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    max_delta = max_datetime - ntfs_epoch
    max_filetime = (
        (max_delta.days * 24 * 60 * 60) + max_delta.seconds
    ) * 10_000_000 + max_delta.microseconds * 10
    assert ntfs_time.filetime_to_utc_iso(max_filetime) == "9999-12-31T23:59:59.999999Z"
    assert ntfs_time.filetime_to_utc_iso(max_filetime + 10) is None
    assert ntfs_time.filetime_to_utc_iso(0) is None
    assert ntfs_time.filetime_to_utc_iso(10**30) is None


def test_env_lookup_helpers_prepare_names_and_read_first_nonblank() -> None:
    assert env_lookup.unique_env_names(("A", "B", "A")) == ("A", "B")
    assert env_lookup.read_env_value(environ={}) == (None, None)
    assert env_lookup.read_env_value(
        "MISSING",
        "BLANK",
        "SECOND",
        "FIRST",
        environ={"BLANK": "  ", "FIRST": " one ", "SECOND": " two "},
    ) == ("two", "SECOND")


def test_process_helpers_read_timeouts_and_format_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIMEOUT_SECONDS", "2.5")
    assert processes.timeout_seconds_from_env("TIMEOUT_SECONDS") == 2.5
    monkeypatch.setenv("TIMEOUT_SECONDS", "-1")
    with pytest.raises(
        ValueError, match="TIMEOUT_SECONDS must be a positive finite number"
    ):
        processes.timeout_seconds_from_env("TIMEOUT_SECONDS", default=9)
    monkeypatch.setenv("TIMEOUT_SECONDS", "nope")
    with pytest.raises(
        ValueError, match="TIMEOUT_SECONDS must be a positive finite number"
    ):
        processes.timeout_seconds_from_env("TIMEOUT_SECONDS", default=7)
    monkeypatch.setenv("TIMEOUT_SECONDS", "inf")
    with pytest.raises(
        ValueError, match="TIMEOUT_SECONDS must be a positive finite number"
    ):
        processes.timeout_seconds_from_env("TIMEOUT_SECONDS", default=7)
    monkeypatch.delenv("TIMEOUT_SECONDS")
    assert processes.timeout_seconds_from_env("TIMEOUT_SECONDS", default=7) == 7.0
    with pytest.raises(
        ValueError,
        match="TIMEOUT_SECONDS default timeout must be a positive finite number",
    ):
        processes.timeout_seconds_from_env("TIMEOUT_SECONDS", default=0)

    assert processes.command_line_text(["a b", "c"]) == "'a b' c"
    assert processes.decoded_process_output(b"caf\xe9") == "caf\ufffd"
    assert processes.process_output_excerpt("x" * 10, "err", limit=5) == "xxxxx..."
    assert processes.process_output_excerpt(b"out", b"err", limit=7) == "out\nerr"
    assert processes.process_output_excerpt("xy", "", limit=1) == "x..."
    with pytest.raises(ValueError, match="limit must be positive"):
        processes.process_output_excerpt("out", "", limit=0)


def test_error_payloads_notes_and_cli_boundaries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    error = FmbError("failed", details={"field": "value"})
    add_exception_note(error, "operator note")

    assert error.to_payload()["notes"] == ["operator note"]
    assert exception_notes(error) == ["operator note"]

    assert run_cli("fmb", lambda: 7) == 7
    assert run_cli("fmb", lambda: None) == 0
    assert run_cli("fmb", lambda: (_ for _ in ()).throw(FmbInputError("no"))) == 2
    assert "fmb: no" in capsys.readouterr().err
    interrupt = KeyboardInterrupt("ctrl-c")
    add_exception_note(interrupt, "operator stopped")
    assert run_cli("fmb", lambda: (_ for _ in ()).throw(interrupt)) == 130
    assert "operator stopped" in capsys.readouterr().err
    bad_value = ValueError("bad input")
    add_exception_note(bad_value, "bad value note")
    assert (
        run_cli(
            "fmb",
            lambda: (_ for _ in ()).throw(bad_value),
            input_exceptions=(ValueError,),
            json_errors=True,
        )
        == 2
    )
    input_payload = json.loads(capsys.readouterr().err)
    assert input_payload["notes"] == ["bad value note"]
    internal_error = RuntimeError("boom")
    add_exception_note(internal_error, "wrapped note")
    assert (
        run_cli("fmb", lambda: (_ for _ in ()).throw(internal_error), json_errors=True)
        == 1
    )
    internal_payload = json.loads(capsys.readouterr().err)
    assert internal_payload["error_kind"] == "internal_error"
    assert internal_payload["details"] == {
        "error_type": "RuntimeError",
        "error": "boom",
    }
    assert internal_payload["notes"] == ["wrapped note"]
    assert (
        run_cli(
            "fmb",
            lambda: (_ for _ in ()).throw(
                FmbError("odd", details={"nan": float("nan"), "path": Path("x")})
            ),
            json_errors=True,
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["details"] == {"nan": "nan", "path": "x"}
    cyclic_details: dict[str, object] = {"name": "cycle"}
    cyclic_details["self"] = cyclic_details
    assert (
        run_cli(
            "fmb",
            lambda: (_ for _ in ()).throw(FmbError("cyclic", details=cyclic_details)),
            json_errors=True,
        )
        == 2
    )
    cyclic_payload = json.loads(capsys.readouterr().err)
    assert cyclic_payload["details"]["self"] == "<recursive>"


def test_schema_validation_error_summarizes_its_errors() -> None:
    error = SchemaValidationError("schema.json", ["a", "b", "c"], max_display=2)
    assert str(error) == "a; b; ... 1 more validation error(s)"
    assert error.details["error_count"] == 3
    empty_error = SchemaValidationError("schema.json", [])
    assert str(empty_error) == "schema.json validation failed with no details"
    assert empty_error.details["error_count"] == 0


def test_schema_format_checker_requires_timezone_only_for_strings() -> None:
    assert schemas.is_rfc3339_date_time(123) is True
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05Z") is True
    assert schemas.is_rfc3339_date_time("2026-01-02t03:04:05z") is True
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05+00:00") is True
    assert schemas.is_rfc3339_date_time(" 2026-01-02T03:04:05Z") is False
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05Z ") is False
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05") is False
    assert schemas.is_rfc3339_date_time("2026-01-02 03:04:05+00:00") is False
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05+0000") is False
    assert schemas.is_rfc3339_date_time("2026-01-02T03:04:05,123+00:00") is False
    assert schemas.is_rfc3339_date_time("not-a-date") is False


def test_path_policy_accepts_only_portable_relative_paths() -> None:
    assert path_policy.is_portable_relative_path("nested folder/artifact file.json")
    assert not path_policy.is_portable_relative_path("../artifact.json")
    for unsafe_path in (
        "dir/file:stream.txt",
        "dir/a*b.txt",
        'dir/"quoted".txt',
        "dir/fi<le.txt",
        "dir/fi>le.txt",
        "dir/fi|le.txt",
        "dir/what?.txt",
        "dir/control\nname.txt",
        "dir/file.",
        "dir/file ",
        "dir/NUL.txt",
        "dir/COM1.log",
    ):
        assert not path_policy.is_portable_relative_path(unsafe_path), unsafe_path


def test_provenance_timestamps_are_utc_strings() -> None:
    from fmb.core import provenance

    iso = provenance.record_timestamp()
    assert datetime.fromisoformat(iso).tzinfo is timezone.utc
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", iso)
    assert "." not in iso


