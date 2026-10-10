from __future__ import annotations

from datetime import datetime, timezone

from fmb.index.support.usb_devices import (
    normalize_usbstor_rows,
    parse_setupapi_surface,
)


def registry_row(
    key: str,
    name: str,
    value: str,
    *,
    value_type: str = "RegSz",
) -> dict[str, str]:
    return {
        "KeyPath": key,
        "ValueName": name,
        "ValueType": value_type,
        "ValueData": value,
    }


def registry_filetime(value: datetime) -> str:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    ticks = (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return "-".join(f"{byte:02X}" for byte in ticks.to_bytes(8, "little"))


def test_usbstor_native_device_properties_form_one_identity_record() -> None:
    key = r"ControlSet001\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
    property_root = key + r"\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
    rows = [
        (1, registry_row(key, "FriendlyName", "Shared label")),
        (
            2,
            registry_row(
                property_root + r"\0065",
                "",
                registry_filetime(datetime(2025, 12, 1, tzinfo=timezone.utc)),
                value_type="RegBinary",
            ),
        ),
        (
            3,
            registry_row(
                property_root + r"\0066",
                "",
                registry_filetime(datetime(2026, 1, 1, 10, tzinfo=timezone.utc)),
                value_type="RegBinary",
            ),
        ),
        (
            4,
            registry_row(
                property_root + r"\0067",
                "",
                registry_filetime(datetime(2026, 1, 1, 11, tzinfo=timezone.utc)),
                value_type="RegBinary",
            ),
        ),
    ]

    records, source_count = normalize_usbstor_rows(rows)

    assert source_count == 4
    assert len(records) == 1
    assert records[0]["device_instance_id"].casefold() == (
        r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1".casefold()
    )
    assert records[0]["serial_number"] == "SERIAL-1"
    assert records[0]["control_set"] == "ControlSet001"
    assert records[0]["timestamp_basis"] == "native_device_property_filetime"
    assert records[0]["first_install"] == "2025-12-01T00:00:00+00:00"
    assert records[0]["last_arrival"] == "2026-01-01T10:00:00+00:00"
    assert records[0]["last_removal"] == "2026-01-01T11:00:00+00:00"
    assert "filesystem_path" not in records[0]


def test_usbstor_plugin_row_forms_exact_identity_and_preserves_timestamps() -> None:
    records, source_count = normalize_usbstor_rows(
        [
            (
                1,
                {
                    "Timestamp": "2026-01-04T09:00:00Z",
                    "BatchKeyPath": (
                        r"ROOT\ControlSet012\Enum\USBSTOR"
                        r"\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00"
                    ),
                    "Manufacturer": "Generic",
                    "Title": "Flash Disk",
                    "Version": "1.00",
                    "SerialNumber": "435A30E52B19",
                    "DeviceName": "Generic Flash Disk",
                    "DiskId": "{11111111-2222-3333-4444-555555555555}",
                    "Installed": "2026-01-01T08:00:00Z",
                    "FirstInstalled": "2026-01-01T07:00:00+00:00",
                    "LastConnected": "2026-01-03T10:30:00+01:00",
                    "LastRemoved": "2026-01-03T11:00:00+01:00",
                },
            )
        ]
    )

    assert source_count == 1
    assert len(records) == 1
    assert records[0]["device_instance_id"] == (
        r"USBSTOR\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00\435A30E52B19"
    )
    assert records[0]["serial_number"] == "435A30E52B19"
    assert records[0]["control_set"] == "ControlSet012"
    assert records[0]["friendly_name"] == "Generic Flash Disk"
    assert records[0]["registry_key_timestamp"] == "2026-01-04T09:00:00+00:00"
    assert records[0]["installed"] == "2026-01-01T08:00:00+00:00"
    assert records[0]["first_install"] == "2026-01-01T07:00:00+00:00"
    assert records[0]["last_arrival"] == "2026-01-03T09:30:00+00:00"
    assert records[0]["last_removal"] == "2026-01-03T10:00:00+00:00"
    assert records[0]["timestamp_basis"] == "explicit_plugin_timestamp"


def test_usbstor_plugin_rows_reject_generic_batch_paths_and_fuzzy_values() -> None:
    records, source_count = normalize_usbstor_rows(
        [
            (
                1,
                {
                    "BatchKeyPath": r"ROOT\ControlSet001\Enum\USBSTOR\*",
                    "SerialNumber": "SERIAL-1",
                },
            ),
            (
                2,
                {
                    "BatchKeyPath": r"ROOT\ControlSet001\Enum\USBSTOR",
                    "ValueData": (
                        r"USBSTOR\Disk&Ven_Generic&Prod_Flash_Disk\SERIAL-2"
                    ),
                },
            ),
            (
                3,
                {
                    "BatchKeyPath": r"ROOT\ControlSet001\Services\USBSTOR",
                    "SerialNumber": "SERIAL-3",
                },
            ),
        ]
    )

    assert source_count == 3
    assert records == []


def test_usbstor_plugin_conflicting_timestamp_is_not_preserved() -> None:
    batch_key = (
        r"ROOT\ControlSet001\Enum\USBSTOR"
        r"\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00"
    )
    records, _ = normalize_usbstor_rows(
        [
            (
                1,
                {
                    "BatchKeyPath": batch_key,
                    "SerialNumber": "SERIAL-1",
                    "LastConnected": "2026-01-03T10:30:00Z",
                },
            ),
            (
                2,
                {
                    "BatchKeyPath": batch_key,
                    "SerialNumber": "SERIAL-1",
                    "LastConnected": "2026-01-03T11:30:00Z",
                },
            ),
        ]
    )

    assert len(records) == 1
    assert records[0]["last_arrival"] == ""
    assert records[0]["timestamp_basis"] == "ambiguous"
    assert "last_arrival" not in records[0]["time_provenance"]


def test_usbstor_ignores_custom_paths_and_generic_time_columns() -> None:
    key = r"ControlSet001\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
    custom_prefix = "".join(("F", "md"))
    records, _ = normalize_usbstor_rows(
        [
            (
                1,
                registry_row(
                    key,
                    custom_prefix + "FilesystemPath",
                    r"C:\Users\analyst\Documents\answer.txt",
                ),
            ),
            (
                2,
                {
                    "DeviceInstanceId": r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-2",
                    "SerialNumber": "SERIAL-2",
                    "FilesystemPath": r"E:\private\answer.txt",
                    "FirstSeen": "2026-01-01T10:00:00Z",
                    "LastSeen": "2026-01-01T11:00:00Z",
                },
            ),
        ]
    )

    assert len(records) == 2
    for record in records:
        assert "filesystem_path" not in record
        assert record["last_arrival"] == ""
        assert record["last_removal"] == ""
        assert record["timestamp_basis"] == "unavailable"


def test_equal_labels_do_not_merge_distinct_device_instances() -> None:
    rows = [
        (
            1,
            {
                "DeviceInstanceId": r"USBSTOR\Disk&Ven_ACME\ONE",
                "SerialNumber": "ONE",
                "FriendlyName": "Shared label",
            },
        ),
        (
            2,
            {
                "DeviceInstanceId": r"USBSTOR\Disk&Ven_ACME\TWO",
                "SerialNumber": "TWO",
                "FriendlyName": "Shared label",
            },
        ),
    ]

    records, _ = normalize_usbstor_rows(rows)

    assert {item["serial_number"] for item in records} == {"ONE", "TWO"}


def test_same_device_in_distinct_control_sets_remains_distinct() -> None:
    suffix = r"\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
    records, _ = normalize_usbstor_rows(
        [
            (1, registry_row("ControlSet001" + suffix, "FriendlyName", "Media")),
            (2, registry_row("ControlSet002" + suffix, "FriendlyName", "Media")),
        ]
    )

    assert {record["control_set"] for record in records} == {
        "ControlSet001",
        "ControlSet002",
    }


def test_setupapi_sections_bind_timestamp_to_device_identity() -> None:
    records, source_count, _surface = parse_setupapi_surface(
        [
            (
                1,
                ">>>  [Device Install (Hardware initiated) - "
                r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1]",
            ),
            (2, ">>>  Section start 2026-01-01T10:00:00Z"),
            (3, "<<<  Section end 2026-01-01T10:00:01Z"),
        ]
    )

    assert source_count == 3
    assert len(records) == 1
    assert records[0]["serial_number"] == "SERIAL-1"
    assert records[0]["event_timestamp"] == "2026-01-01T10:00:00+00:00"
    assert records[0]["timestamp_basis"] == "explicit_offset"


def test_setupapi_wpd_header_normalizes_to_exact_usbstor_identity() -> None:
    serial = "A1B2C3D4&0"
    records, _, _surface = parse_setupapi_surface(
        [
            (
                1,
                ">>>  [Device Install (Hardware initiated) - "
                r"SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_ACME&Prod_Portable"
                rf"&Rev_1.00#{serial}#"
                r"{53f56307-b6bf-11d0-94f2-00a0c91efb8b}]",
            ),
            (2, ">>>  Section start 2026/01/01 10:00:00.000"),
        ]
    )

    assert len(records) == 1
    assert records[0]["device_instance_id"].casefold() == (
        r"USBSTOR\Disk&Ven_ACME&Prod_Portable&Rev_1.00\A1B2C3D4&0".casefold()
    )
    assert records[0]["serial_number"] == serial
    assert records[0]["timestamp_basis"] == "local_clock"


def test_setupapi_non_usb_section_closes_the_previous_usb_section() -> None:
    records, _, _surface = parse_setupapi_surface(
        [
            (
                1,
                ">>>  [Device Install (Hardware initiated) - "
                r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1]",
            ),
            (2, ">>>  [Device Install (Hardware initiated) - PCI\\VEN_1234]"),
            (3, ">>>  Section start 2026-01-01T10:00:00Z"),
        ]
    )

    assert len(records) == 1
    assert records[0]["serial_number"] == "SERIAL-1"
    assert records[0]["event_timestamp"] == ""
    assert records[0]["timestamp_basis"] == "missing"
