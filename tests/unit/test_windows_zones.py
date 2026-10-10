import pytest

from fmb.core import paper_contract as contract
from fmb.core.windows_zones import WINDOWS_ZONES, windows_zone


def _usb_case(zone, timestamp="2026-07-01T12:00:00.000000"):
    return {"candidate_roster": [{
        "coverage": [{"scope": {"kind": "setupapi_log", "guest_time_zone": zone}}],
        "evidence_records": [{"record_type": "setupapi_usb_event",
                              "fields": {"timestamp_basis": "local_clock", "event_timestamp": timestamp}}]}]}


def test_every_standard_windows_zone_resolves_to_an_installed_iana_zone():
    assert len(WINDOWS_ZONES) == 139
    assert {name: windows_zone(name).key for name in WINDOWS_ZONES} == WINDOWS_ZONES
    assert WINDOWS_ZONES["Pacific Standard Time"] == "America/Los_Angeles"
    assert WINDOWS_ZONES["W. Europe Standard Time"] == "Europe/Berlin"


@pytest.mark.parametrize("name", ["Mars Standard Time", "pacific standard time", "", None, ["UTC"]])
def test_an_unknown_windows_zone_is_a_clear_value_error(name):
    with pytest.raises(ValueError, match="unknown Windows time zone") as error:
        windows_zone(name)
    assert not isinstance(error.value, KeyError)


@pytest.mark.parametrize("zone,expected", [
    ("Pacific Standard Time", "2026-07-01T19:00:00.000000Z"),
    ("W. Europe Standard Time", "2026-07-01T10:00:00.000000Z"),
    ("India Standard Time", "2026-07-01T06:30:00.000000Z"),
    ("UTC-11", "2026-07-01T23:00:00.000000Z"),
])
def test_setupapi_utc_view_converts_the_local_clock_of_any_windows_zone(zone, expected):
    case = _usb_case(zone)
    contract._setupapi_utc(case, None, True)
    assert case["candidate_roster"][0]["evidence_records"][0]["fields"]["event_timestamp_utc"] == expected


def test_setupapi_utc_view_refuses_an_unknown_zone_with_a_value_error():
    with pytest.raises(ValueError, match="unknown Windows time zone: 'Mars Standard Time'"):
        contract._setupapi_utc(_usb_case("Mars Standard Time"), None, True)
