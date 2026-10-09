from __future__ import annotations

import json
import shutil
import struct
import subprocess
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from test_generation_logfile_retention import _fixture_volume
from test_iteration2_generation import guest_plan, load
from test_logfile_adapter import driver_document, stomp_record
from test_logfile_scanner import FILETIME_2010, FILETIME_2026_B, file_record_bytes

from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.scanners import logfile_runtime


@pytest.mark.parametrize("seed", [0, 2])
def test_known_previously_forward_seeds_now_precede_the_unchanged_archive_control(seed):
    population = load("population")
    control = load("archive_control")
    archive = datetime.fromisoformat(control.ARCHIVE_LAST_WRITE_UTC)
    stamps = population._seeded_stomp_timestamps(seed)
    assert len(set(stamps)) == 2
    assert population.STOMP_YEAR_RANGE == (2004, 2017)
    assert all(datetime.fromisoformat(stamp.replace("Z", "+00:00")) <= archive - timedelta(seconds=60)
               for stamp in stamps)
    assert stamps == population._seeded_stomp_timestamps(seed)


def test_current_plan_requires_both_native_prevalues_but_legacy_receipt_stays_readable(verified_receipts):
    population = load("population")
    plan = guest_plan(population, seed=0)
    inputs = plan["scenario_inputs"]["timestomp_01"]
    assert inputs["minimum_backdating_seconds"] == 60
    assert inputs["archive_last_write_utc"] == population.archive_control.ARCHIVE_LAST_WRITE_UTC
    receipts = verified_receipts(population, plan, case="positive")
    population.validate_guest_receipts(plan, receipts, case="positive")
    original = deepcopy(receipts)
    timestamp_receipt = next(row for row in receipts if row["scenario_id"] == "timestomp_01")
    for instance in timestamp_receipt["instances"]:
        instance.pop("original_modified_utc")
    with pytest.raises(population.PopulationError, match="invalid instances"):
        population.validate_guest_receipts(plan, receipts, case="positive")
    legacy = deepcopy(plan)
    legacy["scenario_inputs"]["timestomp_01"].pop("minimum_backdating_seconds")
    legacy["scenario_inputs"]["timestomp_01"].pop("archive_last_write_utc")
    population.validate_guest_receipts(legacy, receipts, case="positive")
    forward = next(row for row in original if row["scenario_id"] == "timestomp_01")["instances"][0]
    forward["original_modified_utc"] = forward["assigned_timestamp"]
    with pytest.raises(population.PopulationError, match="both fields backdated"):
        population.validate_guest_receipts(plan, original, case="positive")


@pytest.mark.parametrize("offset_ticks,exact_old_binding,expected", [
    (-10_000_000, False, False), (0, False, False),
    (60 * 10_000_000 - 1, False, False), (60 * 10_000_000, False, True),
    (60 * 10_000_000, True, True), (60 * 10_000_000, "wrong", False),
])
def test_native_retention_requires_modified_backdating_even_for_legacy_target(
    tmp_path, monkeypatch, offset_ticks, exact_old_binding, expected,
):
    module = load("logfile_retention")
    log = tmp_path / "$LogFile"
    log.write_bytes(b"public retained transition fixture")
    record = stomp_record(lsn=500, entry=10)
    undo = bytearray.fromhex(record["undo_hex"])
    old_modified = FILETIME_2010 + offset_ticks
    struct.pack_into("<Q", undo, 8, old_modified)
    record["undo_hex"] = undo.hex()
    document = driver_document([record], logfile=log)
    mft = bytearray(11 * 1024)
    mft[10 * 1024:] = file_record_bytes(entry=10, sequence=3, lsn=500)
    _fixture_volume(monkeypatch, bytes(mft), log.read_bytes())
    monkeypatch.setattr(logfile_runtime, "logfile_runtime_availability", lambda: {"available": True})
    monkeypatch.setattr(logfile_runtime, "run_logfile_driver", lambda *a, **k: deepcopy(document))
    target = {"path": r"C:\Records\Files\public.txt", "assigned_timestamp": filetime_to_utc_iso(FILETIME_2010),
              "original_creation_utc": filetime_to_utc_iso(FILETIME_2026_B)}
    if exact_old_binding:
        target["original_modified_utc"] = filetime_to_utc_iso(old_modified + (1 if exact_old_binding == "wrong" else 0))
    if expected:
        receipt = module.check_logfile_retention(tmp_path / "public.vmdk", targets=[target], output_dir=tmp_path, require=True)
        assert receipt["status"] == "retained"
    else:
        with pytest.raises(ValueError, match="not retained"):
            module.check_logfile_retention(tmp_path / "public.vmdk", targets=[target], output_dir=tmp_path, require=True)


def test_exact_guest_guard_rejects_forward_and_subminute_native_fields(tmp_path):
    import yaml

    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell AST/guard runtime unavailable")
    source = Path(__file__).resolve().parents[2] / "src/fmb/generation/ansible/roles/manipulation/tasks/timestomp_01.yml"
    body = yaml.safe_load(source.read_text())[0]["ansible.windows.win_shell"]
    start = body.index("$fmbFailurePhase = 'verify_backdating_precondition'")
    guard = body[start:body.index("[LocalFileTimes]::SetAllUtc", start)]
    script = """$ErrorActionPreference='Stop'
$stompUtc=[DateTime]::Parse('2010-01-01T00:00:00Z').ToUniversalTime()
$results=@()
foreach($field in @('CreationTimeUtc','LastWriteTimeUtc')) {
 foreach($offset in @(-10000000L,0L,599999999L,600000000L)) {
  $file=[pscustomobject]@{CreationTimeUtc=$stompUtc.AddSeconds(120);LastWriteTimeUtc=$stompUtc.AddSeconds(120)}
  $file.$field=$stompUtc.AddTicks($offset)
  $accepted=$true
  try {
""" + guard + """
  } catch { $accepted=$false }
  $results += [ordered]@{field=$field;offset_ticks=$offset;accepted=$accepted}
 }
}
$results | ConvertTo-Json -Compress
"""
    path = tmp_path / "native-backdating-guard.ps1"
    path.write_text(script)
    result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-File", str(path)],
                            capture_output=True, text=True, check=True, timeout=20)
    rows = json.loads(result.stdout)
    assert len(rows) == 8
    assert all(row["accepted"] is (row["offset_ticks"] >= 600_000_000) for row in rows)
