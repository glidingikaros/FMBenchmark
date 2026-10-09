from types import SimpleNamespace

import pytest

from fmb.analysis import deterministic, shared_rules

CREATED = "2026-10-09 01:20:00.0000000"
SOURCE_WRITE = "2024-04-01 08:00:00.0000000"


def decide(monkeypatch, current: dict, update: dict) -> deterministic.Decision:
    record = SimpleNamespace(observation_type="mft_file_record", observation_id="r1", fields=current)
    logged = SimpleNamespace(observation_type="logfile_si_update", observation_id="r2", fields={
        "transaction_committed": True, "transaction_rolled_back": False, "binding_basis": "current_mft_record",
        "covered_fields": "created|modified|record_changed", **update})
    monkeypatch.setattr(deterministic, "_candidate_observations", lambda value, subject: [record, logged])
    monkeypatch.setattr(deterministic, "_observation_is_bound", lambda item, subject: True)
    monkeypatch.setattr(deterministic, "_logfile_si_updates", lambda rows, subject: [logged])
    monkeypatch.setattr(deterministic, "_timestamp", lambda value, subject, **kwargs:
                        deterministic.Decision("not_supported", "si_fn_comparison", ()))
    return shared_rules._timestamp_decision(None, None)


def transition(created=(CREATED, CREATED), modified=(CREATED, CREATED), changed=(CREATED, CREATED)) -> dict:
    return {"old_si_created": created[0], "new_si_created": created[1], "old_si_modified": modified[0],
            "new_si_modified": modified[1], "old_si_record_changed": changed[0], "new_si_record_changed": changed[1]}


def record(created=CREATED, modified=CREATED, changed=CREATED, named=CREATED) -> dict:
    return {"si_created": created, "si_modified": modified, "si_record_changed": changed, "fn_created": named}


@pytest.mark.parametrize("changed", ["2026-10-09 01:20:00.0100000", "2026-10-09 00:47:41.9164419"],
                         ids=["change_time_moves_on", "change_time_restored_from_the_source"])
def test_a_copy_restoring_its_source_times_is_not_backdating(monkeypatch, changed):
    update = transition(modified=(CREATED, SOURCE_WRITE), changed=(CREATED, changed))
    decision = decide(monkeypatch, record(modified=SOURCE_WRITE, changed=changed), update)
    assert (decision.outcome, decision.reason_code) == ("not_supported", "si_fn_comparison")


def test_a_build_26300_copy_of_where_exe_is_not_backdating(monkeypatch):
    created, written, changed = "2026-10-09 07:27:14.5111872", "2024-04-01 07:22:17.4660394", "2026-10-09 06:54:56.4276291"
    update = transition(created=(created, created), modified=(created, written), changed=(created, changed))
    decision = decide(monkeypatch, record(created=created, modified=written, changed=changed, named=created), update)
    assert (decision.outcome, decision.reason_code) == ("not_supported", "si_fn_comparison")


@pytest.mark.parametrize("current,update", [
    (record(created=SOURCE_WRITE, modified=SOURCE_WRITE),
     transition(created=(CREATED, SOURCE_WRITE), modified=(CREATED, SOURCE_WRITE))),
    (record(created="2026-09-01 00:00:00.0000000", modified="2026-10-09 00:59:59.9999999"),
     transition(created=("2026-09-01 00:00:00.0000000",) * 2,
                modified=("2026-10-09 01:00:00.0000000", "2026-10-09 00:59:59.9999999"))),
    (record(modified="2026-10-09 01:19:59.9999999"),
     transition(modified=(CREATED, "2026-10-09 01:19:59.9999999"))),
    (record(modified=SOURCE_WRITE, named="2026-10-09 02:00:00.0000000"),
     transition(modified=(CREATED, SOURCE_WRITE))),
    (record(changed=SOURCE_WRITE), transition(changed=(CREATED, SOURCE_WRITE))),
    (record(modified=SOURCE_WRITE), transition(modified=("2026-10-09 02:20:00.0000000", SOURCE_WRITE))),
    (record(modified=SOURCE_WRITE, changed="2024-03-01 00:00:00.0000000"),
     transition(modified=(CREATED, SOURCE_WRITE), changed=(CREATED, "2024-03-01 00:00:00.0000000"))),
], ids=["created_and_modified", "single_tick_on_an_old_file", "single_tick_on_a_new_file",
        "creation_time_not_its_own", "record_change_backdate", "write_time_backdated_an_hour_after_creation",
        "change_time_set_before_the_restored_write_time"])
def test_backdating_is_still_supported(monkeypatch, current, update):
    decision = decide(monkeypatch, current, update)
    assert (decision.outcome, decision.reason_code) == ("supported", "committed_native_timestamp_backdating")
