from contextvars import ContextVar
import hashlib
import threading
import time

import pytest

from fmb.core.hashing import hashing_threads, in_order, sha256_file
from fmb.core.truth_guard import truth_blind_reads
from fmb.pipeline import reads

LABEL = ContextVar("test_hashing_label", default=None)


def test_in_order_hashes_files_at_once_and_returns_them_in_order(tmp_path):
    paths = [tmp_path / f"extent-s00{index}.vmdk" for index in range(1, 6)]
    for index, path in enumerate(paths):
        path.write_bytes(bytes([index]) * (1000 + index))
    assert in_order(sha256_file, paths, workers=3) == [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    both = threading.Barrier(2, timeout=10)

    def meet(item):
        both.wait()  # returns only while the other call runs too
        return item

    assert in_order(meet, ["first", "second"], workers=2) == ["first", "second"]


def test_in_order_reports_the_first_failing_item_not_the_first_to_fail():
    later_failed = threading.Event()

    def call(item):
        if item == 1:
            assert later_failed.wait(10)
            raise FileNotFoundError("first in order")
        if item == 2:
            later_failed.set()
            raise ValueError("first to fail")
        return item

    with pytest.raises(FileNotFoundError, match="first in order"):
        in_order(call, [0, 1, 2], workers=3)


def test_calls_run_in_the_callers_context_so_the_audits_see_their_opens(tmp_path):
    generation = tmp_path / "generation"
    generation.mkdir()
    public, private = generation / "manifest.json", generation / "recipe.json"
    public.write_text("{}")
    private.write_text("{}")

    def label(path):
        sha256_file(path)
        return LABEL.get()

    token = LABEL.set("caller")
    try:
        with reads.measured() as seen:
            assert in_order(label, [public], workers=2) == ["caller"]
    finally:
        LABEL.reset(token)
    assert str(public) in seen
    with truth_blind_reads(generation) as guard, pytest.raises(PermissionError, match="truth-blind"):
        in_order(sha256_file, [public, private], workers=2)
    assert str(private.resolve()) in guard["denied"]


def test_leaving_the_block_drops_the_calls_not_started():
    started, queued, ran = threading.Event(), [], []

    def running():
        started.set()
        deadline = time.monotonic() + 10
        while not (queued and queued[0].cancelled()) and time.monotonic() < deadline:
            time.sleep(0.01)

    with pytest.raises(RuntimeError, match="caller failed"):
        with hashing_threads(1) as submit:
            submit(running)
            queued.append(submit(ran.append, "queued"))
            assert started.wait(10)
            raise RuntimeError("caller failed")
    assert ran == [] and queued[0].cancelled()
