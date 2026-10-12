from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from fmb.replication import host, run


def unfinished(folder: Path, size: int) -> Path:
    disk = folder / "generation" / "attempt-1" / "full_scale" / "a" / "full_scale.vmdk"
    disk.parent.mkdir(parents=True)
    disk.write_bytes(b"\0" * size)
    return disk


def test_the_disk_check_counts_what_unfinished_attempts_hold(tmp_path, monkeypatch):
    unfinished(tmp_path / "I1", 2**20)
    reclaimable = run.unpublished_gib(tmp_path / "I1" / "generation")
    assert reclaimable == pytest.approx(2**-10)
    monkeypatch.setattr(host, "free_gib", lambda root: 1.0)
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0 + run.SLACK_GIB + 2**-11)
    with pytest.raises(run.NoSpace):
        run.disk_space("I1", tmp_path)
    run.disk_space("I1", tmp_path, reclaimable)


def test_a_published_attempt_is_not_counted_as_reclaimable(tmp_path):
    disk = unfinished(tmp_path / "I1", 2**20)
    (disk.parent / "manifest.json").write_text("{}")
    assert run.unpublished_gib(tmp_path / "I1" / "generation") == 0


def test_again_never_deletes_an_image_another_fmb_is_generating(tmp_path):
    disk = unfinished(tmp_path / "I1", 16)
    image = SimpleNamespace(name="I1", path=tmp_path / "I1.json")
    with run.generating(tmp_path / "I1"), pytest.raises(SystemExit, match="another fmb is generating this image"):
        run.generate_one(image, tmp_path / "lock.json", tmp_path, attempts=1, again=True)
    assert disk.is_file()
