from __future__ import annotations

import os
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
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0 + host.RESULT_GIB + 2**-11)
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


def test_two_fmb_runs_that_find_the_lock_stale_together_renew_it_once(tmp_path):
    import json
    import subprocess
    import sys

    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"old": True}))
    script = (
        "import json, sys, time\n"
        "from pathlib import Path\n"
        "from fmb.replication import run\n"
        "lock = Path(sys.argv[1])\n"
        "seen = b'{\"old\": true}'\n"  # the lock both found stale
        "def dependency_lock(root):\n"
        "    time.sleep(1.0)\n"
        "    with (root / 'lock.json').open('x') as stream:\n"  # as the lock step: never over an existing lock
        "        json.dump({'by': sys.argv[2]}, stream)\n"
        "run.dependency_lock = dependency_lock\n"
        "time.sleep(float(sys.argv[3]))\n"
        "run.renew_lock(lock, seen)\n"
    )
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    runs = [subprocess.Popen([sys.executable, "-c", script, str(lock), name, delay], env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for name, delay in (("A", "0"), ("B", "0.3"))]
    outputs = [process.communicate(timeout=60)[0] for process in runs]
    assert [process.returncode for process in runs] == [0, 0], outputs
    assert len(list(tmp_path.glob("lock-*.json"))) == 1  # renewed once, by whichever came first
    assert json.loads(lock.read_text()) in ({"by": "A"}, {"by": "B"})
    assert sum("another fmb wrote a new dependency lock meanwhile; using it" in output for output in outputs) == 1
