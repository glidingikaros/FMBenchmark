import hashlib
import json
import os
import time

import pytest

from fmb.core import paper_integrity
from fmb.core.paper_integrity import source_files, verify_sources


@pytest.fixture
def locked(tmp_path):
    roots = {"package": tmp_path / "package", "data": tmp_path / "data"}
    for path in roots.values():
        path.mkdir()
    module = roots["package"] / "analysis/structured_content.py"
    module.parent.mkdir()
    module.write_text("def zip_content_evidence(*args): return False\n")
    assets = roots["package"] / "contracts"
    assets.mkdir()
    (assets / "schema.json").write_text("{}")
    manifest = tmp_path / "lock.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "paper_source_manifest.v1",
                "files": {
                    name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for name, p in source_files(roots).items()
                },
            }
        )
    )
    return roots, manifest, module


def test_decision_dependency_change_is_rejected(locked):
    roots, manifest, module = locked
    verify_sources(manifest, roots=roots)
    module.write_text("def zip_content_evidence(*args): return True\n")
    with pytest.raises(ValueError, match="implementation changed"):
        verify_sources(manifest, roots=roots)


@pytest.mark.parametrize("change", ["extra", "missing", "omitted_from_lock"])
def test_manifest_membership_is_exact(locked, change):
    roots, manifest, module = locked
    if change == "extra":
        (roots["package"] / "new_dependency.py").write_text("x=1\n")
    elif change == "missing":
        module.unlink()
    else:
        data = json.loads(manifest.read_text())
        data["files"].pop("package/analysis/structured_content.py")
        manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="membership"):
        verify_sources(manifest, roots=roots)


def test_a_rewrite_in_the_same_timestamp_tick_is_never_served_from_the_digest_cache(locked):
    roots, manifest, module = locked
    verify_sources(manifest, roots=roots)
    stamp = module.stat().st_mtime_ns
    module.write_text("def zip_content_evidence(*args): return 1 < 0\n")
    os.utime(module, ns=(stamp, stamp))
    with pytest.raises(ValueError, match="implementation changed"):
        verify_sources(manifest, roots=roots)


def test_an_old_file_is_hashed_once_and_rehashed_when_it_changes(locked):
    roots, manifest, module = locked
    old = time.time_ns() - 3_600_000_000_000
    os.utime(module, ns=(old, old))
    verify_sources(manifest, roots=roots)
    assert paper_integrity._DIGESTS[module][1] == hashlib.sha256(module.read_bytes()).hexdigest()
    module.write_text("def zip_content_evidence(*args): return True\n")
    with pytest.raises(ValueError, match="implementation changed"):
        verify_sources(manifest, roots=roots)
