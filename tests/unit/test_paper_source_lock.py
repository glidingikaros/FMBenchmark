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


def symlink_or_skip(link, target, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


@pytest.mark.parametrize("where", ["file", "directory", "excluded_name"])
def test_inventory_refuses_symlinks_anywhere_in_the_tree(locked, tmp_path, where):
    roots, _, module = locked
    if where == "file":
        symlink_or_skip(module.parent / "alias.py", module)
    elif where == "directory":
        symlink_or_skip(roots["package"] / "contracts" / "linked", module.parent, directory=True)
    else:
        symlink_or_skip(module.parent / "__pycache__", tmp_path, directory=True)
    with pytest.raises(ValueError, match="symlinked implementation asset"):
        source_files(roots)


def test_inventory_lists_nested_sources_and_leaves_out_fixtures_bytecode_and_the_manifest(locked):
    roots, _, module = locked
    package = roots["package"]
    deep = package / "a" / "b" / "c.py"
    deep.parent.mkdir(parents=True)
    deep.write_text("x=1\n")
    for skipped in ("fixtures/sample.json", "a/__pycache__/c.cpython-313.pyc", "a/b/c.pyc",
                    "paper-source-manifest.json", "a/.git/HEAD"):
        (package / skipped).parent.mkdir(parents=True, exist_ok=True)
        (package / skipped).write_text("{}")
    assert source_files(roots) == {
        "package/a/b/c.py": deep,
        "package/analysis/structured_content.py": module,
        "package/contracts/schema.json": package / "contracts" / "schema.json",
    }


def test_inventory_refuses_trees_deeper_than_its_budget(locked):
    roots, _, _ = locked
    deep = roots["package"].joinpath(*["d"] * 21)
    deep.mkdir(parents=True)
    with pytest.raises(ValueError, match="depth/time budget"):
        source_files(roots)
