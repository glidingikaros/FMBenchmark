import hashlib
import json
import pytest
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
