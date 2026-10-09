from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


surfaces_tests = _load("surfaces_fixture", ROOT / "tests/unit/test_ntfs_surfaces.py")
native = _load("i30_postcondition_native", ROOT / "src/fmb/generation/ntfs_surface_injection.py")


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="QEMU unavailable")
def test_i30_postcondition_accepts_slack_residue_for_freed_child(tmp_path: Path) -> None:
    image, _mft, _csv = surfaces_tests._fixture(tmp_path)

    receipt = native.verify_i30_residue(image, [r"C:\Cases"], ["removed.bin"])

    assert receipt["postcondition_verified"] is True
    assert receipt["image_modified"] is False
    (row,) = receipt["directories"]
    assert row["absent_reference_residue_count"] == 1
    assert row["residue_names"] == ["removed.bin"]
    assert row["residue_surfaces"] == ["index_allocation_slack"]
    assert row["index_allocation_present"] is True


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="QEMU unavailable")
def test_i30_postcondition_rejects_live_or_missing_residue(tmp_path: Path) -> None:
    image, _mft, _csv = surfaces_tests._fixture(tmp_path)

    with pytest.raises(ValueError, match="still live"):
        native.verify_i30_residue(image, [r"C:\Cases"], ["ordinary.bin"])
    with pytest.raises(ValueError, match="no header-intact residue"):
        native.verify_i30_residue(image, [r"C:\Cases"], ["never-existed.bin"])
    with pytest.raises(ValueError, match="requires"):
        native.verify_i30_residue(image, [], ["removed.bin"])
