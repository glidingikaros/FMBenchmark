from pathlib import Path

import pytest

from fmb.collection.tools.host import validation as appliance
from fmb.collection.tools.host.validation import required_artifact_globs


def test_bounded_user_bmp_requires_one_profile_level_artifact_glob() -> None:
    assert required_artifact_globs(
        targets=["FMBBoundedUserBMP"],
        modules=[],
        explicit=[],
    ) == ["targets/*/Users/*/**/*.bmp"]


@pytest.mark.parametrize("profile_directory", ["Desktop", "Documents"])
def test_bounded_user_bmp_validation_accepts_populated_profile_directory(
    tmp_path: Path,
    profile_directory: str,
) -> None:
    bmp_path = (
        tmp_path
        / "targets"
        / "C"
        / "Users"
        / "analyst"
        / profile_directory
        / "subject.bmp"
    )
    bmp_path.parent.mkdir(parents=True)
    bmp_path.write_bytes(b"BM")
    checks: list[dict[str, object]] = []

    appliance.assert_required_kape_artifacts(
        tmp_path,
        required_artifact_globs(
            targets=["FMBBoundedUserBMP"], modules=[], explicit=[]
        ),
        checks=checks,
    )

    assert checks == [
        {"check_id": "artifact_glob:targets/*/Users/*/**/*.bmp", "status": "pass"}
    ]
