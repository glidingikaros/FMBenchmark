import json

import pytest

from fmb.replication import image_files


@pytest.mark.parametrize("seed", range(40))
def test_random_images_are_images_the_generator_builds(tmp_path, seed):
    path = tmp_path / "random.json"
    path.write_text(json.dumps(image_files.random_definition(seed)))
    assert image_files.check(image_files.load(path)).startswith(f"random: seed {seed},")


def test_a_seed_gives_one_definition():
    assert image_files.random_definition(7) == image_files.random_definition(7)
    assert image_files.random_definition(7) != image_files.random_definition(8)


def test_random_images_cover_the_open_settings():
    definitions = [image_files.random_definition(seed) for seed in range(60)]
    drives = {d["scenarios"]["usbstor_setupapi_discrepancy_01"]["configured_count"] for d in definitions
              if "usbstor_setupapi_discrepancy_01" in d["scenarios"]}
    assert drives == {2, 3, 4}
    assert any(len(d["experiments"]["full_scale"]) < 14 for d in definitions)
    assert any(any(not s["configured_count"] for s in d["scenarios"].values()) for d in definitions)
    assert any(d["scenarios"]["timestomp_01"]["manipulation_count"] == 3 for d in definitions if "timestomp_01" in d["scenarios"])
