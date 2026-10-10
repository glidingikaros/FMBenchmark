from fmb.core.json_io import write_json


def test_json_records_have_the_same_bytes_on_every_platform(tmp_path):
    write_json(tmp_path / "record.json", {"lines": [1, 2]})
    assert (tmp_path / "record.json").read_bytes() == b'{\n  "lines": [\n    1,\n    2\n  ]\n}\n'
