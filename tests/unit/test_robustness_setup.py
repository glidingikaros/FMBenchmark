import hashlib
import io
import urllib.error
import zipfile

import pytest

from fmb.cli.commands import SET_UP_BY_FMB
from fmb.replication import host, setup


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_a_download_is_tried_again_with_backoff_and_a_failure_names_its_url(monkeypatch):
    waited, answers = [], [urllib.error.URLError("Tunnel connection failed: 403 Forbidden"), ConnectionResetError(104)]

    def urlopen(request, timeout):
        if answers:
            raise answers.pop(0)
        return Response(b"payload")

    monkeypatch.setattr(setup.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(setup.time, "sleep", waited.append)
    assert setup.fetch("https://example.invalid/tool.zip") == b"payload"
    assert waited == list(setup.RETRY_SECONDS)

    def unavailable(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(setup.urllib.request, "urlopen", unavailable)
    with pytest.raises(SystemExit, match=r"downloading https://example\.invalid/tool\.zip failed 3 times; .*404"):
        setup.fetch("https://example.invalid/tool.zip")


def zipped(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def validated_only(monkeypatch, tmp_path, good: bytes):
    from fmb.collection.tools.host import parser_appliance

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    builds = {hashlib.sha256(good).hexdigest(): "the validated build"}
    monkeypatch.setattr(parser_appliance, "validated_builds", lambda name: dict(builds))
    return builds


def test_setup_installs_only_validated_parser_builds_and_names_an_unvalidated_download(tmp_path, monkeypatch):
    good, newer = b"MZ validated", b"MZ upstream's newer build"
    validated_only(monkeypatch, tmp_path, good)
    served = {"PECmd.exe": newer, "SBECmd.exe": good}
    fetched = []

    def fetch(url):
        fetched.append(url)
        name = url.rsplit("/", 1)[1].replace(".zip", ".exe")
        return zipped(name, served[name])

    monkeypatch.setattr(setup, "fetch", fetch)
    folder = tmp_path / "windows-parsers"
    with pytest.raises(SystemExit) as failure:
        setup.parsers()
    message = str(failure.value)
    assert host.PINS["windows_parsers"]["PECmd.exe"] in message
    assert hashlib.sha256(newer).hexdigest() in message and hashlib.sha256(good).hexdigest() in message
    assert f"at {folder / 'PECmd.exe'} by hand" in message
    assert not (folder / "PECmd.exe").exists() and not (folder / "PECmd.exe.part").exists()

    served["PECmd.exe"] = good
    (folder / "PECmd.exe").parent.mkdir(parents=True, exist_ok=True)
    (folder / "PECmd.exe").write_bytes(good[:3])  # an interrupted earlier write
    fetched.clear()
    setup.parsers()
    assert (folder / "PECmd.exe").read_bytes() == good and (folder / "SBECmd.exe").read_bytes() == good
    assert len(fetched) == 2 and not list(folder.glob("*.part"))
    setup.parsers()
    assert len(fetched) == 2


def test_setup_check_reports_whether_the_parsers_are_validated_builds(tmp_path, monkeypatch):
    good = b"MZ validated"
    validated_only(monkeypatch, tmp_path, good)
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0)
    monkeypatch.setattr(host, "leftovers", lambda: [])
    monkeypatch.setattr(host, "which", lambda name: None)
    folder = tmp_path / "windows-parsers"
    folder.mkdir()
    (folder / "PECmd.exe").write_bytes(good)
    (folder / "SBECmd.exe").write_bytes(b"MZ unvalidated")

    def row():
        return next(row for row in host.checks() if row[0].startswith("Windows parsers"))

    name, ok, detail = row()
    assert not ok and detail == f"run: fmb setup (SBECmd.exe in {folder}: missing or not a validated build)"
    assert name.startswith(SET_UP_BY_FMB)
    (folder / "SBECmd.exe").write_bytes(good)
    assert row()[1:] == (True, "the validated build; the validated build")
