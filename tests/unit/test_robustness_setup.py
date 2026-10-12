import io
import urllib.error

import pytest

from fmb.replication import setup


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
