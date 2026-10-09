import io
import json
import urllib.error
from http.client import HTTPResponse, IncompleteRead

import pytest

from fmb.core.errors import ExternalToolError
from fmb.interpretation import provider
from fmb.interpretation.response_audit import retain_response_bytes


def test_raw_success_is_retained_byte_for_byte_before_json_normalization(
    tmp_path, monkeypatch
):
    raw = b'{ "answer" : "yes", "usage": {"x":3} }\n'
    def opener(*_):
        return io.BytesIO(raw)
    monkeypatch.setattr(provider, "_open_provider_request", opener)
    with retain_response_bytes(tmp_path):
        assert (
            provider.post_json("https://api.openai.com/v1/responses", {}, 5)["answer"]
            == "yes"
        )
    assert provider._open_provider_request is opener
    assert (tmp_path / "transport-01.response.bin").read_bytes() == raw
    assert (tmp_path / "transport-01.request.bin").read_bytes() == b"{}"
    receipt = json.loads((tmp_path / "transport-inventory.json").read_text())["calls"][
        0
    ]
    assert receipt["url"] == "https://api.openai.com/v1/responses"
    assert receipt["method"] == "POST"
    assert receipt["response_bytes"] == len(raw)


@pytest.mark.parametrize("http_error", [False, True])
def test_incomplete_http_body_preserves_partial_bytes_and_original_error(
    tmp_path, monkeypatch, http_error
):
    partial = b'{"output":['

    class Interrupted(io.BytesIO):
        def read(self, *args):
            raise IncompleteRead(partial, 500)

    def opener(*_):
        if http_error:
            raise urllib.error.HTTPError(
                "https://api.openai.com/v1/responses",
                503,
                "unavailable",
                {},
                Interrupted(),
            )
        return Interrupted()

    monkeypatch.setattr(provider, "_open_provider_request", opener)
    with retain_response_bytes(tmp_path), pytest.raises(ExternalToolError) as caught:
        provider.post_json("https://api.openai.com/v1/responses", {}, 5)
    assert caught.value.details["retryable"] is True
    if not http_error:
        assert caught.value.details["provider_failure_stage"] == "transport"
        assert isinstance(caught.value.__cause__, IncompleteRead) and caught.value.__cause__.partial == partial
    assert (tmp_path / "transport-01.response.bin").read_bytes() == partial
    saved = json.loads((tmp_path / "transport-inventory.json").read_text())["calls"][0]
    assert saved["response_bytes"] == len(partial)
    assert provider._open_provider_request is opener


@pytest.mark.parametrize("http_error", [False, True])
def test_failed_response_body_is_preserved_without_request_headers(
    tmp_path, monkeypatch, http_error
):
    raw = b"provider diagnostic " * 400

    def opener(*_):
        if http_error:
            raise urllib.error.HTTPError(
                "https://api.openai.com/v1/responses",
                503,
                "unavailable",
                {},
                io.BytesIO(raw),
            )
        return io.BytesIO(raw)

    monkeypatch.setattr(provider, "_open_provider_request", opener)
    with retain_response_bytes(tmp_path), pytest.raises(ExternalToolError):
        provider.post_json(
            "https://api.openai.com/v1/responses",
            {},
            5,
            headers={"Authorization": "Bearer offline-key-not-to-be-written"},
        )
    assert (tmp_path / "transport-01.response.bin").read_bytes() == raw
    saved = "".join(p.read_text() for p in tmp_path.iterdir())
    assert "offline-key-not-to-be-written" not in saved
    assert provider._open_provider_request is opener


@pytest.mark.parametrize("http_error", [False, True])
@pytest.mark.parametrize("ending", ["complete", "timeout", "early_eof"])
def test_native_http_response_keeps_bytes_before_timeout_or_eof(
    tmp_path, monkeypatch, http_error, ending
):
    body = b'{ "answer": "yes" }\n'
    declared = len(body) if ending == "complete" else len(body) + 500
    wire = (
        f"HTTP/1.1 {503 if http_error else 200} Test\r\nContent-Length: {declared}\r\n\r\n".encode()
        + body
    )

    class Raw(io.RawIOBase):
        position = 0

        def readable(self):
            return True

        def readinto(self, destination):
            if self.position == len(wire):
                if ending == "timeout":
                    raise TimeoutError("offline partial-body timeout")
                return 0
            count = min(len(destination), len(wire) - self.position)
            destination[:count] = wire[self.position : self.position + count]
            self.position += count
            return count

    class Socket:
        def makefile(self, *_):
            return io.BufferedReader(Raw())

    def opener(*_):
        response = HTTPResponse(Socket())
        response.begin()
        if http_error:
            raise urllib.error.HTTPError(
                "https://api.openai.com/v1/responses", 503, "unavailable", {}, response
            )
        return response

    monkeypatch.setattr(provider, "_open_provider_request", opener)
    with retain_response_bytes(tmp_path):
        if ending == "early_eof":
            with pytest.raises(ExternalToolError) as caught:
                provider.post_json("https://api.openai.com/v1/responses", {}, 5)
            if not http_error:
                assert caught.value.details["retryable"] is True
                assert caught.value.__cause__.partial == body
        elif ending == "timeout" or http_error:
            with pytest.raises(ExternalToolError):
                provider.post_json("https://api.openai.com/v1/responses", {}, 5)
        else:
            assert (
                provider.post_json("https://api.openai.com/v1/responses", {}, 5)[
                    "answer"
                ]
                == "yes"
            )
    assert (tmp_path / "transport-01.response.bin").read_bytes() == body
    assert json.loads((tmp_path / "transport-inventory.json").read_text())["calls"][0][
        "response_bytes"
    ] == len(body)
