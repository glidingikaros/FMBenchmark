from contextlib import contextmanager
import io
import hashlib
from http.client import HTTPResponse, IncompleteRead
import json
from pathlib import Path
import urllib.error

from fmb.interpretation import provider
from fmb.interpretation.request_audit import AuditedProviderCall


class _Response:
    def __init__(self, response, path):
        self.response, self.path = response, path

    def read(self, *args):
        native = (
            self.response.fp
            if isinstance(self.response, urllib.error.HTTPError)
            else self.response
        )
        if not args and isinstance(native, HTTPResponse):
            chunks = []
            while True:
                try:
                    data = native.read1(64 * 1024)
                except IncompleteRead as error:
                    with self.path.open("ab") as output:
                        output.write(error.partial)
                    raise
                if not data:
                    body = b"".join(chunks)
                    if native.length not in (None, 0):
                        raise IncompleteRead(body, native.length)
                    return body
                with self.path.open("ab") as output:
                    output.write(data)
                chunks.append(data)
        try:
            data = self.response.read(*args)
        except IncompleteRead as error:
            with self.path.open("ab") as output:
                output.write(error.partial)
            raise
        with self.path.open("ab") as output:
            output.write(data)
        return data

    def __enter__(self):
        self.response.__enter__()
        return self

    def __exit__(self, *args):
        return self.response.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self.response, name)


@contextmanager
def retain_response_bytes(directory: Path):
    original = provider._open_provider_request
    calls = []

    def retained(request, timeout):
        ordinal = len(calls) + 1
        path = directory / f"transport-{ordinal:02d}.response.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=False)
        request_path = directory / f"transport-{ordinal:02d}.request.bin"
        request_path.write_bytes(request.data or b"")
        row = {
            "request_file": request_path.name,
            "request_sha256": hashlib.sha256(request_path.read_bytes()).hexdigest(),
            "url": request.full_url,
            "method": request.get_method(),
            "response_file": path.name,
            "response_status": None,
        }
        calls.append(row)
        try:
            response = original(request, timeout)
        except urllib.error.HTTPError as error:
            row["response_status"] = error.code
            raw = _Response(error, path).read()
            error.fp = io.BytesIO(raw)
            error.read = error.fp.read
            raise
        else:
            row["response_status"] = getattr(response, "status", None)
            return _Response(response, path)

    provider._open_provider_request = retained
    try:
        yield
    finally:
        provider._open_provider_request = original
        directory.mkdir(parents=True, exist_ok=True)
        for row in calls:
            data = (directory / row["response_file"]).read_bytes()
            row.update(
                response_bytes=len(data),
                response_sha256=hashlib.sha256(data).hexdigest(),
            )
        (directory / "transport-inventory.json").write_text(
            json.dumps({"calls": calls}, indent=2) + "\n"
        )


class RetainedProviderCall(AuditedProviderCall):
    def __init__(self, directory, delegate=provider.call_llm):
        def recorded(**kwargs):
            with retain_response_bytes(self.directory / f"attempt-{self.count:04d}"):
                return delegate(**kwargs)

        super().__init__(directory, delegate=recorded)
