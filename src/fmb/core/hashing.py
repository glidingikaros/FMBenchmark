from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
import contextvars
import hashlib
import os
from pathlib import Path
import queue
import threading
from typing import Any

from fmb.core.json_io import json_text

DEFAULT_FILE_CHUNK_SIZE = 1024 * 1024
# From this size on, a reader thread fetches the next blocks while the current one is hashed. The blocks are large
# so that a hash running beside busy Python code waits for the interpreter lock once per 16 MiB, not once per MiB.
READ_AHEAD_MIN_BYTES = 64 * 1024 * 1024
READ_AHEAD_BLOCK_SIZE = 16 * 1024 * 1024
READ_AHEAD_BLOCKS = 4
# One SHA-256 thread reads a Mac's SSD at a fraction of its speed, so the files of a VM disk are hashed a few at once.
HASH_WORKERS = min(4, os.cpu_count() or 1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_FILE_CHUNK_SIZE) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size >= READ_AHEAD_MIN_BYTES:
            _update_reading_ahead(digest, handle, max(chunk_size, READ_AHEAD_BLOCK_SIZE))
        else:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _update_reading_ahead(digest: Any, handle: Any, chunk_size: int) -> None:
    blocks: queue.Queue = queue.Queue(maxsize=READ_AHEAD_BLOCKS)
    stop = threading.Event()

    def hand_over(item: Any) -> bool:
        while not stop.is_set():
            try:
                blocks.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def reader() -> None:
        try:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                if not hand_over(chunk):
                    return
        except BaseException as error:  # handed to the hashing thread
            hand_over(error)
            return
        hand_over(None)

    thread = threading.Thread(target=reader, name="fmb-sha256-read-ahead", daemon=True)
    thread.start()
    try:
        while (chunk := blocks.get()) is not None:
            if isinstance(chunk, BaseException):
                raise chunk
            digest.update(chunk)
    finally:
        stop.set()
        thread.join()


@contextmanager
def hashing_threads(workers: int = HASH_WORKERS) -> Iterator[Callable[..., Future]]:
    """Yields submit(function, *args), which starts the call on one of a few threads and returns its future.

    Each call runs in a copy of the caller's context, so the run's read audit and truth guard see its file opens.
    Leaving the block drops the calls not started yet and waits for the running ones.
    """
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fmb-sha256") as pool:
        try:
            yield lambda function, *args: pool.submit(contextvars.copy_context().run, function, *args)
        finally:
            pool.shutdown(cancel_futures=True)


def in_order(function: Callable[[Any], Any], items: Iterable[Any], *, workers: int = HASH_WORKERS) -> list:
    """[function(item) for item in items], a few items at once; an error is the first failing item's, as in a loop."""
    with hashing_threads(workers) as submit:
        calls = [submit(function, item) for item in items]
        return [call.result() for call in calls]


def canonical_json_bytes(document: Any) -> bytes:
    return json_text(document, sort_keys=True).encode("utf-8")


def sha256_json(document: Any) -> str:
    return sha256_bytes(canonical_json_bytes(document))


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
