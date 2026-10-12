from __future__ import annotations

import contextvars
import threading
from typing import Any, Callable


class Background:
    """Runs one call on its own thread while the caller does other work; result() waits for it.

    The thread runs in a copy of the caller's context, so the run's read audit and truth guard see its file opens.
    """

    def __init__(self, function: Callable[..., Any], *args: Any, name: str, **kwargs: Any) -> None:
        self._value: Any = None
        self._error: BaseException | None = None
        context = contextvars.copy_context()
        self._thread = threading.Thread(target=context.run, args=(self._call, function, args, kwargs),
                                        name=name, daemon=True)
        self._thread.start()

    def _call(self, function: Callable[..., Any], args: tuple, kwargs: dict) -> None:
        try:
            self._value = function(*args, **kwargs)
        except BaseException as error:  # handed to result()
            self._error = error

    def result(self) -> Any:
        self._thread.join()
        if self._error is not None:
            raise self._error
        return self._value
