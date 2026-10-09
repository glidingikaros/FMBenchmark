from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from typing import Any

MAX_EXACT_FLOAT_INTEGER = 2**53 - 1


def _decimal_from_text(text: str) -> Decimal | None:
    try:
        number = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    return number if number.is_finite() else None


def _prepared_number(value: Any) -> int | float | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    text = str(value).strip()
    return text or None


def _float_to_int(value: float, *, require_integral: bool) -> int | None:
    if not math.isfinite(value):
        return None
    if require_integral and not value.is_integer():
        return None
    if abs(value) > MAX_EXACT_FLOAT_INTEGER:
        return None
    return int(value)


def parse_integral_int(value: Any) -> int | None:
    prepared = _prepared_number(value)
    if prepared is None:
        return None
    if isinstance(prepared, int):
        return prepared
    if isinstance(prepared, float):
        return _float_to_int(prepared, require_integral=True)
    try:
        return int(prepared)
    except (TypeError, ValueError, OverflowError):
        try:
            return int(prepared, 0)
        except (TypeError, ValueError, OverflowError):
            number = _decimal_from_text(str(prepared))
            if number is None:
                return None
            integral = number.to_integral_value()
            return int(integral) if number == integral else None


def parse_truncated_int(value: Any) -> int | None:
    prepared = _prepared_number(value)
    if prepared is None:
        return None
    if isinstance(prepared, int):
        return prepared
    if isinstance(prepared, float):
        return _float_to_int(prepared, require_integral=False)
    try:
        return int(prepared, 0)
    except (TypeError, ValueError, OverflowError):
        number = _decimal_from_text(str(prepared))
        return int(number) if number is not None else None


__all__ = [
    "MAX_EXACT_FLOAT_INTEGER",
    "parse_integral_int",
    "parse_truncated_int",
]
