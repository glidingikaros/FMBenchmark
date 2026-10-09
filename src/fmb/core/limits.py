from __future__ import annotations

MAX_USB_MEDIUM_BYTES = 4 * 1024**3


def usb_medium_size(value) -> bool:
    return type(value) is int and 0 < value <= MAX_USB_MEDIUM_BYTES and not value % 512
