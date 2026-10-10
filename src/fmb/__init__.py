from __future__ import annotations

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    from fmb.cli.app import main as cli_main

    return cli_main(argv)


__all__ = ["main"]
