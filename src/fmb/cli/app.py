from __future__ import annotations

import argparse
from collections.abc import Sequence

from fmb.cli.replicate import add_replicate_parser, run_replicate
from fmb.core.errors import run_cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fmb", allow_abbrev=False,
                                     description="Replicate the paper's I1-I3 experiment on this host.")
    commands = parser.add_subparsers(dest="command", required=True)
    add_replicate_parser(commands)
    args = parser.parse_args(argv)
    return run_cli("fmb", lambda: run_replicate(args))
