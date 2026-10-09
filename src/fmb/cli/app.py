from __future__ import annotations

import argparse
from collections.abc import Sequence

from fmb.cli.commands import add_parsers, run_command
from fmb.core.errors import run_cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fmb", allow_abbrev=False,
        description="Generate synthetic Windows disk images with known anti-forensic manipulations, and score the "
                    "pipeline of the paper on them: deterministic rules (S3) and an LLM (S3'), against ground truth.")
    commands = parser.add_subparsers(dest="command", required=True)
    add_parsers(commands)
    args = parser.parse_args(argv)
    return run_cli("fmb", lambda: run_command(args))
