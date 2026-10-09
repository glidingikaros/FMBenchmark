from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path


def add_benchmark_parsers(commands) -> None:
    commands.add_parser("list", allow_abbrev=False,
                        help="List the images (the paper's and images/*.json) and the LLM conditions for S3'.")
    new = commands.add_parser("new", allow_abbrev=False, help="Write images/NAME.json from one of the paper's images.")
    new.add_argument("name")
    new.add_argument("--from", dest="template", default="I3", choices=["I1", "I2", "I3"], help="default: I3")
    new.add_argument("--seed", type=int, help="default: a random seed")
    run = commands.add_parser("run", allow_abbrev=False,
                              help="Generate, collect and analyse images: S3, and S3' with --llm; asks when no "
                                   "image is named.")
    run.add_argument("images", nargs="*", help="I1, I2, I3, or the name of a file in images/")
    run.add_argument("--llm", action="append", default=[], metavar="CONDITION",
                     help="also send the evidence cards to this LLM condition (S3'); repeat for more")
    run.add_argument("--cap-usd", type=float,
                     help="the most the LLM requests of one image may cost, in US dollars (needed with --llm)")
    run.add_argument("--price", action="append", default=[], metavar="CONDITION=INPUT,OUTPUT",
                     help="US dollars per million input and output tokens, for a condition without a recorded price")
    run.add_argument("--output", type=Path, default=Path("runs"))
    run.add_argument("--attempts", type=int, default=3,
                     help="Generation attempts per image when booting or provisioning fails (default 3).")


def run_benchmark(args: argparse.Namespace) -> int:
    from fmb.replication import image_files

    if args.command == "list":
        for title, rows in (("Images", image_files.available_images()),
                            ("LLM conditions for S3'", image_files.available_conditions())):
            print(title)
            for name, detail in rows:
                print(f"  {name:<22} {detail}")
        return 0
    if args.command == "new":
        seed = secrets.randbelow(2**31) if args.seed is None else args.seed
        path = image_files.scaffold(args.name, args.template, seed)
        print(f"wrote {path} from {args.template}; edit it, then: fmb run {args.name}")
        return 0
    names, conditions, cap = (args.images, args.llm, args.cap_usd) if args.images else choose(args.llm, args.cap_usd)
    llm = image_files.llm_dispatch(conditions, cap, args.price, dict(os.environ))
    images = [image_files.resolve_image(name) for name in names]
    from fmb.replication import run

    return run.images(images, args.output, args.attempts, llm)


def pick(title: str, rows: list[tuple[str, str]], prompt: str, default: list[str]) -> list[str]:
    print(title)
    for number, (name, detail) in enumerate(rows, 1):
        print(f"  {number}. {name:<22} {detail}")
    answer = input(prompt).split() or default
    return [rows[int(item) - 1][0] if item.isdigit() and 1 <= int(item) <= len(rows) else item for item in answer]


def choose(conditions: list[str], cap: float | None) -> tuple[list[str], list[str], float | None]:
    from fmb.replication import image_files

    if not sys.stdin.isatty():
        raise SystemExit("name the images to run; `fmb list` shows them")
    names = pick("Images", image_files.available_images(), "Images to run, by number or name [1]: ", ["1"])
    if not conditions:
        conditions = [name for name in pick("LLM conditions for S3'", image_files.available_conditions(),
                                            "Also run S3' with, by number or name [none]: ", []) if name != "none"]
    if conditions and cap is None:
        cap = float(input("Most the LLM requests of one image may cost, in US dollars: "))
    return names, conditions, cap
