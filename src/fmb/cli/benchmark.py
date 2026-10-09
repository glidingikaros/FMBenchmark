from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path


def add_benchmark_parsers(commands) -> None:
    commands.add_parser("list", allow_abbrev=False,
                        help="List the images (the paper's and images/*.json) and the S3 engines (rules and "
                             "engines/*.py).")
    new = commands.add_parser("new", allow_abbrev=False, help="Write images/NAME.json from one of the paper's images.")
    new.add_argument("name")
    new.add_argument("--from", dest="template", default="I3", choices=["I1", "I2", "I3"], help="default: I3")
    new.add_argument("--seed", type=int, help="default: a random seed")
    run = commands.add_parser("run", allow_abbrev=False,
                              help="Generate, collect and analyse images with an S3 engine of your choice; asks "
                                   "when no image is named.")
    run.add_argument("images", nargs="*", help="I1, I2, I3, or the name of a file in images/")
    run.add_argument("--s3", help="rules (default) or the name of a file in engines/")
    run.add_argument("--output", type=Path, default=Path("runs"))
    run.add_argument("--attempts", type=int, default=3,
                     help="Generation attempts per image when booting or provisioning fails (default 3).")


def run_benchmark(args: argparse.Namespace) -> int:
    from fmb.replication import image_files

    if args.command == "list":
        for title, rows in (("Images", image_files.available_images()),
                            ("S3 engines", image_files.available_engines())):
            print(title)
            for name, detail in rows:
                print(f"  {name:<14} {detail}")
        return 0
    if args.command == "new":
        seed = secrets.randbelow(2**31) if args.seed is None else args.seed
        path = image_files.scaffold(args.name, args.template, seed)
        print(f"wrote {path} from {args.template}; edit it, then: fmb run {args.name}")
        return 0
    names, engine = (args.images, args.s3) if args.images else choose(args.s3)
    from fmb.replication import run

    return run.images([image_files.resolve_image(name) for name in names], args.output, args.attempts,
                      image_files.resolve_engine(engine or "rules"))


def pick(title: str, rows: list[tuple[str, str]], prompt: str) -> list[str]:
    print(title)
    for number, (name, detail) in enumerate(rows, 1):
        print(f"  {number}. {name:<14} {detail}")
    answer = input(prompt).split() or ["1"]
    return [rows[int(item) - 1][0] if item.isdigit() and 1 <= int(item) <= len(rows) else item for item in answer]


def choose(engine: str | None) -> tuple[list[str], str | None]:
    from fmb.replication import image_files

    if not sys.stdin.isatty():
        raise SystemExit("name the images to run; `fmb list` shows them")
    names = pick("Images", image_files.available_images(), "Images to run, by number or name [1]: ")
    if engine is None:
        engine = pick("S3 engines", image_files.available_engines(), "S3 engine, by number or name [1]: ")[0]
    return names, engine
