from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
import sys
from pathlib import Path

STAGES = (("S1", "Resolve profile", False), ("S2", "Collect and prepare", False),
          ("S3", "Deterministic assessment, compared with an LLM (S3')", True), ("S4", "Compare and evaluate", False))


def add_parsers(commands, argv: Sequence[str] = ()) -> None:
    setup = commands.add_parser("setup", allow_abbrev=False,
                                help="Set this machine up: the pinned tools and, on Linux, the Windows base; then "
                                     "check it.")
    setup.add_argument("--check", action="store_true", help="only check this machine and print what is missing")
    setup.add_argument("--iso", type=Path,
                       help="Microsoft's Windows 11 x64 ISO, which Linux hosts build the Windows base from")
    setup.add_argument("--unpinned-iso", action="store_true",
                       help="build the base from an ISO that is not the pinned one, such as a newer build; every "
                            "result records the base's build and the ISO's SHA-256")
    setup.add_argument("--skip-base", action="store_true", help="install the tools only")
    generate = commands.add_parser("generate", allow_abbrev=False,
                                   help="Generate disk images from images/<name>.json; asks when no image is named.")
    generate.add_argument("images", nargs="*", help="files in images/, by name (I1, I2, I3 or yours)")
    generate.add_argument("--attempts", type=int, default=3,
                          help="generation attempts per image when booting or provisioning fails (default 3)")
    run = commands.add_parser("run", allow_abbrev=False,
                              help="Run the pipeline (S1-S4) on generated images and score it against ground "
                                   "truth; asks when no image is named.")
    run.add_argument("images", nargs="*", help="generated images, by name")
    run.add_argument("--compare", action="append", default=[], choices=["S3"],
                     help="the stage at which to compare an LLM with the pipeline; only S3 for now")
    own = declared_in(argv)
    run.add_argument("--llm", action="append", default=[], metavar="CONDITION",
                     help="the LLM condition to compare (repeat for more): " + ", ".join(conditions())
                          + ("; yours: " + ", ".join(own) if own
                             else "; or one of yours, declared in a --conditions FILE"))
    run.add_argument("--conditions", type=Path, metavar="FILE",
                     help="a JSON file of your own LLM conditions, such as conditions/mine.json: each name maps to "
                          "settings like the paper's (provider, model, reasoning_effort, max_output_tokens, "
                          "timeout_seconds; optionally route, temperature, top_p, seed, price_usd_per_million)")
    run.add_argument("--passes", type=int, metavar="N",
                     help="how many times each LLM request is sent, 1 to 10 (default 3, as in the paper)")
    run.add_argument("--cap-usd", type=float, help="the most the LLM requests of one image may cost, in US dollars")
    run.add_argument("--delete-image", action="store_true",
                     help="delete the generated image after a passing run (its result stays; about 25 GB each)")
    run.add_argument("--price", action="append", default=[], metavar="CONDITION=INPUT,OUTPUT",
                     help="US dollars per million input and output tokens, for a condition without a recorded price")


def declared_in(argv: Sequence[str]) -> dict:
    from fmb.replication import image_files

    found = None
    for index, item in enumerate(argv):
        if item == "--conditions" and index + 1 < len(argv):
            found = argv[index + 1]
        elif item.startswith("--conditions="):
            found = item.partition("=")[2]
    try:
        return image_files.read_conditions(Path(found)) if found else {}
    except (OSError, ValueError):
        return {}


def conditions(own: dict | None = None) -> list[str]:
    from fmb.core.paper_protocol import paper_protocol

    return [*paper_protocol()["conditions"], *(own or {})]


def run_command(args: argparse.Namespace) -> int:
    return {"setup": setup_command, "generate": generate_command, "run": pipeline_command}[args.command](args)


def setup_command(args: argparse.Namespace) -> int:
    from fmb.replication import host, setup

    if not args.check:
        setup.all_steps(build_base=not args.skip_base, iso=args.iso, unpinned_iso=args.unpinned_iso)
    rows = host.checks()
    width = max(len(name) for name, _, _ in rows)
    for name, ok, detail in rows:
        print(f"{'ok ' if ok else 'NO '} {name:<{width}}  {detail}")
    return 0 if all(ok for _, ok, _ in rows) else 1


def generate_command(args: argparse.Namespace) -> int:
    from fmb.replication import image_files, run

    names = args.images or pick_images()
    return run.generate_images([image_files.resolve(name) for name in names], args.attempts)


def pipeline_command(args: argparse.Namespace) -> int:
    from fmb.replication import image_files, run

    own = image_files.read_conditions(args.conditions) if args.conditions else None
    names, compare, chosen, cap = args.images, args.compare, args.llm, args.cap_usd
    if not names:
        names, compare, chosen, cap = choose(compare, chosen, cap, own)
    if chosen and not compare:
        compare = ["S3"]
    if compare and not chosen:
        raise SystemExit("--compare S3 needs --llm CONDITION, the LLM to compare: " + ", ".join(conditions(own)))
    llm = image_files.llm_dispatch(chosen, cap, args.price, dict(os.environ), own=own, passes=args.passes)
    return run.run_images(names, llm, delete_image=args.delete_image)


def pick(title: str, rows: list[tuple[str, str]], prompt: str, default: list[str]) -> list[str]:
    print(title)
    for number, (name, detail) in enumerate(rows, 1):
        print(f"  {number}. {name:<22} {detail}")
    answer = input(prompt).split() or default
    return [rows[int(item) - 1][0] if item.isdigit() and 1 <= int(item) <= len(rows) else item for item in answer]


def interactive(what: str, names: list[str]) -> None:
    if not sys.stdin.isatty():
        raise SystemExit(f"name the images to {what}: " + (", ".join(names) or "none yet"))


def pick_images() -> list[str]:
    from fmb.replication import image_files

    rows = image_files.available()
    interactive("generate", [name for name, _ in rows])
    return pick(f"Images in {image_files.IMAGES}/ (to add one, copy {image_files.IMAGES}/template.json to "
                f"{image_files.IMAGES}/<name>.json and edit it)", rows,
                "Generate which, by number or name [1]: ", ["1"])


def choose(compare: list[str], chosen: list[str], cap: float | None,
           own: dict | None = None) -> tuple[list[str], list[str], list[str], float | None]:
    from fmb.replication import image_files, run

    generated = run.generated()
    interactive("run", generated)
    if not generated:
        raise SystemExit("no generated images yet: run fmb generate")
    rows = [(name, image_files.population_line(json.loads((run.GENERATED / name / "image.json").read_text(
        encoding="utf-8")))) for name in generated]
    names = pick("Generated images", rows, "Run which, by number or name [1]: ", ["1"])
    if not compare and not chosen:
        print("Compare an LLM at which stages of the pipeline (Figure 1)?")
        for number, (stage, title, available) in enumerate(STAGES, 1):
            print(f"  {number}. {stage}  {title}" + ("" if available else "  (not available yet)"))
        for item in input("Stages, by number (Enter: none, the pipeline alone): ").split():
            stage = STAGES[int(item) - 1] if item.isdigit() and 1 <= int(item) <= len(STAGES) else next(
                (row for row in STAGES if row[0] == item.upper()), None)
            if stage is None or not stage[2]:
                raise SystemExit(f"{item}: only S3 can be compared with an LLM for now")
            compare.append(stage[0])
    if compare and not chosen:
        chosen = pick("LLM conditions for S3'", image_files.available_conditions(own),
                      "Compare which, by number or name: ", [])
    if chosen and cap is None:
        cap = float(input("The most the LLM requests of one image may cost, in US dollars: "))
    return names, compare, chosen, cap
