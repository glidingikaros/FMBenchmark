from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
import sys
from pathlib import Path

# The check rows that fmb setup itself takes care of; any other missing row is for the user to fix first.
SET_UP_BY_FMB = (".NET runtime", "Ansible with WinRM", "Windows base image", "Windows box", "free disk", "no VMs left",
                 "Windows parsers")


def add_parsers(commands, argv: Sequence[str] = ()) -> None:
    setup = commands.add_parser("setup", allow_abbrev=False,
                                help="Set this machine up: check it, install the pinned tools and build the Windows "
                                     "base (Linux, Windows) or box (macOS) from Microsoft's ISO; then check it again.")
    setup.add_argument("--check", action="store_true", help="only check this machine and print what is missing")
    setup.add_argument("--iso", type=Path,
                       help="Microsoft's Windows 11 ISO, which fmb builds the Windows base from: the x64 ISO on Linux "
                            "and Windows, the Arm64 ISO on macOS")
    setup.add_argument("--unpinned-iso", action="store_true",
                       help="build the base from an ISO that is not the pinned one, such as a newer build; every "
                            "result records the base's build and the ISO's SHA-256")
    setup.add_argument("--skip-base", action="store_true", help="install the tools only")
    generate = commands.add_parser("generate", allow_abbrev=False,
                                   help="Generate disk images from images/<name>.json; asks when no image is named.")
    generate.add_argument("images", nargs="*", help="files in images/, by name (I1, I2, I3 or yours)")
    generate.add_argument("--attempts", type=attempts, default=3,
                          help="generation attempts per image when booting or provisioning fails (default 3)")
    generate.add_argument("--again", action="store_true",
                          help="delete an image that is already generated and generate it again")
    generate.add_argument("--verbose", action="store_true",
                          help="show the whole output (Vagrant or QEMU, Ansible) instead of one line per step; it "
                               "always goes to generated/<name>/generate-<attempt>.log")
    run = commands.add_parser("run", allow_abbrev=False,
                              help="Run the pipeline (S1-S4) on images and score it against ground truth, generating "
                                   "any image that is not generated yet; asks when no image is named.")
    run.add_argument("images", nargs="*", help="images by name; one that is not generated yet is generated first")
    run.add_argument("--compare", action="append", default=[], choices=["S3"],
                     help="the stage at which to compare an LLM with the pipeline; only S3 for now, which --llm "
                          "implies")
    own = declared_in(argv)
    run.add_argument("--llm", action="append", default=[], metavar="CONDITION",
                     help="the LLM condition to compare at S3 (repeat for more), with --cap-usd: "
                          + ", ".join(conditions())
                          + ("; yours: " + ", ".join(own) if own
                             else "; or one of yours, declared in a --conditions FILE"))
    run.add_argument("--conditions", type=Path, metavar="FILE",
                     help="a JSON file of your own LLM conditions, such as conditions/mine.json: each name maps to "
                          "settings like the paper's (provider, model, reasoning_effort, max_output_tokens, "
                          "timeout_seconds; optionally route, temperature, top_p, seed, price_usd_per_million)")
    run.add_argument("--passes", type=int, metavar="N",
                     help="how many times each LLM request is sent, 1 to 10 (default 3, as in the paper)")
    run.add_argument("--cap-usd", type=float,
                     help="the most the LLM requests of one image may cost, in US dollars; each request reserves its "
                          "input and all its output tokens until its answer's cost is known")
    run.add_argument("--price", action="append", default=[], metavar="CONDITION=INPUT,OUTPUT",
                     help="US dollars per million input and output tokens, for a condition without a recorded price")
    run.add_argument("--recollect", action="store_true",
                     help="collect the evidence again (S2) for an LLM comparison, instead of reusing the collection "
                          "of the image's latest run with the same code")
    run.add_argument("--delete-image", action="store_true",
                     help="delete each generated image after its passing run, before the next image (its result "
                          "stays; about 25 GB each)")
    run.add_argument("--attempts", type=attempts, default=3,
                     help="generation attempts per image, for an image fmb run generates (default 3)")
    run.add_argument("--verbose", action="store_true",
                     help="show the whole output of generation and of the pipeline instead of one line per step; it "
                          "always goes to the log files")


def attempts(value: str) -> int:
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError("give a whole number, 1 or more")
    return int(value)


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


def show(rows: list) -> None:
    width = max(len(name) for name, _, _ in rows)
    for name, ok, detail in rows:
        print(f"{'ok ' if ok else 'NO '} {name:<{width}}  {detail}")


def setup_command(args: argparse.Namespace) -> int:
    from fmb.replication import host, setup

    if not args.check:
        rows = host.checks()
        missing = [name for name, ok, _ in rows if not ok and not name.startswith(SET_UP_BY_FMB)]
        if missing and not args.skip_base:
            show(rows)
            raise SystemExit("first install what fmb setup cannot: " + "; ".join(missing)
                             + ". The rows above say how. Then run fmb setup again.")
        setup.all_steps(build_base=not args.skip_base, iso=args.iso, unpinned_iso=args.unpinned_iso)
    rows = host.checks()
    show(rows)
    if busy := host.load_warning():
        print(f"warning: {busy}")
    return 0 if all(ok for _, ok, _ in rows) else 1


def where() -> None:
    from fmb.core.paths import workspace
    from fmb.replication.setup import log

    if Path.cwd().resolve() != workspace().resolve():
        log(f"working in {workspace()} (its images/, generated/ and results/); set FMB_HOME to use another folder")


def generate_command(args: argparse.Namespace) -> int:
    from fmb.replication import awake, image_files, run

    run.VERBOSE = args.verbose
    where()
    names = args.images or pick_images()
    with awake.kept_awake():
        return run.generate_images([image_files.resolve(name) for name in names], args.attempts, again=args.again)


def pipeline_command(args: argparse.Namespace) -> int:
    from fmb.replication import awake, image_files, run

    run.VERBOSE = args.verbose
    where()
    own = image_files.read_conditions(args.conditions) if args.conditions else None
    names, compare, chosen, cap, prices = args.images, args.compare, args.llm, args.cap_usd, args.price
    if not names:
        names, compare, chosen, cap, prices = choose(compare, chosen, cap, prices, own)
    if compare and not chosen:
        raise ValueError("--compare S3 needs --llm CONDITION, the LLM to compare: " + ", ".join(conditions(own)))
    llm = image_files.llm_dispatch(chosen, cap, prices, dict(os.environ), own=own, passes=args.passes)
    with awake.kept_awake():
        return run.run_images(names, llm, delete_image=args.delete_image, attempts=args.attempts,
                              recollect=args.recollect)


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
    folder = image_files.images_folder()
    return pick(f"Images in {folder} (to add one, copy {folder / 'template.json'} to {folder}/<name>.json and edit it)",
                rows, "Generate which, by number or name [1]: ", ["1"])


def choose(compare: list[str], chosen: list[str], cap: float | None, prices: list[str],
           own: dict | None = None) -> tuple[list[str], list[str], list[str], float | None, list[str]]:
    from fmb.replication import image_files, run

    generated = run.generated()
    rows = [(name, "generated: " + image_files.population_line(json.loads(
        (run.generated_root() / name / "image.json").read_text(encoding="utf-8")))) for name in generated]
    rows += [(name, "not generated yet, fmb run generates it first: " + detail)
             for name, detail in image_files.available() if name not in generated]
    interactive("run", [name for name, _ in rows])
    names = pick("Images", rows, "Run which, by number or name [1]: ", ["1"])
    if not chosen:
        chosen = pick("Compare an LLM with the rules at S3 (S3' in Figure 1)? LLM conditions",
                      image_files.available_conditions(own), "Which, by number or name (Enter: none): ", [])
    if chosen and cap is None:
        cap = float(input("The most the LLM requests of one image may cost, in US dollars: "))
    declared = {**image_files.paper_protocol()["conditions"], **(own or {})}
    given = {item.partition("=")[0] for item in prices}
    for name in chosen:
        if name in declared and name not in given and not declared[name]["settings"].get("price_usd_per_million"):
            pair = input(f"{name} has no recorded price: US dollars per million input and output tokens, "
                         "as INPUT,OUTPUT: ")
            prices = [*prices, f"{name}={pair.strip()}"]
    return names, compare, chosen, cap, prices
