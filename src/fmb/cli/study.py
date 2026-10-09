from __future__ import annotations

import argparse
from pathlib import Path


def add_study_parser(subcommands) -> None:
    parser = subcommands.add_parser(
        "study", allow_abbrev=False,
        help="Define, check and run your own images with the paper's pipeline (set the host up with "
             "`fmb replicate setup` first).",
    )
    actions = parser.add_subparsers(dest="study_action", required=True)
    new = actions.add_parser("new", allow_abbrev=False, help="Start a study from one of the paper's images.")
    new.add_argument("folder", type=Path)
    new.add_argument("--from", dest="template", default="I3", choices=["I1", "I2", "I3"],
                     help="the paper image to copy (default I3)")
    new.add_argument("--image", default="S1", help="the new image's name (default S1)")
    new.add_argument("--seed", type=int, help="default: a random seed, written into study.json")
    check = actions.add_parser("check", allow_abbrev=False,
                               help="Validate a study and show what each image will contain, without a VM.")
    check.add_argument("folder", type=Path)
    run = actions.add_parser("run", allow_abbrev=False, help="Generate, collect and analyse a study's images.")
    run.add_argument("folder", type=Path)
    run.add_argument("images", nargs="*", help="default: every image in study.json")
    run.add_argument("--output", type=Path, help="default: study-runs/<study name>")
    run.add_argument("--attempts", type=int, default=3,
                     help="Generation attempts per image when booting or provisioning fails (default 3).")


def run_study(args: argparse.Namespace) -> int:
    from fmb import studies

    if args.study_action == "new":
        file = studies.scaffold(args.folder, template=args.template, label=args.image, seed=args.seed)
        print(f"wrote {file} and {file.parent / studies.load(file).images[args.image].population.name}")
        print(f"edit the population file, then: fmb study check {args.folder}")
        return 0
    study = studies.load(args.folder)
    if args.study_action == "check":
        for row in studies.check(study):
            print(f"{row['image']} (seed {row['seed']})")
            for scenario, (configured, manipulated) in row["scenarios"].items():
                print(f"  {scenario:<36} {configured:>3} objects, {manipulated:>3} manipulated")
            for question, kinds in row["supplement"].items():
                print(f"  supplement {question:<25} {', '.join(kinds)}")
        print(f"{study.name}: ready to run with `fmb study run {args.folder}`")
        return 0
    from fmb.replication import run

    unknown = sorted(set(args.images) - set(study.images))
    if unknown:
        raise SystemExit(f"{study.name} has no image {', '.join(unknown)}; it has {', '.join(study.images)}")
    output = args.output or Path("study-runs") / study.name
    return run.images(list(args.images) or list(study.images), output, args.attempts, study)
