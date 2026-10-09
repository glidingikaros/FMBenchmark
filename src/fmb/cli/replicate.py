from __future__ import annotations

import argparse
from pathlib import Path


def add_replicate_parser(subcommands) -> None:
    parser = subcommands.add_parser(
        "replicate", allow_abbrev=False,
        help="Replicate the I1-I3 experiment on this host (macOS: the paper's VMware path; Linux, Windows: QEMU).",
    )
    actions = parser.add_subparsers(dest="replicate_action", required=True)
    actions.add_parser("doctor", allow_abbrev=False, help="Check this host and print what is missing.")
    setup = actions.add_parser("setup", allow_abbrev=False,
                               help="Install the pinned .NET runtime, Ansible and collection tools; build the Windows base.")
    setup.add_argument("--skip-base", action="store_true", help="Prepare the tools only.")
    setup.add_argument("--iso", type=Path,
                       help="Microsoft's Windows 11 x64 ISO, which Linux and Windows hosts build the base from.")
    setup.add_argument("--unpinned-iso", action="store_true",
                       help="Build the base from an ISO that is not the pinned one, such as a newer build; every result "
                            "records the base's build and the ISO's SHA-256.")
    run = actions.add_parser("run", allow_abbrev=False, help="Generate, collect and analyse paper images.")
    run.add_argument("images", nargs="*", choices=["I1", "I2", "I3"], help="default: I1 I2 I3")
    run.add_argument("--output", type=Path, default=Path("replication"))
    run.add_argument("--attempts", type=int, default=3,
                     help="Generation attempts per image when booting or provisioning fails (default 3).")


def run_replicate(args: argparse.Namespace) -> int:
    from fmb.replication import host, run, setup

    if args.replicate_action == "doctor":
        rows = host.checks()
        width = max(len(name) for name, _, _ in rows)
        for name, ok, detail in rows:
            print(f"{'ok ' if ok else 'NO '} {name:<{width}}  {detail}")
        return 0 if all(ok for _, ok, _ in rows) else 1
    if args.replicate_action == "setup":
        setup.all_steps(build_base=not args.skip_base, iso=args.iso, unpinned_iso=args.unpinned_iso)
        return 0
    return run.images(list(args.images) or ["I1", "I2", "I3"], args.output, args.attempts)
