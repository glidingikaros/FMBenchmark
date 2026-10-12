#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

from fmb.pipeline.diff import repeat_differences

parser = argparse.ArgumentParser(description="Check that a second run of an image repeated the first: the same G3-G5 "
                                             "gates and evidence index, wherever and whenever each ran.")
parser.add_argument("first", type=Path, help="the first run's folder (results/NAME/TIME/run)")
parser.add_argument("second", type=Path, help="the second run's folder")
args = parser.parse_args()
lines = repeat_differences(args.first, args.second)
print("\n".join(lines) if lines else "the second run repeated the first: same G3-G5 gates and evidence index")
sys.exit(1 if lines else 0)
