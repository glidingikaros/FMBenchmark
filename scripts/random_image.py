#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

from fmb.replication import image_files

parser = argparse.ArgumentParser(description="Write a random image definition that fmb generate accepts.")
parser.add_argument("seed", type=int, help="the seed of the definition; the same seed gives the same file")
parser.add_argument("path", type=Path, help="where to write it, such as images/random.json")
args = parser.parse_args()
args.path.write_text(json.dumps(image_files.random_definition(args.seed), indent=2) + "\n", encoding="utf-8")
print(image_files.check(image_files.load(args.path)))
