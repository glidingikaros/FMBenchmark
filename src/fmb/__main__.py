import sys

from fmb.cli.app import main

if __name__ == "__main__":
    sys.argv[0] = "fmb"
    raise SystemExit(main())
