"""Command line: `cheatcatcher scan --trajectory run.jsonl --patch fix.diff`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gauntlet_sandbox import Trajectory

from . import __version__
from .rules import RULES
from .scan import scan

EXIT_CODES = {"clean": 0, "suspicious": 1, "cheating": 2}


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.trajectory and not args.patch:
        print("give me --trajectory, --patch or both", file=sys.stderr)
        return 64
    traj = Trajectory.load(args.trajectory) if args.trajectory else None
    patch = None
    if args.patch:
        patch = sys.stdin.read() if args.patch == "-" else Path(args.patch).read_text()
    report = scan(traj, patch, protected_paths=args.protect)
    print(report.model_dump_json(indent=2) if args.json else report.to_markdown())
    return EXIT_CODES[report.verdict]


def cmd_rules(_: argparse.Namespace) -> int:
    for name, fn in RULES.items():
        doc = (fn.__doc__ or "").strip().splitlines()
        print(f"{name}{'  ' + doc[0] if doc else ''}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cheatcatcher", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a trajectory and/or patch (exit 0 clean, 1 suspicious, 2 cheating)")
    p.add_argument("--trajectory", help="gauntlet-sandbox trajectory JSONL")
    p.add_argument("--patch", help="unified diff file, or - for stdin")
    p.add_argument("--protect", nargs="*", default=[], metavar="PATH", help="test files the grader owns")
    p.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("rules", help="list the rules")
    p.set_defaults(fn=cmd_rules)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
