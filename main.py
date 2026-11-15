"""Command-line entry point: python main.py <auth.log> [options]."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from analyser.detector import detect
from analyser.parser import parse_file
from analyser.report import format_table, write_csv, write_json

EXIT_CLEAN, EXIT_FLAGGED, EXIT_ERROR = 0, 1, 2


def positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Flag SSH brute-force attempts in a Linux auth.log file.",
        epilog="Exit codes: 0 = nothing flagged, 1 = at least one IP flagged, 2 = error.",
    )
    parser.add_argument("logfile", type=Path, help="path to an auth.log style file")
    parser.add_argument("--threshold", type=positive_int, default=5,
                        help="flag an IP with MORE than this many failures in the window (default 5)")
    parser.add_argument("--window", type=positive_int, default=300,
                        help="window length in seconds (default 300)")
    parser.add_argument("--top", type=positive_int, default=10, help="rows to show in the table (default 10)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year for syslog timestamps, which have none (default: this year)")
    parser.add_argument("--json", type=Path, metavar="PATH", help="also write results to a JSON file")
    parser.add_argument("--csv", type=Path, metavar="PATH", help="also write results to a CSV file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.logfile.is_file():
        print(f"error: {args.logfile} is not a readable file", file=sys.stderr)
        return EXIT_ERROR

    parsed = parse_file(args.logfile, args.year)
    reports = detect(parsed.failures, args.threshold, args.window)
    flagged = [r for r in reports if r.flagged]

    print(f"Parsed {len(parsed.failures)} failed logins from {len(reports)} IPs "
          f"({parsed.skipped_lines} other lines skipped).")
    print(f"Rule: more than {args.threshold} failures within {args.window}s. "
          f"Flagged IPs: {len(flagged)}.\n")
    if reports:
        print(format_table(reports, args.top))

    if args.json:
        write_json(reports, args.json, {"threshold": args.threshold, "window_seconds": args.window})
        print(f"\nWrote {args.json}")
    if args.csv:
        write_csv(reports, args.csv)
        print(f"{'' if args.json else chr(10)}Wrote {args.csv}")

    return EXIT_FLAGGED if flagged else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
