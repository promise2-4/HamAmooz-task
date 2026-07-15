"""Command-line interface for the access-log analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze an Apache/Nginx Combined Log Format file.",
    )
    parser.add_argument("input", type=Path, help="path to the access log")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    print(f"Access Log Analysis\nInput: {args.input}")
    return 0
