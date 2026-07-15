"""Command-line interface for the access-log analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import AnalyzerOptions, analyze_path
from .report import render_text, sanitize_text


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def nonnegative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze an Apache/Nginx Combined Log Format file.",
    )
    parser.add_argument("input", type=Path, help="path to the access log")
    parser.add_argument("--top", type=positive_int, default=10, help="number of endpoints to show")
    parser.add_argument(
        "--max-line-length",
        type=positive_int,
        default=64 * 1024,
        help="maximum logical line length in bytes (default: 65536)",
    )
    parser.add_argument(
        "--show-invalid",
        type=nonnegative_int,
        default=5,
        help="maximum malformed examples to retain (default: 5)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input.is_file():
        print(f"error: input file not found: {sanitize_text(str(args.input))}", file=sys.stderr)
        return 2
    try:
        result = analyze_path(
            args.input,
            AnalyzerOptions(
                max_line_length=args.max_line_length,
                malformed_example_limit=args.show_invalid,
            ),
        )
    except (OSError, EOFError) as error:
        print(f"error: unable to analyze input: {sanitize_text(str(error))}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"error: analysis failed: {sanitize_text(str(error))}", file=sys.stderr)
        return 1
    print(render_text(result, top=args.top), end="")
    return 0
