"""Command-line interface for the access-log analyzer."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .analyzer import AnalyzerOptions, analyze_path
from .report import render_json, render_text, sanitize_text


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


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def percentage(value: str) -> float:
    number = positive_float(value)
    if number > 100:
        raise argparse.ArgumentTypeError("must not exceed 100")
    return number


def iso_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an ISO 8601 datetime") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("must include a UTC offset or Z")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze an Apache/Nginx Combined Log Format file.",
    )
    parser.add_argument("input", type=Path, help="path to the access log")
    parser.add_argument("--top", type=positive_int, default=10, help="number of endpoints to show")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    parser.add_argument(
        "--from", dest="from_time", type=iso_datetime, help="inclusive ISO 8601 start"
    )
    parser.add_argument(
        "--to", dest="to_time", type=iso_datetime, help="exclusive ISO 8601 end"
    )
    parser.add_argument(
        "--max-line-length",
        type=positive_int,
        default=64 * 1024,
        help="maximum logical line length in bytes (default: 65536)",
    )
    parser.add_argument(
        "--login-failure-threshold",
        type=positive_int,
        default=10,
        help="failed-authentication alert threshold (default: 10)",
    )
    parser.add_argument(
        "--spike-min-requests",
        type=positive_int,
        default=20,
        help="minimum requests in a server-error spike bucket (default: 20)",
    )
    parser.add_argument(
        "--spike-rate-floor",
        type=percentage,
        default=5.0,
        help="minimum hourly 5xx percentage (default: 5)",
    )
    parser.add_argument(
        "--spike-baseline-factor",
        type=positive_float,
        default=3.0,
        help="minimum multiple of global 5xx rate (default: 3)",
    )
    parser.add_argument(
        "--show-invalid",
        type=nonnegative_int,
        default=5,
        help="maximum malformed examples to retain (default: 5)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.from_time is not None and args.to_time is not None and args.from_time >= args.to_time:
        parser.error("--from must be earlier than --to")
    if not args.input.is_file():
        print(f"error: input file not found: {sanitize_text(str(args.input))}", file=sys.stderr)
        return 2
    try:
        result = analyze_path(
            args.input,
            AnalyzerOptions(
                from_time=args.from_time,
                to_time=args.to_time,
                max_line_length=args.max_line_length,
                malformed_example_limit=args.show_invalid,
                login_failure_threshold=args.login_failure_threshold,
                spike_minimum_requests=args.spike_min_requests,
                spike_rate_floor=args.spike_rate_floor,
                spike_baseline_factor=args.spike_baseline_factor,
            ),
        )
    except (OSError, EOFError) as error:
        print(f"error: unable to analyze input: {sanitize_text(str(error))}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"error: analysis failed: {sanitize_text(str(error))}", file=sys.stderr)
        return 1
    renderer = render_json if args.format == "json" else render_text
    print(renderer(result, top=args.top), end="")
    return 0
