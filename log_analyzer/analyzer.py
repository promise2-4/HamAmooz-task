"""Single-pass aggregation for parsed access-log records."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .io_utils import DEFAULT_MAX_LINE_LENGTH, iter_bounded_lines, open_binary_input
from .models import AnalysisResult, MalformedExample
from .parser import LogParseError, parse_line
from .report import sanitize_text


@dataclass(frozen=True, slots=True)
class AnalyzerOptions:
    from_time: datetime | None = None
    to_time: datetime | None = None
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    malformed_example_limit: int = 5


def analyze_path(path: Path, options: AnalyzerOptions | None = None) -> AnalysisResult:
    """Analyze ``path`` in one streaming pass and return exact aggregates."""
    options = options or AnalyzerOptions()
    started = time.perf_counter()
    total_lines = 0
    valid_requests = 0
    selected_requests = 0
    filtered_out_requests = 0
    malformed_lines = 0
    malformed_reasons: Counter[str] = Counter()
    malformed_examples: list[MalformedExample] = []
    unique_ips: set[str] = set()
    endpoint_counts: Counter[str] = Counter()
    status_counts: Counter[int] = Counter()
    hourly_counts: Counter[datetime] = Counter()
    status_class_counts: Counter[str] = Counter()

    def record_malformed(line_number: int, reason: str, sample: str) -> None:
        nonlocal malformed_lines
        malformed_lines += 1
        malformed_reasons[reason] += 1
        if len(malformed_examples) < options.malformed_example_limit:
            display = sample or "<content discarded>"
            malformed_examples.append(
                MalformedExample(line_number, reason, sanitize_text(display, limit=160))
            )

    with open_binary_input(path) as stream:
        for record in iter_bounded_lines(stream, options.max_line_length):
            total_lines += 1
            if record.error is not None:
                record_malformed(record.line_number, record.error, record.text)
                continue
            try:
                entry = parse_line(record.text)
            except LogParseError as error:
                record_malformed(record.line_number, error.reason, record.text)
                continue
            except Exception:
                record_malformed(
                    record.line_number, "unexpected_parse_error", record.text
                )
                continue

            valid_requests += 1
            if options.from_time is not None and entry.timestamp < options.from_time:
                filtered_out_requests += 1
                continue
            if options.to_time is not None and entry.timestamp >= options.to_time:
                filtered_out_requests += 1
                continue

            selected_requests += 1
            unique_ips.add(entry.ip)
            endpoint_counts[entry.endpoint] += 1
            status_counts[entry.status] += 1
            status_class_counts[f"{entry.status // 100}xx"] += 1
            hour = entry.timestamp.astimezone(timezone.utc).replace(
                minute=0, second=0, microsecond=0
            )
            hourly_counts[hour] += 1

    elapsed = time.perf_counter() - started
    if total_lines != valid_requests + malformed_lines:
        raise RuntimeError("analysis line-count invariant failed")
    if sum(status_counts.values()) != selected_requests:
        raise RuntimeError("analysis status-count invariant failed")
    if sum(hourly_counts.values()) != selected_requests:
        raise RuntimeError("analysis hourly-count invariant failed")
    if len(unique_ips) > selected_requests:
        raise RuntimeError("analysis unique-IP invariant failed")

    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = None
    return AnalysisResult(
        input_path=str(path),
        file_size=file_size,
        compressed=path.suffix.lower() == ".gz",
        total_lines=total_lines,
        valid_requests=valid_requests,
        selected_requests=selected_requests,
        filtered_out_requests=filtered_out_requests,
        malformed_lines=malformed_lines,
        malformed_reasons=malformed_reasons,
        malformed_examples=tuple(malformed_examples),
        unique_ips=frozenset(unique_ips),
        endpoint_counts=endpoint_counts,
        status_counts=status_counts,
        hourly_counts=hourly_counts,
        status_class_counts=status_class_counts,
        elapsed_seconds=elapsed,
    )
