"""Single-pass aggregation for parsed access-log records."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .io_utils import DEFAULT_MAX_LINE_LENGTH, iter_bounded_lines, open_binary_input
from .models import AnalysisResult, MalformedExample, SuspiciousSample
from .parser import LogParseError, parse_line
from .report import sanitize_text
from .security import DEFAULT_AUTH_ENDPOINTS, detect_request_indicators, detect_server_error_spikes


@dataclass(frozen=True, slots=True)
class AnalyzerOptions:
    from_time: datetime | None = None
    to_time: datetime | None = None
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    malformed_example_limit: int = 5
    security_example_limit: int = 10
    login_failure_threshold: int = 10
    auth_endpoints: frozenset[str] = DEFAULT_AUTH_ENDPOINTS
    spike_minimum_requests: int = 20
    spike_rate_floor: float = 5.0
    spike_baseline_factor: float = 3.0


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
    hourly_5xx_counts: Counter[datetime] = Counter()
    suspicious_category_counts: Counter[str] = Counter()
    suspicious_endpoint_counts: Counter[str] = Counter()
    suspicious_ip_counts: Counter[str] = Counter()
    suspicious_samples: list[SuspiciousSample] = []
    suspicious_5xx_samples: list[SuspiciousSample] = []
    suspicious_5xx_category_counts: Counter[str] = Counter()
    suspicious_5xx_endpoint_counts: Counter[str] = Counter()
    suspicious_5xx_ip_counts: Counter[str] = Counter()
    login_failure_counts: Counter[str] = Counter()

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
            if 500 <= entry.status <= 599:
                hourly_5xx_counts[hour] += 1

            if entry.endpoint.lower() in options.auth_endpoints and entry.status in {401, 403}:
                login_failure_counts[entry.ip] += 1

            categories = detect_request_indicators(entry)
            if categories:
                suspicious_category_counts.update(categories)
                suspicious_endpoint_counts[entry.endpoint] += 1
                suspicious_ip_counts[entry.ip] += 1
                sample = SuspiciousSample(
                    timestamp=entry.timestamp,
                    ip=entry.ip,
                    method=entry.method,
                    endpoint=sanitize_text(entry.endpoint, limit=160),
                    status=entry.status,
                    categories=categories,
                    # Query values are intentionally excluded from retained samples.
                    target_sample=sanitize_text(entry.endpoint, limit=160),
                )
                if len(suspicious_samples) < options.security_example_limit:
                    suspicious_samples.append(sample)
                if 500 <= entry.status <= 599:
                    suspicious_5xx_category_counts.update(categories)
                    suspicious_5xx_endpoint_counts[entry.endpoint] += 1
                    suspicious_5xx_ip_counts[entry.ip] += 1
                    if len(suspicious_5xx_samples) < options.security_example_limit:
                        suspicious_5xx_samples.append(sample)

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
    global_5xx_rate = (
        status_class_counts["5xx"] / selected_requests * 100.0
        if selected_requests
        else 0.0
    )
    spikes = detect_server_error_spikes(
        hourly_counts,
        hourly_5xx_counts,
        global_5xx_rate=global_5xx_rate,
        minimum_requests=options.spike_minimum_requests,
        rate_floor=options.spike_rate_floor,
        baseline_factor=options.spike_baseline_factor,
    )
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
        hourly_5xx_counts=hourly_5xx_counts,
        suspicious_category_counts=suspicious_category_counts,
        suspicious_endpoint_counts=suspicious_endpoint_counts,
        suspicious_ip_counts=suspicious_ip_counts,
        suspicious_samples=tuple(suspicious_samples),
        suspicious_5xx_samples=tuple(suspicious_5xx_samples),
        suspicious_5xx_category_counts=suspicious_5xx_category_counts,
        suspicious_5xx_endpoint_counts=suspicious_5xx_endpoint_counts,
        suspicious_5xx_ip_counts=suspicious_5xx_ip_counts,
        login_failure_counts=login_failure_counts,
        login_failure_threshold=options.login_failure_threshold,
        server_error_spikes=spikes,
        elapsed_seconds=elapsed,
    )
