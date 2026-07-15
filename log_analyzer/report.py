"""Safe, stable text rendering for analysis results."""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timedelta

from .models import AnalysisResult, SuspiciousSample

_MAX_FILLED_HOURS = 24 * 366


def sanitize_text(value: str, limit: int = 200) -> str:
    """Escape terminal controls and truncate untrusted text."""
    pieces: list[str] = []
    current_length = 0
    for character in value:
        if character == "\x1b":
            replacement = r"\x1b"
        elif character in {"\n", "\r", "\t", "\x00"}:
            replacement = {
                "\n": r"\n",
                "\r": r"\r",
                "\t": r"\t",
                "\x00": r"\x00",
            }[character]
        elif unicodedata.category(character).startswith("C"):
            replacement = f"\\u{ord(character):04x}"
        else:
            replacement = character
        if current_length + len(replacement) > limit:
            pieces.append("...")
            break
        pieces.append(replacement)
        current_length += len(replacement)
    return "".join(pieces)


def hourly_series(result: AnalysisResult) -> list[tuple[datetime, int]]:
    if not result.hourly_counts:
        return []
    first = min(result.hourly_counts)
    last = max(result.hourly_counts)
    span = int((last - first).total_seconds() // 3600) + 1
    if span > _MAX_FILLED_HOURS:
        return sorted(result.hourly_counts.items())
    return [
        (first + timedelta(hours=offset), result.hourly_counts[first + timedelta(hours=offset)])
        for offset in range(span)
    ]


def _histogram(result: AnalysisResult, width: int = 40) -> list[str]:
    series = hourly_series(result)
    if not series:
        return ["  No requests in the selected range."]
    peak = max(count for _, count in series)
    lines: list[str] = []
    for hour, count in series:
        bar_length = 0 if peak == 0 else round(count / peak * width)
        lines.append(f"  {hour.isoformat()}  {count:>8}  {'#' * bar_length}")
    return lines


def render_text(result: AnalysisResult, top: int = 10) -> str:
    """Render a readable report without emitting raw untrusted content."""
    lines = [
        "Access Log Analysis",
        "",
        "Input",
        f"  Path: {sanitize_text(result.input_path)}",
        f"  File size: {result.file_size if result.file_size is not None else 'unknown'} bytes",
        "",
        "Summary",
        f"  Total physical lines: {result.total_lines}",
        f"  Valid requests: {result.valid_requests}",
        f"  Selected requests: {result.selected_requests}",
        f"  Filtered-out requests: {result.filtered_out_requests}",
        f"  Malformed lines: {result.malformed_lines}",
        f"  Unique client IPs: {result.unique_ip_count}",
        f"  Combined 4xx + 5xx errors: {result.error_count}",
        f"  Error rate: {result.error_rate:.2f}% (selected valid requests)",
        "",
        "Status Distribution",
    ]
    if result.status_counts:
        lines.extend(
            f"  {status}: {count}" for status, count in sorted(result.status_counts.items())
        )
        lines.extend(
            f"  {status_class}: {result.status_class_counts[status_class]}"
            for status_class in ("1xx", "2xx", "3xx", "4xx", "5xx")
        )
    else:
        lines.append("  No valid requests in the selected range.")

    lines.extend(["", f"Top Endpoints (top {top})"])
    if result.endpoint_counts:
        lines.extend(
            f"  {count:>8}  {sanitize_text(endpoint, 160)}"
            for endpoint, count in result.endpoint_counts.most_common(top)
        )
    else:
        lines.append("  No endpoints in the selected range.")

    lines.extend(["", "Requests by Hour (UTC)", *_histogram(result)])
    lines.extend(["", "Malformed Records"])
    if result.malformed_reasons:
        lines.extend(
            f"  {reason}: {count}"
            for reason, count in sorted(result.malformed_reasons.items())
        )
        if result.malformed_examples:
            lines.append("  Examples:")
            lines.extend(
                f"    line {example.line_number} [{example.reason}]: {example.sample}"
                for example in result.malformed_examples
            )
    else:
        lines.append("  None.")

    lines.extend(["", "Suspicious Activity"])
    if result.suspicious_category_counts:
        lines.extend(
            f"  {category}: {count}"
            for category, count in sorted(result.suspicious_category_counts.items())
        )
        lines.append("  Bounded examples (heuristics, not proven attacks):")
        lines.extend(
            "    "
            f"{sample.timestamp.isoformat()} {sample.ip} {sample.method} "
            f"{sample.endpoint} {sample.status} [{', '.join(sample.categories)}]"
            for sample in result.suspicious_samples
        )
    else:
        lines.append("  No request-signature indicators detected.")
    offenders = result.login_failure_offenders.most_common(10)
    if offenders:
        lines.append(
            f"  Repeated authentication failures (threshold {result.login_failure_threshold}):"
        )
        lines.extend(f"    {ip}: {count}" for ip, count in offenders)
    else:
        lines.append(
            f"  No authentication source reached the threshold of {result.login_failure_threshold}."
        )
    if result.suspicious_5xx_samples:
        lines.append("  Potential crash-trigger candidates (access-log heuristic only):")
        lines.extend(
            f"    {category}: {count}"
            for category, count in sorted(result.suspicious_5xx_category_counts.items())
        )
        lines.extend(
            "    "
            f"{sample.timestamp.isoformat()} {sample.ip} {sample.method} "
            f"{sample.endpoint} {sample.status} [{', '.join(sample.categories)}]"
            for sample in result.suspicious_5xx_samples
        )
        lines.append("  Application logs, traces, and request IDs are required to prove causality.")
    else:
        lines.append("  No suspicious 5xx request candidates detected.")

    lines.extend(["", "Server Error Spikes"])
    if result.server_error_spikes:
        lines.extend(
            "  "
            f"{spike.hour.isoformat()}: {spike.server_errors}/{spike.total_requests} "
            f"5xx ({spike.hourly_rate:.2f}%); global {spike.global_rate:.2f}% - "
            f"{spike.reason}"
            for spike in result.server_error_spikes
        )
    else:
        lines.append("  No hourly bucket met the configured spike heuristic.")

    lines.extend(
        [
            "",
            "Performance",
            f"  Elapsed: {result.elapsed_seconds:.6f} seconds",
            f"  Throughput: {result.lines_per_second:.2f} lines/second",
        ]
    )
    if result.mebibytes_per_second is not None:
        lines.append(f"  Throughput: {result.mebibytes_per_second:.2f} MiB/second")
    return "\n".join(lines) + "\n"


def result_to_dict(result: AnalysisResult, top: int = 10) -> dict[str, object]:
    """Convert a result to JSON-safe primitives with stable field names."""
    return {
        "input": {
            "path": result.input_path,
            "file_size_bytes": result.file_size,
            "compressed": result.compressed,
        },
        "summary": {
            "total_lines": result.total_lines,
            "valid_requests": result.valid_requests,
            "selected_requests": result.selected_requests,
            "filtered_out_requests": result.filtered_out_requests,
            "malformed_lines": result.malformed_lines,
            "unique_ip_count": result.unique_ip_count,
            "error_count_4xx_5xx": result.error_count,
            "error_rate_percent": result.error_rate,
            "error_rate_denominator": "selected_valid_requests",
        },
        "status_counts": {str(key): value for key, value in sorted(result.status_counts.items())},
        "status_class_counts": {
            key: result.status_class_counts[key]
            for key in ("1xx", "2xx", "3xx", "4xx", "5xx")
        },
        "top_endpoints": [
            {"endpoint": endpoint, "requests": count}
            for endpoint, count in result.endpoint_counts.most_common(top)
        ],
        "hourly_counts_utc": [
            {"hour": hour.isoformat(), "requests": count}
            for hour, count in hourly_series(result)
        ],
        "malformed": {
            "reason_counts": dict(sorted(result.malformed_reasons.items())),
            "examples": [
                {
                    "line_number": example.line_number,
                    "reason": example.reason,
                    "sample": example.sample,
                }
                for example in result.malformed_examples
            ],
        },
        "security": {
            "indicator_counts": dict(sorted(result.suspicious_category_counts.items())),
            "top_endpoints": result.suspicious_endpoint_counts.most_common(10),
            "top_ips": result.suspicious_ip_counts.most_common(10),
            "samples": [_sample_to_dict(sample) for sample in result.suspicious_samples],
            "login_failure_threshold": result.login_failure_threshold,
            "login_failure_offenders": result.login_failure_offenders.most_common(10),
            "potential_crash_trigger_candidates": [
                _sample_to_dict(sample) for sample in result.suspicious_5xx_samples
            ],
            "potential_candidate_category_counts": dict(
                sorted(result.suspicious_5xx_category_counts.items())
            ),
            "potential_candidate_top_endpoints": result.suspicious_5xx_endpoint_counts.most_common(10),
            "potential_candidate_top_ips": result.suspicious_5xx_ip_counts.most_common(10),
            "causality_notice": (
                "Access logs cannot prove crash causality; application logs, traces, "
                "and request IDs are required."
            ),
        },
        "server_error_spikes": [
            {
                "hour": spike.hour.isoformat(),
                "total_requests": spike.total_requests,
                "server_errors": spike.server_errors,
                "hourly_rate_percent": spike.hourly_rate,
                "global_rate_percent": spike.global_rate,
                "reason": spike.reason,
            }
            for spike in result.server_error_spikes
        ],
        "performance": {
            "elapsed_seconds": result.elapsed_seconds,
            "lines_per_second": result.lines_per_second,
            "mebibytes_per_second": result.mebibytes_per_second,
        },
    }


def _sample_to_dict(sample: SuspiciousSample) -> dict[str, object]:
    # Kept local to avoid exposing mutable dataclass serialization details.
    return {
        "timestamp": sample.timestamp.isoformat(),
        "ip": sample.ip,
        "method": sample.method,
        "endpoint": sample.endpoint,
        "status": sample.status,
        "categories": list(sample.categories),
        "target_sample": sample.target_sample,
    }


def render_json(result: AnalysisResult, top: int = 10) -> str:
    return json.dumps(result_to_dict(result, top), indent=2, sort_keys=True) + "\n"
