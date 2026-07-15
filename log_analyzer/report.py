"""Safe, stable text rendering for analysis results."""

from __future__ import annotations

import unicodedata
from datetime import datetime, timedelta

from .models import AnalysisResult

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
