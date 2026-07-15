"""Small, explainable suspicious-request and server-error heuristics."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from urllib.parse import unquote

from .models import LogEntry, ServerErrorSpike

COMMON_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
DEFAULT_AUTH_ENDPOINTS = frozenset({"/login", "/auth", "/signin", "/api/login", "/api/auth"})
MAX_DECODE_TARGET_LENGTH = 8192
LONG_TARGET_LENGTH = 2048
LONG_USER_AGENT_LENGTH = 1024

_SENSITIVE_PATTERN = re.compile(
    r"(?:^|/)(?:\.env(?:/|$)|\.git(?:/|$)|server-status(?:/|$)|phpmyadmin(?:/|$)|"
    r"wp-admin(?:/|$)|actuator(?:/|$)|(?:[^/?]+\.)?(?:bak|backup|config)(?:/|$))"
)
_SQL_PATTERNS = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b"),
    re.compile(r"\binformation_schema\b"),
    re.compile(r"\b(?:sleep|benchmark)\s*\("),
    re.compile(r"(?:'|\")\s*(?:or|and)\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+"),
)
_XSS_PATTERN = re.compile(r"<\s*script\b|javascript\s*:|\bonerror\s*=|<\s*iframe\b")
_COMMAND_PATTERN = re.compile(
    r"(?:;|&&|\|\||\$\(|`)\s*(?:/bin/(?:ba)?sh|curl|wget|cat|id|whoami)\b|/bin/(?:ba)?sh\b"
)


def decoded_targets(raw_target: str) -> tuple[str, ...]:
    """Return raw plus at most two percent-decoded target variants."""
    variants = [raw_target]
    current = raw_target
    for _ in range(2):
        decoded = unquote(current, errors="replace")
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    return tuple(variants)


def detect_request_indicators(entry: LogEntry) -> tuple[str, ...]:
    """Return stable categories for conservative request heuristics."""
    categories: set[str] = set()
    if entry.method.upper() not in COMMON_METHODS:
        categories.add("unusual_method")
    if len(entry.raw_target) > LONG_TARGET_LENGTH:
        categories.add("long_target")
    if len(entry.user_agent) > LONG_USER_AGENT_LENGTH:
        categories.add("long_user_agent")
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in entry.raw_target + entry.user_agent
    ):
        categories.add("terminal_control")

    if len(entry.raw_target) <= MAX_DECODE_TARGET_LENGTH:
        variants = tuple(value.lower() for value in decoded_targets(entry.raw_target))
        if any("../" in value or "..\\" in value or "/etc/passwd" in value for value in variants):
            categories.add("path_traversal")
        if any(_SENSITIVE_PATTERN.search(value) for value in variants):
            categories.add("sensitive_file_probe")
        if any(pattern.search(value) for value in variants for pattern in _SQL_PATTERNS):
            categories.add("sql_injection")
        if any(_XSS_PATTERN.search(value) for value in variants):
            categories.add("xss")
        if any(_COMMAND_PATTERN.search(value) for value in variants):
            categories.add("command_injection")
    return tuple(sorted(categories))


def detect_server_error_spikes(
    hourly_totals: Counter[datetime],
    hourly_5xx: Counter[datetime],
    *,
    global_5xx_rate: float,
    minimum_requests: int = 20,
    rate_floor: float = 5.0,
    baseline_factor: float = 3.0,
) -> tuple[ServerErrorSpike, ...]:
    """Flag hours above both an absolute and file-wide relative threshold."""
    spikes: list[ServerErrorSpike] = []
    for hour, total in sorted(hourly_totals.items()):
        errors = hourly_5xx[hour]
        rate = errors / total * 100.0 if total else 0.0
        relative_threshold = global_5xx_rate * baseline_factor
        if total < minimum_requests or rate < rate_floor:
            continue
        if global_5xx_rate > 0 and rate < relative_threshold:
            continue
        reason = (
            f"5xx rate {rate:.2f}% is at least {rate_floor:.2f}% and "
            f"{baseline_factor:.2f}x the global baseline"
            if global_5xx_rate > 0
            else f"5xx rate {rate:.2f}% exceeds the {rate_floor:.2f}% floor"
        )
        spikes.append(
            ServerErrorSpike(
                hour=hour,
                total_requests=total,
                server_errors=errors,
                hourly_rate=rate,
                global_rate=global_5xx_rate,
                reason=reason,
            )
        )
    return tuple(spikes)
