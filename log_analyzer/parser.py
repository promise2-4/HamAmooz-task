"""Bounded Combined Log Format parsing and field validation."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

from .models import LogEntry

_QUOTED = r'(?:\\.|[^"\\])*'
_OUTER_PATTERN = re.compile(
    rf'^(?P<ip>\S+) (?P<identity>\S+) (?P<user>\S+) '
    rf'\[(?P<timestamp>[^\]\r\n]{{1,80}})\] "(?P<request>{_QUOTED})" '
    rf'(?P<status>\S+) (?P<size>\S+) '
    rf'"(?P<referrer>{_QUOTED})" "(?P<agent>{_QUOTED})"$'
)
_METHOD_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PROTOCOL_PATTERN = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?)$")


class LogParseError(ValueError):
    """A stable malformed-record classification."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _unescape_quoted(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def normalize_endpoint(raw_target: str) -> str:
    """Remove a query without guessing the application's route schema."""
    if raw_target == "*":
        return "*"
    try:
        parsed = urlsplit(raw_target)
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                return raw_target.split("?", 1)[0]
            return parsed.path or "/"
        return parsed.path or raw_target.split("?", 1)[0]
    except ValueError:
        return raw_target.split("?", 1)[0]


def parse_line(line: str) -> LogEntry:
    """Parse one decoded Combined Log Format record.

    ``LogParseError.reason`` is suitable for stable aggregation and tests.
    """
    if not line:
        raise LogParseError("empty_line")
    if "\x00" in line:
        raise LogParseError("null_byte")

    match = _OUTER_PATTERN.fullmatch(line)
    if match is None:
        raise LogParseError("format_mismatch")
    fields = match.groupdict()

    try:
        ipaddress.ip_address(fields["ip"])
    except ValueError as error:
        raise LogParseError("invalid_ip") from error

    try:
        timestamp = datetime.strptime(
            fields["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError as error:
        raise LogParseError("invalid_timestamp") from error

    try:
        status = int(fields["status"])
    except ValueError as error:
        raise LogParseError("invalid_status") from error
    if not 100 <= status <= 599:
        raise LogParseError("invalid_status")

    size_text = fields["size"]
    if size_text == "-":
        response_size = None
    else:
        try:
            response_size = int(size_text)
        except ValueError as error:
            raise LogParseError("invalid_size") from error
        if response_size < 0:
            raise LogParseError("invalid_size")

    request = _unescape_quoted(fields["request"])
    if request == "-":
        raise LogParseError("missing_request")
    parts = request.split(" ")
    if len(parts) != 3 or any(not part for part in parts):
        raise LogParseError("invalid_request_line")
    method, raw_target, protocol = parts
    if not _METHOD_PATTERN.fullmatch(method):
        raise LogParseError("invalid_method")
    if not raw_target:
        raise LogParseError("invalid_request_line")
    if not _PROTOCOL_PATTERN.fullmatch(protocol):
        raise LogParseError("invalid_protocol")

    return LogEntry(
        ip=fields["ip"],
        remote_identity=fields["identity"],
        authenticated_user=fields["user"],
        timestamp=timestamp,
        method=method,
        raw_target=raw_target,
        endpoint=normalize_endpoint(raw_target),
        protocol=protocol,
        status=status,
        response_size=response_size,
        referrer=_unescape_quoted(fields["referrer"]),
        user_agent=_unescape_quoted(fields["agent"]),
    )
