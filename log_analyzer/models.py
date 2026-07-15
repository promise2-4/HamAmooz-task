"""Immutable data structures shared by analyzer modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from collections import Counter


@dataclass(frozen=True, slots=True)
class LogEntry:
    ip: str
    remote_identity: str
    authenticated_user: str
    timestamp: datetime
    method: str
    raw_target: str
    endpoint: str
    protocol: str
    status: int
    response_size: int | None
    referrer: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class InputLine:
    line_number: int
    text: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class MalformedExample:
    line_number: int
    reason: str
    sample: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    input_path: str
    file_size: int | None
    compressed: bool
    total_lines: int
    valid_requests: int
    selected_requests: int
    filtered_out_requests: int
    malformed_lines: int
    malformed_reasons: Counter[str]
    malformed_examples: tuple[MalformedExample, ...]
    unique_ips: frozenset[str]
    endpoint_counts: Counter[str]
    status_counts: Counter[int]
    hourly_counts: Counter[datetime]
    status_class_counts: Counter[str]
    elapsed_seconds: float

    @property
    def error_count(self) -> int:
        return self.status_class_counts["4xx"] + self.status_class_counts["5xx"]

    @property
    def error_rate(self) -> float:
        if not self.selected_requests:
            return 0.0
        return self.error_count / self.selected_requests * 100.0

    @property
    def unique_ip_count(self) -> int:
        return len(self.unique_ips)

    @property
    def lines_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.total_lines / self.elapsed_seconds

    @property
    def mebibytes_per_second(self) -> float | None:
        if self.compressed or self.file_size is None or self.elapsed_seconds <= 0:
            return None
        return self.file_size / (1024 * 1024) / self.elapsed_seconds
