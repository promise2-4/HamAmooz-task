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
class SuspiciousSample:
    timestamp: datetime
    ip: str
    method: str
    endpoint: str
    status: int
    categories: tuple[str, ...]
    target_sample: str


@dataclass(frozen=True, slots=True)
class ServerErrorSpike:
    hour: datetime
    total_requests: int
    server_errors: int
    hourly_rate: float
    global_rate: float
    reason: str


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
    hourly_5xx_counts: Counter[datetime]
    suspicious_category_counts: Counter[str]
    suspicious_endpoint_counts: Counter[str]
    suspicious_ip_counts: Counter[str]
    suspicious_samples: tuple[SuspiciousSample, ...]
    suspicious_5xx_samples: tuple[SuspiciousSample, ...]
    suspicious_5xx_category_counts: Counter[str]
    suspicious_5xx_endpoint_counts: Counter[str]
    suspicious_5xx_ip_counts: Counter[str]
    login_failure_counts: Counter[str]
    login_failure_threshold: int
    server_error_spikes: tuple[ServerErrorSpike, ...]
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

    @property
    def login_failure_offenders(self) -> Counter[str]:
        return Counter(
            {
                ip: count
                for ip, count in self.login_failure_counts.items()
                if count >= self.login_failure_threshold
            }
        )
