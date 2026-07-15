"""Immutable data structures shared by analyzer modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


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
