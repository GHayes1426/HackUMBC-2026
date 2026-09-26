from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class EventKind(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    HTTP_REQUEST = "http_request"
    SERVICE_OBSERVED = "service_observed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    kind: EventKind
    occurred_at: datetime
    source: str
    target: str
    account: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must include timezone information")
        if not self.source.strip() or not self.target.strip():
            raise ValueError("source and target cannot be blank")

    @classmethod
    def now(
        cls,
        *,
        kind: EventKind,
        source: str,
        target: str,
        account: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        return cls(
            kind=kind,
            occurred_at=datetime.now(timezone.utc),
            source=source,
            target=target,
            account=account,
            details=details or {},
        )


@dataclass(frozen=True, slots=True)
class Alert:
    rule_id: str
    title: str
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    event_count: int
    summary: str
    evidence: tuple[SecurityEvent, ...]

