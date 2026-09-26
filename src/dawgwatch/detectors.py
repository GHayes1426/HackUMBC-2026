from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from itertools import groupby
from operator import attrgetter
from typing import Iterable

from .models import Alert, EventKind, SecurityEvent, Severity
from .settings import DetectionSettings


class DetectionEngine:
    def __init__(self, settings: DetectionSettings | None = None) -> None:
        self.settings = settings or DetectionSettings()

    def analyze(self, events: Iterable[SecurityEvent]) -> list[Alert]:
        ordered = sorted(events, key=attrgetter("occurred_at"))
        failures = [event for event in ordered if event.kind == EventKind.AUTH_FAILURE]
        return self._detect_brute_force(failures) + self._detect_password_spray(failures)

    def _detect_brute_force(self, failures: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        key = lambda event: (event.source, event.target, event.account or "<unknown>")
        for (source, target, account), grouped in groupby(sorted(failures, key=key), key=key):
            events = sorted(grouped, key=attrgetter("occurred_at"))
            window = timedelta(seconds=self.settings.brute_force_window_seconds)
            match = _first_threshold_window(events, self.settings.brute_force_failures, window)
            if match:
                alerts.append(
                    Alert(
                        rule_id="auth.brute_force",
                        title="Possible brute-force login activity",
                        severity=Severity.HIGH,
                        first_seen=match[0].occurred_at,
                        last_seen=match[-1].occurred_at,
                        event_count=len(match),
                        summary=(
                            f"{len(match)} failed logins from {source} targeted account "
                            f"{account} on {target} within {int(window.total_seconds())} seconds."
                        ),
                        evidence=tuple(match),
                    )
                )
        return alerts

    def _detect_password_spray(self, failures: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for event in failures:
            grouped[(event.source, event.target)].append(event)

        window = timedelta(seconds=self.settings.password_spray_window_seconds)
        for (source, target), events in grouped.items():
            ordered = sorted(events, key=attrgetter("occurred_at"))
            for start_index, start in enumerate(ordered):
                candidate = [
                    event
                    for event in ordered[start_index:]
                    if event.occurred_at - start.occurred_at <= window
                ]
                counts = Counter(event.account for event in candidate if event.account)
                eligible = {
                    account
                    for account, count in counts.items()
                    if count <= self.settings.password_spray_max_attempts_per_account
                }
                if len(eligible) >= self.settings.password_spray_accounts:
                    evidence = [event for event in candidate if event.account in eligible]
                    alerts.append(
                        Alert(
                            rule_id="auth.password_spray",
                            title="Possible password-spraying activity",
                            severity=Severity.HIGH,
                            first_seen=evidence[0].occurred_at,
                            last_seen=evidence[-1].occurred_at,
                            event_count=len(evidence),
                            summary=(
                                f"Failed logins from {source} targeted {len(eligible)} accounts "
                                f"on {target} within {int(window.total_seconds())} seconds."
                            ),
                            evidence=tuple(evidence),
                        )
                    )
                    break
        return alerts


def _first_threshold_window(
    events: list[SecurityEvent], threshold: int, window: timedelta
) -> list[SecurityEvent] | None:
    left = 0
    for right, event in enumerate(events):
        while event.occurred_at - events[left].occurred_at > window:
            left += 1
        if right - left + 1 >= threshold:
            return events[left : right + 1]
    return None

