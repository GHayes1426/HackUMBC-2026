from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .detectors import DetectionEngine
from .models import EventKind, SecurityEvent


def main() -> None:
    started = datetime.now(timezone.utc)
    events = [
        SecurityEvent(
            kind=EventKind.AUTH_FAILURE,
            occurred_at=started + timedelta(seconds=index * 10),
            source="192.0.2.10",
            target="lab-vm:ssh",
            account="demo-user",
        )
        for index in range(8)
    ]
    alerts = DetectionEngine().analyze(events)
    if not alerts:
        print("No suspicious activity detected.")
        return
    for alert in alerts:
        print(f"[{alert.severity.upper()}] {alert.title}")
        print(alert.summary)


if __name__ == "__main__":
    main()

