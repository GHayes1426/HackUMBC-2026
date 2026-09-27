from datetime import datetime, timedelta, timezone
import unittest

from dawgwatch.detectors import DetectionEngine
from dawgwatch.models import EventKind, SecurityEvent
from dawgwatch.settings import DetectionSettings


START = datetime(2026, 9, 26, 16, 0, tzinfo=timezone.utc)


def failed_login(second: int, account: str, source: str = "192.0.2.10") -> SecurityEvent:
    return SecurityEvent(
        kind=EventKind.AUTH_FAILURE,
        occurred_at=START + timedelta(seconds=second),
        source=source,
        target="lab-vm:ssh",
        account=account,
    )


class DetectionEngineTests(unittest.TestCase):
    def test_detects_brute_force_within_configured_window(self) -> None:
        settings = DetectionSettings(brute_force_failures=4, brute_force_window_seconds=60)
        alerts = DetectionEngine(settings).analyze(
            [failed_login(second, "alice") for second in (0, 10, 20, 30)]
        )
        self.assertIn("auth.brute_force", {alert.rule_id for alert in alerts})

    def test_does_not_detect_slow_failures_as_brute_force(self) -> None:
        settings = DetectionSettings(brute_force_failures=4, brute_force_window_seconds=30)
        alerts = DetectionEngine(settings).analyze(
            [failed_login(second, "alice") for second in (0, 20, 40, 60)]
        )
        self.assertNotIn("auth.brute_force", {alert.rule_id for alert in alerts})

    def test_detects_password_spray_across_accounts(self) -> None:
        settings = DetectionSettings(
            brute_force_failures=10,
            password_spray_accounts=4,
            password_spray_window_seconds=60,
            password_spray_max_attempts_per_account=2,
        )
        alerts = DetectionEngine(settings).analyze(
            [failed_login(index * 5, account) for index, account in enumerate(("a", "b", "c", "d"))]
        )
        self.assertIn("auth.password_spray", {alert.rule_id for alert in alerts})

    def test_rejects_invalid_thresholds(self) -> None:
        with self.assertRaises(ValueError):
            DetectionSettings(brute_force_failures=0)


if __name__ == "__main__":
    unittest.main()
