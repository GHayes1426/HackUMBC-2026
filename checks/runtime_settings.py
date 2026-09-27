"""Fixed detection rules used by the IOC / CVE Analyzer.

Port a Potty is a teaching tool, so the brute-force and password-spray rules
are not user-tunable: every visitor sees the same, easy-to-explain result for
the same example log. Change the numbers here if the lesson needs different
examples.
"""

from __future__ import annotations

from dawgwatch.settings import DetectionSettings


DEMO_DETECTION_SETTINGS = DetectionSettings(
    brute_force_failures=4,
    brute_force_window_seconds=120,
    password_spray_accounts=4,
    password_spray_window_seconds=300,
    password_spray_max_attempts_per_account=3,
    alert_cooldown_seconds=300,
)


def load_detection_settings() -> DetectionSettings:
    """Return the fixed, demo-friendly detection rules."""
    return DEMO_DETECTION_SETTINGS
