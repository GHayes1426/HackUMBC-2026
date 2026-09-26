"""Persistent dashboard settings shared by the detection checks."""

from __future__ import annotations

from pathlib import Path

from dawgwatch.settings import DetectionSettings


SETTINGS_PATH = Path(__file__).resolve().parent.parent / ".state" / "detection_settings.json"


def load_detection_settings() -> DetectionSettings:
    """Return saved settings, or safe demo-friendly defaults on first run."""
    if SETTINGS_PATH.exists():
        return DetectionSettings.load(SETTINGS_PATH)
    return DetectionSettings(
        brute_force_failures=4,
        brute_force_window_seconds=120,
        password_spray_accounts=4,
        password_spray_window_seconds=300,
        password_spray_max_attempts_per_account=3,
        alert_cooldown_seconds=300,
    )


def save_detection_settings(settings: DetectionSettings) -> None:
    settings.save(SETTINGS_PATH)
