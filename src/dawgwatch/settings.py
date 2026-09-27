from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class DetectionSettings:
    brute_force_failures: int = 8
    brute_force_window_seconds: int = 120
    password_spray_accounts: int = 5
    password_spray_window_seconds: int = 300
    password_spray_max_attempts_per_account: int = 3
    alert_cooldown_seconds: int = 300

    def __post_init__(self) -> None:
        positive_fields = (
            "brute_force_failures",
            "brute_force_window_seconds",
            "password_spray_accounts",
            "password_spray_window_seconds",
            "password_spray_max_attempts_per_account",
            "alert_cooldown_seconds",
        )
        for field_name in positive_fields:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")

    @classmethod
    def load(cls, path: Path) -> DetectionSettings:
        if not path.exists():
            return cls()
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("settings file must contain a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unknown settings: {', '.join(sorted(unknown))}")
        return cls(**raw)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

