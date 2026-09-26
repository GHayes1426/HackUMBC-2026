"""Curated, safe log scenarios used for the Port a Potty demo."""

from __future__ import annotations

import os
import json
from pathlib import Path
import sys
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
STATE_ROOT = (
    Path(os.environ.get("APPDATA", Path.home())) / "Port a Potty"
    if getattr(sys, "frozen", False)
    else PROJECT_ROOT / ".state"
)
DEMO_LOG_DIR = RESOURCE_ROOT / "sample_data"
SCENARIOS = {
    "combined_attack": ("sample_auth.log", "Combined brute-force and password-spray scenario"),
    "brute_force": ("brute_force.log", "Brute-force SSH scenario"),
    "password_spray": ("password_spray.log", "Password-spraying scenario"),
    "normal_activity": ("normal_activity.log", "Normal SSH activity"),
}
DEFAULT_SCENARIO = "combined_attack"
SCENARIO_STATE_PATH = STATE_ROOT / "demo_scenario.json"
UPLOAD_DIR = SCENARIO_STATE_PATH.parent / "uploaded_logs"
UPLOAD_INDEX_PATH = SCENARIO_STATE_PATH.parent / "uploaded_logs.json"
MAX_RECENT_UPLOADS = 8


def load_demo_log():
    """Return lines and a label for the selected bundled or uploaded log."""
    source = load_log_source()
    if source.startswith("upload:"):
        if os.environ.get("VERCEL"):
            from dawgwatch.storage import uploaded_log_content
            content = uploaded_log_content(source[7:])
            upload = next((item for item in _uploads() if item["id"] == source[7:]), None)
            if content is not None and upload:
                return content.splitlines(), f"UPLOADED LOG: {upload['name']}", True
        upload = next((item for item in _uploads() if item["id"] == source[7:]), None)
        if upload:
            path = UPLOAD_DIR / upload["stored_name"]
            if path.is_file():
                return path.read_text(encoding="utf-8").splitlines(), f"UPLOADED LOG: {upload['name']}", True

    scenario = source.removeprefix("demo:")
    filename, title = SCENARIOS.get(scenario, SCENARIOS[DEFAULT_SCENARIO])
    path = DEMO_LOG_DIR / filename
    return path.read_text(encoding="utf-8").splitlines(), f"DEMO SCENARIO: {title}", True


def load_demo_scenario() -> str:
    """Get the saved demo scenario, optionally seeded by the local .env value."""
    try:
        saved = json.loads(SCENARIO_STATE_PATH.read_text(encoding="utf-8"))
        selected = saved.get("source", saved.get("scenario"))
    except (OSError, ValueError, AttributeError):
        selected = os.environ.get("PORT_A_POTTY_LOG_SCENARIO", DEFAULT_SCENARIO)
    if isinstance(selected, str) and selected.startswith("demo:"):
        selected = selected[5:]
    return selected if selected in SCENARIOS else DEFAULT_SCENARIO


def save_demo_scenario(scenario: str) -> None:
    if scenario not in SCENARIOS:
        raise ValueError("Unknown demo scenario.")
    SCENARIO_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_log_source(f"demo:{scenario}")


def log_sources() -> list[tuple[str, str]]:
    sources = [(f"demo:{key}", f"Demo: {title}") for key, (_, title) in SCENARIOS.items()]
    sources.extend((f"upload:{item['id']}", f"Uploaded: {item['name']}") for item in _uploads())
    return sources


def load_log_source() -> str:
    if os.environ.get("VERCEL"):
        from dawgwatch.storage import get_setting
        selected = (get_setting("log_source") or {}).get("source")
    else:
        selected = None
    try:
        if selected is None:
            saved = json.loads(SCENARIO_STATE_PATH.read_text(encoding="utf-8"))
            selected = saved.get("source")
    except (OSError, ValueError, AttributeError):
        selected = None
    valid = {source for source, _ in log_sources()}
    if selected in valid:
        return selected
    return f"demo:{os.environ.get('PORT_A_POTTY_LOG_SCENARIO', DEFAULT_SCENARIO)}" if os.environ.get("PORT_A_POTTY_LOG_SCENARIO") in SCENARIOS else f"demo:{DEFAULT_SCENARIO}"


def save_log_source(source: str) -> None:
    if source not in {item[0] for item in log_sources()}:
        raise ValueError("Unknown log source.")
    if os.environ.get("VERCEL"):
        from dawgwatch.storage import put_setting
        if put_setting("log_source", {"source": source}):
            return
    SCENARIO_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_STATE_PATH.write_text(json.dumps({"source": source}) + "\n", encoding="utf-8")


def store_uploaded_log(name: str, text: str) -> str:
    """Store a validated text log and retain only the newest eight uploads."""
    if os.environ.get("VERCEL"):
        from dawgwatch.storage import save_uploaded_log
        entry_id = save_uploaded_log(name, text)
        if entry_id:
            source = f"upload:{entry_id}"
            save_log_source(source)
            return source
        raise ValueError("Tiger Data is unavailable; the upload was not saved.")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    entry_id = uuid4().hex
    stored_name = f"{entry_id}.log"
    (UPLOAD_DIR / stored_name).write_text(text, encoding="utf-8")
    uploads = [{"id": entry_id, "name": name, "stored_name": stored_name}, *_uploads()]
    for old in uploads[MAX_RECENT_UPLOADS:]:
        (UPLOAD_DIR / old["stored_name"]).unlink(missing_ok=True)
    uploads = uploads[:MAX_RECENT_UPLOADS]
    UPLOAD_INDEX_PATH.write_text(json.dumps(uploads, indent=2) + "\n", encoding="utf-8")
    source = f"upload:{entry_id}"
    save_log_source(source)
    return source


def _uploads() -> list[dict[str, str]]:
    if os.environ.get("VERCEL"):
        from dawgwatch.storage import uploaded_logs
        return [{**item, "stored_name": ""} for item in uploaded_logs()]
    try:
        data = json.loads(UPLOAD_INDEX_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [item for item in data if isinstance(item, dict) and {"id", "name", "stored_name"} <= item.keys()]
