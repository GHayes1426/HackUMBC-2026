"""Tiger Data persistence for Port a Potty scans.

Database failures must never prevent a local security scan from running, so
all callers receive a boolean success value rather than a database exception.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from dotenv import load_dotenv


PROJECT_ROOT = Path(getattr(sys, "executable", Path(__file__).resolve())).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS port_a_potty_settings (
    setting_key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS port_a_potty_uploaded_logs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS port_a_potty_alerts (
    observed_at TIMESTAMPTZ NOT NULL,
    host TEXT NOT NULL,
    check_name TEXT NOT NULL,
    label TEXT NOT NULL,
    detail TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'error')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('port_a_potty_alerts', 'observed_at', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS port_a_potty_alerts_host_time_idx
    ON port_a_potty_alerts (host, observed_at DESC);
"""


def _connection():
    url = os.environ.get("TIGER_DATABASE_URL")
    return psycopg.connect(url, connect_timeout=8) if url else None


def _ensure_schema(cursor) -> None:
    cursor.execute(_SCHEMA)


def get_setting(key: str) -> dict[str, Any] | None:
    connection = _connection()
    if connection is None:
        return None
    try:
        with connection:
            with connection.cursor() as cursor:
                _ensure_schema(cursor)
                cursor.execute("SELECT value FROM port_a_potty_settings WHERE setting_key = %s", (key,))
                row = cursor.fetchone()
                return row[0] if row else None
    except psycopg.Error:
        return None


def put_setting(key: str, value: dict[str, Any]) -> bool:
    connection = _connection()
    if connection is None:
        return False
    try:
        with connection:
            with connection.cursor() as cursor:
                _ensure_schema(cursor)
                cursor.execute("""INSERT INTO port_a_potty_settings (setting_key, value) VALUES (%s, %s)
                    ON CONFLICT (setting_key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""", (key, json.dumps(value)))
        return True
    except psycopg.Error:
        return False


def save_uploaded_log(name: str, content: str) -> str | None:
    from uuid import uuid4
    connection = _connection()
    if connection is None:
        return None
    log_id = uuid4().hex
    try:
        with connection:
            with connection.cursor() as cursor:
                _ensure_schema(cursor)
                cursor.execute("INSERT INTO port_a_potty_uploaded_logs (id, name, content) VALUES (%s, %s, %s)", (log_id, name, content))
                cursor.execute("""DELETE FROM port_a_potty_uploaded_logs WHERE id IN (
                    SELECT id FROM port_a_potty_uploaded_logs ORDER BY created_at DESC OFFSET 8)""")
        return log_id
    except psycopg.Error:
        return None


def uploaded_logs() -> list[dict[str, str]]:
    connection = _connection()
    if connection is None:
        return []
    try:
        with connection:
            with connection.cursor() as cursor:
                _ensure_schema(cursor)
                cursor.execute("SELECT id, name FROM port_a_potty_uploaded_logs ORDER BY created_at DESC LIMIT 8")
                return [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]
    except psycopg.Error:
        return []


def uploaded_log_content(log_id: str) -> str | None:
    connection = _connection()
    if connection is None:
        return None
    try:
        with connection:
            with connection.cursor() as cursor:
                _ensure_schema(cursor)
                cursor.execute("SELECT content FROM port_a_potty_uploaded_logs WHERE id = %s", (log_id,))
                row = cursor.fetchone()
                return row[0] if row else None
    except psycopg.Error:
        return None


def record_scan(results: list[dict[str, Any]], host: str = "local") -> bool:
    """Append warning/error findings from one scan to Tiger Data."""
    database_url = os.environ.get("TIGER_DATABASE_URL")
    if not database_url:
        return False

    findings = [
        (datetime.now(timezone.utc), host, check["name"], item["label"], item["detail"], item["status"])
        for check in results
        for item in check.get("items", [])
        if item.get("status") in {"warning", "error"}
    ]
    if not findings:
        return True

    try:
        with psycopg.connect(database_url, connect_timeout=8) as conn:
            with conn.cursor() as cursor:
                cursor.execute(_SCHEMA)
                cursor.executemany(
                    """
                    INSERT INTO port_a_potty_alerts
                        (observed_at, host, check_name, label, detail, severity)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    findings,
                )
    except psycopg.Error:
        return False
    return True


def recent_alerts(limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest stored alerts, or an empty list if Tiger is offline."""
    database_url = os.environ.get("TIGER_DATABASE_URL")
    if not database_url:
        return []
    try:
        with psycopg.connect(database_url, connect_timeout=8, autocommit=True) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT observed_at, host, check_name, label, detail, severity
                    FROM port_a_potty_alerts
                    ORDER BY observed_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return [
                    {
                        "observed_at": observed_at.isoformat(),
                        "host": host,
                        "check_name": check_name,
                        "label": label,
                        "detail": detail,
                        "severity": severity,
                    }
                    for observed_at, host, check_name, label, detail, severity in cursor.fetchall()
                ]
    except psycopg.Error:
        return []
