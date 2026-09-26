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
