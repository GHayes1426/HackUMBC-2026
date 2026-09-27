"""Verify Tiger Data connectivity without printing credentials."""

from __future__ import annotations

from pathlib import Path
import re

import psycopg
from dotenv import dotenv_values


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    database_url = dotenv_values(project_root / ".env").get("TIGER_DATABASE_URL")
    if not database_url:
        print("connection=failed")
        print("reason=missing_TIGER_DATABASE_URL")
        return 1

    try:
        with psycopg.connect(database_url, connect_timeout=10) as connection:
            row = connection.execute(
                """
                SELECT
                    current_database(),
                    current_user,
                    COALESCE(
                        (SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'),
                        'not-installed'
                    )
                """
            ).fetchone()
    except Exception as error:
        print("connection=failed")
        print(f"error_type={type(error).__name__}")
        if isinstance(error, psycopg.ProgrammingError):
            separator_index = database_url.find("://")
            scheme = database_url[:separator_index] if separator_index >= 0 else ""
            safe_scheme = (
                scheme.lower()
                if len(scheme) <= 20 and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]*", scheme)
                else "missing-or-invalid"
            )
            print(
                "valid_scheme="
                + str(database_url.startswith(("postgresql://", "postgres://"))).lower()
            )
            print(f"detected_scheme={safe_scheme}")
            print("contains_scheme_separator=" + str(separator_index >= 0).lower())
            print(
                "starts_with_variable_name="
                + str(database_url.startswith("TIGER_DATABASE_URL=")).lower()
            )
            print("contains_backslash=" + str("\\" in database_url).lower())
            print(
                "contains_whitespace="
                + str(any(character.isspace() for character in database_url)).lower()
            )
        return 1

    assert row is not None
    print("connection=ok")
    print(f"database={row[0]}")
    print(f"user={row[1]}")
    print(f"timescaledb={row[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
