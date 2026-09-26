"""
Log input for the IOC / CVE Analyzer.

Two jobs:
  1. load_log_lines(): load the selected bundled demo scenario and say which
     one it used.
  2. parse_failed_logins(): turn raw lines into structured events.

This module only reads and parses; deciding what counts as an attack
is detector.py's job.
"""

from datetime import datetime, timezone
import re

from checks.demo_logs import load_demo_log
from checks.signatures import FAILED_SSH_PATTERN

SYSLOG_TIMESTAMP = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def load_log_lines():
    """
    Return (lines, source, is_sample):
        lines     -- list of str, one per log line
        source    -- path of the file that was read, for display
        is_sample -- True if we fell back to SAMPLE_LOG_PATH

    This deliberately uses only static demo data. It never reads system or
    VM logs, so judging runs are repeatable and safe.
    """
    return load_demo_log()


def parse_failed_logins(lines):
    """
    Return a list of failed-login events, one per matching line:
        [{"user": "root", "ip": "203.0.113.45", "raw": "<original line>"}, ...]

    Non-matching lines are skipped.
    """
    events = []
    for line in lines:
        m = FAILED_SSH_PATTERN.search(line)
        if m:
            occurred_at = _parse_syslog_timestamp(line)
            if occurred_at is not None:
                events.append({
                    "user": m["user"],
                    "ip": m["ip"],
                    "occurred_at": occurred_at,
                    "raw": line.strip(),
                })
    return events


def _parse_syslog_timestamp(line):
    """Parse a normal syslog timestamp, using the current UTC year.

    Syslog lines omit the year. This is sufficient for a rolling detection
    window; events without a recognizable timestamp are ignored rather than
    assigned a misleading time.
    """
    match = SYSLOG_TIMESTAMP.match(line)
    if not match:
        return None
    try:
        parsed = datetime.strptime(match["timestamp"], "%b %d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
