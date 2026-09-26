"""
Log input for the IOC / CVE Analyzer.

Two jobs:
  1. load_log_lines(): find a log to read (real system log if one is
     readable, otherwise the bundled sample) and say which one it used.
  2. parse_failed_logins(): turn raw lines into structured events.

This module only reads and parses; deciding what counts as an attack
is detector.py's job.
"""

from pathlib import Path

from checks.signatures import FAILED_SSH_PATTERN

# Debian/Ubuntu and RHEL/Fedora locations. macOS has neither, so a Mac
# will always fall back to the sample log.
REAL_LOG_PATHS = [Path("/var/log/auth.log"), Path("/var/log/secure")]

SAMPLE_LOG_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "sample_auth.log"


def load_log_lines():
    """
    Return (lines, source, is_sample):
        lines     -- list of str, one per log line
        source    -- path of the file that was read, for display
        is_sample -- True if we fell back to SAMPLE_LOG_PATH

    TODO:
      - Loop over REAL_LOG_PATHS; for the first one that exists and can
        be opened, return its lines with is_sample=False. Catch
        PermissionError / OSError (auth.log usually needs root) and
        move on to the next path.
      - Otherwise read SAMPLE_LOG_PATH and return is_sample=True.
    """
    return [], str(SAMPLE_LOG_PATH), True


def parse_failed_logins(lines):
    """
    Return a list of failed-login events, one per matching line:
        [{"user": "root", "ip": "203.0.113.45", "raw": "<original line>"}, ...]

    Non-matching lines are skipped.

    TODO:
      - For each line, m = FAILED_SSH_PATTERN.search(line)
      - If m: append {"user": m["user"], "ip": m["ip"], "raw": line.strip()}
    """
    return []
