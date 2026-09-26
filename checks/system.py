"""
Helpers for running OS commands from checks. Not a Check.

OS = "Darwin" (macOS), "Windows" or "Linux", so checks can pick the
right commands with a dict lookup.
"""

import json
import platform
import subprocess

OS = platform.system()


def run(command, timeout=15):
    """Run a command; return (exit code, stdout + stderr), or (None, "") if it couldn't start."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return result.returncode, result.stdout + result.stderr


def powershell_json(script, timeout=20):
    """
    Run a PowerShell snippet whose output is piped to ConvertTo-Json and
    return the parsed value (always a list), or None on failure. The cmdlets
    used by the checks return locale-independent objects, unlike netsh text.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"ConvertTo-Json -Compress -Depth 3 -InputObject @({script})"],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(result.stdout or "null")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if data is None:
        return []
    return data if isinstance(data, list) else [data]
