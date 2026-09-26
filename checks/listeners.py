"""
Which programs are listening on which TCP ports. Not a Check.

Shared by the Port Assessor (to say which program has a risky port open)
and Listening Services (to list everything). Results are cached for a few
seconds so one page load only asks the OS once.

Where the list comes from:
    macOS   -- lsof            (without admin: only the current user's programs)
    Windows -- Get-NetTCPConnection + Get-Process (PowerShell)
    Linux   -- ss              (without root: program names show as "?")
"""

import re
import time

from checks.system import OS, powershell_json, run

EXPOSED_ADDRESSES = {"*", "0.0.0.0", "[::]", "::"}
CACHE_SECONDS = 5

_cache = {"time": 0.0, "value": None}


def _split_address(local):
    """'0.0.0.0:22' / '[::]:22' / '*:22' -> ('0.0.0.0', 22), or None."""
    address, _, port = local.rpartition(":")
    return (address, int(port)) if port.isdigit() else None


def _listeners_macos():
    code, out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "cn"])
    if code is None:
        return None
    found, command = [], "?"
    for line in out.splitlines():
        if line.startswith("c"):
            # lsof escapes spaces etc. as \x20
            command = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), line[1:])
        elif line.startswith("n") and (split := _split_address(line[1:])):
            found.append((command, *split))
    return found


def _listeners_windows():
    rows = powershell_json(
        "Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{"
        " a = $_.LocalAddress; p = $_.LocalPort;"
        " n = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }"
    )
    if rows is None:
        return None
    return [(row.get("n") or "?", row["a"], int(row["p"])) for row in rows]


def _listeners_linux():
    code, out = run(["ss", "-Hltnp"])
    if code is None:
        return None
    found = []
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 4 and (split := _split_address(cols[3])):
            name = re.search(r'users:\(\("([^"]+)"', line)
            found.append((name[1] if name else "?", *split))
    return found


def get_listeners():
    """Return {(command, port): exposed?} for TCP sockets in LISTEN state, or None if unavailable."""
    if time.monotonic() - _cache["time"] < CACHE_SECONDS:
        return _cache["value"]

    lister = {"Darwin": _listeners_macos, "Windows": _listeners_windows, "Linux": _listeners_linux}.get(OS)
    found = lister() if lister else None
    listeners = None
    if found is not None:
        listeners = {}
        for command, address, port in found:
            key = (command, port)
            listeners[key] = listeners.get(key, False) or address.split("%")[0] in EXPOSED_ADDRESSES

    _cache.update(time=time.monotonic(), value=listeners)
    return listeners


def programs_on_port(port):
    """Names of the programs listening on a port (empty if none or unknown)."""
    return sorted({command for command, p in (get_listeners() or {}) if p == port})
