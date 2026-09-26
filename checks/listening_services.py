"""
Listening Services check.

Lists every program accepting TCP connections, beyond the fixed
RISKY_PORTS list the Port Assessor covers. A program listening on all
interfaces (*, 0.0.0.0, ::) can be reached from other devices on the
network, so it's flagged and offered a Close button. One bound to
127.0.0.1 is only reachable from this computer.

Where the list comes from:
    macOS   -- lsof            (without admin: only the current user's programs)
    Windows -- Get-NetTCPConnection + Get-Process (PowerShell)
    Linux   -- ss              (without root: program names may show as "?")
"""

import re

from checks.base import Check, register
from checks.port_control import DASHBOARD_PORT, closed_ports
from checks.port_scan import RISKY_PORTS
from checks.system import OS, powershell_json, run

EXPOSED_ADDRESSES = {"*", "0.0.0.0", "[::]", "::"}

SCOPE_NOTE = {
    "Darwin": "Shows programs run by your user; system services need admin rights to list.",
    "Windows": "Shows all listening programs; some system process names need admin rights.",
    "Linux": "Program names need root to read; ports and exposure are always shown.",
}


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


def _listeners():
    """Return {(command, port): exposed?} for TCP sockets in LISTEN state, or None."""
    lister = {"Darwin": _listeners_macos, "Windows": _listeners_windows, "Linux": _listeners_linux}.get(OS)
    found = lister() if lister else None
    if found is None:
        return None
    listeners = {}
    for command, address, port in found:
        key = (command, port)
        listeners[key] = listeners.get(key, False) or address.split("%")[0] in EXPOSED_ADDRESSES
    return listeners


@register
class ListeningServicesCheck(Check):
    NAME = "Listening Services"
    DESCRIPTION = "Programs accepting connections, and whether other devices can reach them"

    def run(self):
        listeners = _listeners()
        if listeners is None:
            return {"status": "error", "summary": f"Couldn't list listening programs on {OS}", "items": []}

        closed_here = closed_ports()
        items = []
        exposed_count = 0

        for (command, port), exposed in sorted(listeners.items(), key=lambda kv: kv[0][1]):
            if port in RISKY_PORTS:
                continue  # already reported by the Port Assessor
            label = f"Port {port} ({command})"
            if port in closed_here:
                items.append({
                    "label": label,
                    "status": "ok",
                    "detail": "Still running, but closed by this dashboard (firewall rule).",
                    "action": {"kind": "reopen", "port": port},
                })
            elif exposed:
                exposed_count += 1
                item = {
                    "label": label,
                    "status": "warning",
                    "detail": "Reachable from other devices on your network (listening on all interfaces).",
                }
                if port == DASHBOARD_PORT:
                    item["detail"] += " Shares the dashboard's port, so it can't be closed here."
                else:
                    item["action"] = {"kind": "close", "port": port}
                items.append(item)
            else:
                items.append({
                    "label": label,
                    "status": "ok",
                    "detail": "Only reachable from this computer.",
                })

        # Ports closed here whose program has since stopped still need a Reopen button.
        listening_ports = {port for _, port in listeners}
        for port in sorted(closed_here - listening_ports - set(RISKY_PORTS)):
            items.append({
                "label": f"Port {port}",
                "status": "ok",
                "detail": "Closed by this dashboard (firewall rule); nothing is listening now.",
                "action": {"kind": "reopen", "port": port},
            })

        items.append({
            "label": "Scope",
            "status": "ok",
            "detail": SCOPE_NOTE.get(OS, ""),
        })

        if exposed_count:
            status, summary = "warning", f"{exposed_count} service(s) exposed to the network"
        else:
            status, summary = "ok", "No services exposed to the network"
        return {"status": status, "summary": summary, "items": items}
