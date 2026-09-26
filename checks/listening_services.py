"""
Listening Services check.

Lists every program accepting TCP connections (via lsof), beyond the
fixed RISKY_PORTS list the Port Assessor covers. A program listening
on all interfaces (*, 0.0.0.0, [::]) can be reached from other devices
on the network, so it's flagged and offered a Close button. One bound
to 127.0.0.1 is only reachable from this computer.

Limitation: without root, lsof only shows the current user's programs.
"""

import re
import subprocess

from checks.base import Check, register
from checks.port_control import DASHBOARD_PORT, closed_ports
from checks.port_scan import RISKY_PORTS

EXPOSED_ADDRESSES = {"*", "0.0.0.0", "[::]"}


def _listeners():
    """Return {(command, port): exposed?} for TCP sockets in LISTEN state."""
    out = subprocess.run(
        ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "cn"],
        capture_output=True, text=True, timeout=10,
    ).stdout
    listeners = {}
    command = "?"
    for line in out.splitlines():
        if line.startswith("c"):
            # lsof escapes spaces etc. as \x20
            command = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), line[1:])
        elif line.startswith("n") and ":" in line:
            address, port = line[1:].rsplit(":", 1)
            if port.isdigit():
                key = (command, int(port))
                listeners[key] = listeners.get(key, False) or address in EXPOSED_ADDRESSES
    return listeners


@register
class ListeningServicesCheck(Check):
    NAME = "Listening Services"
    DESCRIPTION = "Programs accepting connections, and whether other devices can reach them"

    def run(self):
        try:
            listeners = _listeners()
        except (OSError, subprocess.SubprocessError):
            return {"status": "error", "summary": "lsof isn't available on this system", "items": []}

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
            "detail": "Shows programs run by your user; system services need admin rights to list.",
        })

        if exposed_count:
            status, summary = "warning", f"{exposed_count} service(s) exposed to the network"
        else:
            status, summary = "ok", "No services exposed to the network"
        return {"status": status, "summary": summary, "items": items}
