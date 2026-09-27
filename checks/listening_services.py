"""
Listening Services check.

Lists every program accepting TCP connections, beyond the fixed
RISKY_PORTS list the Port Assessor covers, and explains each one using
checks/port_catalog.py. Statuses:

    info    (blue, IN USE)  -- a recognized app or OS feature uses this port
    review  (amber, REVIEW) -- unrecognized program reachable from other devices
    ok      (green, SAFE)   -- unrecognized program only reachable from this computer,
                               or a port this dashboard has closed

A program listening on all interfaces (*, 0.0.0.0, ::) can be reached from
other devices on the network; one bound to 127.0.0.1 cannot. Exposed ports
get a Close button, recognized or not.
"""

from checks.base import Check, register
from checks.listeners import get_listeners
from checks.port_catalog import describe
from checks.port_control import DASHBOARD_PORT, closed_ports
from checks.port_scan import RISKY_PORTS
from checks.system import OS

SCOPE_NOTE = {
    "Darwin": "Names programs run by your user; macOS hides system services' names without admin rights, "
              "so those are identified by the Sharing setting that opens their port.",
    "Windows": "Shows all listening programs; some system process names need admin rights.",
    "Linux": "Program names need root to read; ports and exposure are always shown.",
}

EXPOSED_TEXT = "Reachable from other devices on your network."
LOCAL_TEXT = "Only reachable from this computer."


def _sentence(*parts):
    return " ".join(part for part in parts if part)


@register
class ListeningServicesCheck(Check):
    NAME = "Listening Services"
    DESCRIPTION = "Every program accepting connections: what it is, and whether other devices can reach it"

    def run(self):
        listeners = get_listeners()
        if listeners is None:
            return {"status": "error", "summary": f"Couldn't list listening programs on {OS}", "items": []}

        closed_here = closed_ports()
        items = []
        counts = {"info": 0, "review": 0}

        for (command, port), exposed in sorted(listeners.items(), key=lambda kv: kv[0][1]):
            if port in RISKY_PORTS:
                continue  # already reported by the Port Assessor
            info = describe(command, port)
            label = f"Port {port} · {info['name']}"
            if command != "?" and command.lower() not in info["name"].lower():
                label += f" ({command})"

            if port in closed_here:
                items.append({
                    "label": label,
                    "status": "ok",
                    "detail": _sentence(info["what"], "Closed by this dashboard (firewall rule); the program is still running."),
                    "action": {"kind": "reopen", "port": port},
                })
                continue

            reach = EXPOSED_TEXT if exposed else LOCAL_TEXT
            unrecognized = "" if command == "?" else f"Unrecognized program “{command}”."
            if info["known"]:
                counts["info"] += 1
                item = {"label": label, "status": "info",
                        "detail": _sentence(info["what"], reach, info["advice"])}
            elif exposed:
                counts["review"] += 1
                item = {"label": label, "status": "review",
                        "detail": _sentence(
                            unrecognized, info["what"], reach,
                            "If you don't know what it is, look up the program name or close the port.")}
            else:
                item = {"label": label, "status": "ok",
                        "detail": _sentence(unrecognized, info["what"], reach,
                                            "Low risk, since other devices can't connect.")}

            if exposed:
                if port == DASHBOARD_PORT:
                    item["detail"] += " Shares the dashboard's port, so it can't be closed here."
                else:
                    item["action"] = {"kind": "close", "port": port}
            items.append(item)

        # Ports closed here whose program has since stopped still need a Reopen button.
        listening_ports = {port for _, port in listeners}
        for port in sorted(closed_here - listening_ports - set(RISKY_PORTS)):
            items.append({
                "label": f"Port {port}",
                "status": "ok",
                "detail": "Closed by this dashboard (firewall rule); nothing is listening now.",
                "action": {"kind": "reopen", "port": port},
            })

        parts = []
        if counts["review"]:
            parts.append(f"{counts['review']} unrecognized service(s) exposed")
        if counts["info"]:
            parts.append(f"{counts['info']} in use by recognized apps")
        summary = ", ".join(parts) or "Nothing exposed to the network"
        status = "review" if counts["review"] else "info" if counts["info"] else "ok"
        return {"status": status, "summary": summary, "items": items, "note": SCOPE_NOTE.get(OS, "")}
