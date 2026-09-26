"""
Local Port Assessor check.

Scans localhost for a set of commonly risky ports and flags any
that are open, with a plain-text recommendation for each.
"""

import socket

from checks.base import Check, register
from checks.port_control import closed_ports

# port -> (service name, why it's risky, recommendation)
RISKY_PORTS = {
    21:   ("FTP",         "Transmits credentials in plaintext",           "Disable FTP or switch to SFTP/FTPS"),
    23:   ("Telnet",      "Transmits everything in plaintext",            "Disable Telnet; use SSH instead"),
    25:   ("SMTP",        "Can be abused as an open mail relay",          "Restrict to trusted hosts or disable"),
    135:  ("MSRPC",       "Common target for Windows exploits",           "Firewall off from untrusted networks"),
    139:  ("NetBIOS",     "Legacy file-sharing, frequent attack target",  "Disable if SMB isn't needed"),
    445:  ("SMB",         "Target of major worms (WannaCry, etc.)",       "Patch fully or disable if unused"),
    1433: ("MSSQL",       "Database exposed to network scanning",        "Restrict to app servers only"),
    3306: ("MySQL",       "Database exposed to network scanning",        "Bind to localhost or restrict access"),
    3389: ("RDP",         "Frequent target of brute-force attacks",      "Use VPN + MFA, don't expose directly"),
    5900: ("VNC",         "Often runs with weak/no authentication",      "Add auth or tunnel through SSH"),
}


def _scan_port(host, port, timeout=0.3):
    """Return True if the port is open on host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def get_open_ports(ports, host="127.0.0.1"):
    """
    Scan the given iterable of ports on host, return the set of
    ports found open. Exposed so other checks (e.g. the IOC/CVE
    analyzer) can reuse this instead of re-implementing scanning.
    """
    return {port for port in ports if _scan_port(host, port)}


@register
class PortScanCheck(Check):
    NAME = "Local Port Assessor"
    DESCRIPTION = "Scans localhost for commonly risky open ports"

    def run(self):
        host = "127.0.0.1"
        items = []
        open_count = 0
        closed_here = closed_ports()

        for port, (service, risk, recommendation) in RISKY_PORTS.items():
            is_open = _scan_port(host, port)
            if is_open:
                open_count += 1
                items.append({
                    "label": f"Port {port} ({service})",
                    "status": "warning",
                    "detail": f"OPEN — {risk}. {recommendation}.",
                    "action": {"kind": "close", "port": port},
                })
            elif port in closed_here:
                items.append({
                    "label": f"Port {port} ({service})",
                    "status": "ok",
                    "detail": "Closed by this dashboard (firewall rule). Reopen it if a program needs it.",
                    "action": {"kind": "reopen", "port": port},
                })
            else:
                items.append({
                    "label": f"Port {port} ({service})",
                    "status": "ok",
                    "detail": "Closed",
                })

        if open_count == 0:
            status = "ok"
            summary = "No risky ports open"
        else:
            status = "warning"
            summary = f"{open_count} risky port(s) open"

        return {"status": status, "summary": summary, "items": items}
