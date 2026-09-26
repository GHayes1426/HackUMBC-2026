"""
Local Port Assessor check.

Scans localhost for a set of commonly risky ports and explains each:
what the port is for, which program has it open, why it's risky, and
what to do. Statuses:
    warning (red, RISK)     -- open, and no recognized program explains it
    review  (amber, REVIEW) -- open because a recognized app/OS feature uses it:
                               probably needed, but still a common attack target
    ok      (green, SAFE)   -- closed, or closed by this dashboard
"""

import socket
from concurrent.futures import ThreadPoolExecutor

from checks.base import Check, register
from checks.listeners import programs_on_port
from checks.port_catalog import describe, port_info
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
    ports = list(ports)
    # Scanned in parallel: on Windows a closed localhost port waits out the
    # full timeout instead of refusing instantly.
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda port: _scan_port(host, port), ports)
    return {port for port, is_open in zip(ports, results) if is_open}


@register
class PortScanCheck(Check):
    NAME = "Local Port Assessor"
    DESCRIPTION = "Scans localhost for commonly risky open ports"

    def run(self):
        host = "127.0.0.1"
        items = []
        open_count = 0
        closed_here = closed_ports()
        open_ports = get_open_ports(RISKY_PORTS, host)

        for port, (service, risk, recommendation) in RISKY_PORTS.items():
            label = f"Port {port} · {service}"
            what = port_info(port)[1] if port_info(port) else ""
            if port in closed_here:
                # Checked first: on Windows a blocked port still answers local scans.
                items.append({
                    "label": label,
                    "status": "ok",
                    "detail": f"{what} Closed by this dashboard (firewall rule). Reopen it if a program needs it.",
                    "action": {"kind": "reopen", "port": port},
                })
            elif port in open_ports:
                open_count += 1
                programs = programs_on_port(port)
                known = [describe(program, port) for program in programs]
                known = [info for info in known if info["known"]]
                if known:
                    used_by = f"In use by {known[0]['name']} ({', '.join(programs)}), so something on this computer probably needs it."
                    status = "review"
                elif programs:
                    used_by = f"Open, used by unrecognized program(s): {', '.join(programs)}."
                    status = "warning"
                else:
                    used_by = "Open, but the program using it isn't visible without admin rights."
                    status = "warning"
                items.append({
                    "label": label,
                    "status": status,
                    "detail": f"{what} {used_by} Why it's risky: {risk.lower()}. What to do: {recommendation}.",
                    "action": {"kind": "close", "port": port},
                })
            else:
                items.append({
                    "label": label,
                    "status": "ok",
                    "detail": f"Closed. {what}",
                })

        risks = sum(1 for item in items if item["status"] == "warning")
        if open_count == 0:
            status, summary = "ok", f"None of the {len(RISKY_PORTS)} commonly attacked ports are open"
        else:
            status = "warning" if risks else "review"
            summary = f"{open_count} risky port(s) open"
            if open_count - risks:
                summary += f", {open_count - risks} used by recognized apps"

        return {"status": status, "summary": summary, "items": items}
