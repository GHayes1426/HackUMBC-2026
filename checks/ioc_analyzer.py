"""
IOC / CVE Analyzer check.

The dashboard panel that ties the pipeline together:

    log_parser.load_log_lines() -> parse_failed_logins() -> detector.detect_brute_force()
    port_scan.get_open_ports()  ---------------------->  detector.detect_cve_ports()

It turns both sets of findings into the standard result dict from
checks/base.py. The actual rules live in detector.py and their data
in signatures.py.
"""

from checks.base import Check, register
from checks.detector import count_failures_by_ip, detect_brute_force, detect_cve_ports
from checks.log_parser import load_log_lines, parse_failed_logins
from checks.port_control import closed_ports
from checks.port_scan import get_open_ports
from checks.signatures import BRUTE_FORCE_THRESHOLD, CVE_PORT_MAP


@register
class IOCAnalyzerCheck(Check):
    NAME = "IOC / CVE Analyzer"
    DESCRIPTION = "Flags brute-force SSH sources and open ports tied to known CVEs"

    def run(self):
        items = []

        # Rule 1: brute-force SSH
        lines, source, is_sample = load_log_lines()
        events = parse_failed_logins(lines)
        brute_force = detect_brute_force(events)
        for finding in brute_force:
            items.append({
                "label": f"Brute-force source {finding['ip']}",
                "status": "warning",
                "detail": (
                    f"{finding['count']} failed SSH logins, trying username(s): {', '.join(finding['users'])}. "
                    f"{BRUTE_FORCE_THRESHOLD}+ failures from one address is a sign of password guessing. "
                    "If this is a real log: block this IP in your firewall, and switch SSH to key-only logins."
                ),
            })
        flagged_ips = {finding["ip"] for finding in brute_force}
        for ip, count in count_failures_by_ip(events).most_common():
            if ip not in flagged_ips:
                items.append({
                    "label": f"Failed logins from {ip}",
                    "status": "ok",
                    "detail": (f"{count} failed SSH login(s), below the {BRUTE_FORCE_THRESHOLD}-failure threshold. "
                               "Usually a mistyped password, not an attack."),
                })
        if not events:
            items.append({"label": "SSH login failures", "status": "ok",
                          "detail": "No failed SSH logins in the log."})

        # Rule 2: CVE-mapped open ports
        # Ports this dashboard closed are firewalled even if a local scan still connects (Windows).
        cve_hits = detect_cve_ports(get_open_ports(CVE_PORT_MAP.keys()) - closed_ports())
        for finding in cve_hits:
            items.append({
                "label": f"Port {finding['port']}: {finding['cve']}",
                "status": "warning",
                "detail": (f"{finding['description']}. This port is open, and it's the port that "
                           f"vulnerability attacks. An open port doesn't prove the vulnerable version is "
                           f"installed, so check the program's version and update it."),
            })
        if not cve_hits:
            watched = ", ".join(str(port) for port in sorted(CVE_PORT_MAP))
            items.append({
                "label": "Known-vulnerability ports",
                "status": "ok",
                "detail": f"None of the ports tied to well-known attacks ({watched}) are open.",
            })

        issue_count = len(brute_force) + len(cve_hits)
        if issue_count == 0:
            status, summary = "ok", "No indicators of compromise found"
        else:
            status, summary = "warning", f"{issue_count} indicator(s) found"
        if is_sample:
            summary += " (sample log)"

        # Optional "chart" key: drawn in the dashboard's Threat Summary section.
        chart = {
            "title": "Failed SSH logins by source IP",
            "note": f"Flagged at {BRUTE_FORCE_THRESHOLD}+ failures" + (" · sample log" if is_sample else ""),
            "bars": [
                {"label": ip, "value": count, "flagged": count >= BRUTE_FORCE_THRESHOLD}
                for ip, count in count_failures_by_ip(events).most_common(8)
            ],
        }

        # Always say where the log data came from, so sample data is never
        # mistaken for a real attack on this machine.
        note = (f"Log source: SAMPLE DATA ({source}). No readable system SSH log was found, so a bundled "
                "example log is used." if is_sample else f"Log source: {source}")

        return {"status": status, "summary": summary, "items": items, "chart": chart, "note": note}
