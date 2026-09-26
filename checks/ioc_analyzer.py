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
                    f"{finding['count']} failed SSH logins "
                    f"(users tried: {', '.join(finding['users'])})"
                ),
            })

        # Rule 2: CVE-mapped open ports
        cve_hits = detect_cve_ports(get_open_ports(CVE_PORT_MAP.keys()))
        for finding in cve_hits:
            items.append({
                "label": f"Port {finding['port']}: {finding['cve']}",
                "status": "warning",
                "detail": f"{finding['description']} (open port only; version not verified)",
            })

        # Always say where the log data came from, so sample data is never
        # mistaken for a real attack on this machine.
        items.append({
            "label": "Log source",
            "status": "ok",
            "detail": f"SAMPLE DATA: {source}" if is_sample else source,
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

        return {"status": status, "summary": summary, "items": items, "chart": chart}
