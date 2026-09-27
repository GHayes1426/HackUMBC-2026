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
from checks.detector import count_failures_by_ip, detect_cve_ports
from checks.log_parser import load_log_lines, parse_failed_logins
from checks.port_control import closed_ports
from checks.port_scan import get_open_ports
from checks.runtime_settings import load_detection_settings
from checks.signatures import CVE_PORT_MAP
from dawgwatch.detectors import DetectionEngine
from dawgwatch.models import EventKind, SecurityEvent


@register
class IOCAnalyzerCheck(Check):
    NAME = "IOC / CVE Analyzer"
    DESCRIPTION = "Flags brute-force SSH sources and open ports tied to known CVEs"

    def run(self):
        items = []
        settings = load_detection_settings()

        # Rule 1: brute-force SSH
        lines, source, is_sample = load_log_lines()
        events = parse_failed_logins(lines)
        security_events = [
            SecurityEvent(
                kind=EventKind.AUTH_FAILURE,
                occurred_at=event["occurred_at"],
                source=event["ip"],
                target="local SSH service",
                account=event["user"],
                details={"raw": event["raw"]},
            )
            for event in events
        ]
        auth_alerts = DetectionEngine(settings).analyze(security_events)
        for alert in auth_alerts:
            source_ip = alert.evidence[0].source
            items.append({
                "label": alert.title,
                "status": "warning",
                "detail": (
                    f"Source {source_ip}. {alert.summary} "
                    "If this were a real log, block the source and use SSH keys."
                ),
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
        # Always say where the log data came from, so sample data is never
        # mistaken for a real attack on this machine.
        items.append({
            "label": "Log source",
            "status": "ok",
            "detail": f"DEMO DATA: {source}" if is_sample else source,
        })

        issue_count = len(auth_alerts) + len(cve_hits)
        if issue_count == 0:
            status, summary = "ok", "No indicators of compromise found"
        else:
            status, summary = "warning", f"{issue_count} indicator(s) found"
        if is_sample:
            summary += " (demo log)"

        # Optional "chart" key: drawn in the dashboard's Threat Summary section.
        chart = {
            "title": "Failed SSH logins by source IP",
            "note": (
                f"Brute force: {settings.brute_force_failures}+ failures in "
                f"{settings.brute_force_window_seconds}s" + (" · demo log" if is_sample else "")
            ),
            "bars": [
                {"label": ip, "value": count, "flagged": count >= settings.brute_force_failures}
                for ip, count in count_failures_by_ip(events).most_common(8)
            ],
        }

        # Always say where the log data came from, so sample data is never
        # mistaken for a real attack on this machine.
        note = (f"Log source: SAMPLE DATA ({source}). No readable system SSH log was found, so a bundled "
                "example log is used." if is_sample else f"Log source: {source}")

        return {"status": status, "summary": summary, "items": items, "chart": chart, "note": note}
