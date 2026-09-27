"""
IOC / CVE Analyzer check.

The dashboard panel that ties the pipeline together:

    log_parser.load_log_lines() -> parse_failed_logins() -> DetectionEngine (brute force, spraying)
    port_scan.get_open_ports()  ---------------------->  detector.detect_cve_ports()

The log is always a static example file (or one the user uploaded), never
this device's real logs, and the result says so in its "example" key so the
page can label it clearly. The port -> CVE rule only runs on a real device:
on the hosted site "this computer" is a cloud server, so the rule is skipped
and the page's port guide explains the CVEs instead.

The actual rules live in detector.py / dawgwatch and their data in signatures.py.
"""

from checks.base import Check, register
from checks.detector import count_failures_by_ip, detect_cve_ports
from checks.log_parser import load_log_lines, parse_failed_logins
from checks.port_control import closed_ports
from checks.port_scan import get_open_ports
from checks.runtime_settings import load_detection_settings
from checks.signatures import CVE_PORT_MAP
from checks.system import HOSTED
from dawgwatch.detectors import DetectionEngine
from dawgwatch.models import EventKind, SecurityEvent

# What each alert means and what to do, in plain words.
ALERT_LESSONS = {
    "auth.brute_force": (
        "What it means: one computer guessed passwords for the same account over and over, as fast as it could, "
        "hoping to hit the right one. This is the most common attack on any open remote-login port (SSH, port 22). "
        "On a real system: block that address, turn off password logins in favor of SSH keys, and check that none "
        "of its attempts succeeded."
    ),
    "auth.password_spray": (
        "What it means: instead of many guesses on one account (which would trigger a lockout), the attacker tried "
        "one or two common passwords, like \"Summer2026!\", on many different accounts, hoping someone used a weak "
        "one. On a real system: require strong, unique passwords and multi-factor sign-in, and review the "
        "targeted accounts."
    ),
}


@register
class IOCAnalyzerCheck(Check):
    NAME = "IOC / CVE Analyzer"
    DESCRIPTION = ("Reads an example security log to show what password-guessing attacks look like, "
                   "and flags open ports tied to famous vulnerabilities (CVEs)")

    def run(self):
        items = []
        settings = load_detection_settings()

        # Rule 1: brute-force and password-spray logins in the example log
        lines, source, _ = load_log_lines()
        uploaded = source.startswith("UPLOADED LOG")
        log_name = source.split(": ", 1)[-1]
        events = parse_failed_logins(lines)
        security_events = [
            SecurityEvent(
                kind=EventKind.AUTH_FAILURE,
                occurred_at=event["occurred_at"],
                source=event["ip"],
                target="the example SSH server",
                account=event["user"],
                details={"raw": event["raw"]},
            )
            for event in events
        ]
        auth_alerts = DetectionEngine(settings).analyze(security_events)
        for alert in auth_alerts:
            items.append({
                "label": alert.title,
                "status": "warning",
                "detail": f"{'In your uploaded log' if uploaded else 'In the example log'}: {alert.summary} "
                          f"{ALERT_LESSONS.get(alert.rule_id, '')}".strip(),
            })
        if not events:
            items.append({"label": "SSH login failures", "status": "ok",
                          "detail": "No failed SSH logins in this log file."})
        elif not auth_alerts:
            items.append({"label": "SSH login failures", "status": "ok",
                          "detail": (f"{len(events)} failed login(s), but too few or too spread out to look like "
                                     "an attack. A few typos are normal.")})

        # Rule 2: CVE-mapped open ports, only on a real device.
        cve_hits = []
        if not HOSTED:
            # Ports this dashboard closed are firewalled even if a local scan still connects (Windows).
            cve_hits = detect_cve_ports(get_open_ports(CVE_PORT_MAP.keys()) - closed_ports())
            for finding in cve_hits:
                items.append({
                    "label": f"Port {finding['port']}: {finding['cve']}",
                    "status": "warning",
                    "detail": (f"{finding['description']}. This port is open on this computer, and it's the port "
                               f"that vulnerability attacks. An open port doesn't prove the vulnerable version is "
                               f"installed, so check the program's version and update it, or close the port."),
                })
            if not cve_hits:
                watched = ", ".join(str(port) for port in sorted(CVE_PORT_MAP))
                items.append({
                    "label": "Known-vulnerability ports",
                    "status": "ok",
                    "detail": f"None of the ports tied to famous attacks ({watched}) are open on this computer.",
                })

        issue_count = len(auth_alerts) + len(cve_hits)
        if issue_count == 0:
            status, summary = "ok", "No signs of attack found"
        else:
            status, summary = "warning", f"{issue_count} sign(s) of attack found"
        summary += " in your uploaded log" if uploaded else " in the example log"
        if cve_hits:
            summary += " and this computer's ports"

        # Optional "chart" key: drawn in the dashboard's Threat Summary section.
        chart = {
            "title": "Failed SSH logins by source IP",
            "note": (
                f"Brute force: {settings.brute_force_failures}+ failures in "
                f"{settings.brute_force_window_seconds}s · " + ("uploaded log" if uploaded else "example log")
            ),
            "bars": [
                {"label": ip, "value": count, "flagged": count >= settings.brute_force_failures}
                for ip, count in count_failures_by_ip(events).most_common(8)
            ],
        }

        # Shown as a banner on the panel so the log is never mistaken for a
        # real attack on the visitor's device.
        example = {
            "file": log_name,
            "uploaded": uploaded,
            "text": (
                "You uploaded this file. Port a Potty only reads it as text; nothing on your device was scanned for it."
                if uploaded else
                "This is a static example file bundled with Port a Potty. The attackers, addresses and accounts in it "
                "are made up so you can safely see what real attacks look like. It is not your device's log."
            ),
        }
        note = ("On this website the port-to-CVE check is skipped, because the site runs on a cloud server, not your "
                "device. See \"Common ports explained\" below for the famous vulnerabilities behind each port."
                if HOSTED else "")

        return {"status": status, "summary": summary, "items": items, "chart": chart,
                "note": note, "example": example}
