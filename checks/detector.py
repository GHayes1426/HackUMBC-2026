"""
Detection rules for the IOC / CVE Analyzer.

Pure functions: structured data in, findings out. No file access, no
network, no socket scanning, so each rule can be tested with a
hand-written list or set.

    parse_failed_logins() --events-->  detect_brute_force()  --> findings
    get_open_ports()      --ports--->  detect_cve_ports()    --> findings
"""

from collections import Counter

from checks.signatures import BRUTE_FORCE_THRESHOLD, CVE_PORT_MAP


def count_failures_by_ip(events):
    """Return a Counter of failed logins per source IP (every IP, flagged or not)."""
    return Counter(event["ip"] for event in events)


def detect_brute_force(events, threshold=BRUTE_FORCE_THRESHOLD):
    """
    Rule 1: brute-force SSH detection.

    events -- output of log_parser.parse_failed_logins()
    Returns one finding per IP with >= threshold failures, most
    attempts first:
        [{"ip": "203.0.113.45", "count": 6, "users": ["admin", "root"]}, ...]
    """
    users_by_ip = {}
    for event in events:
        users_by_ip.setdefault(event["ip"], set()).add(event["user"])

    return [
        {"ip": ip, "count": count, "users": sorted(users_by_ip[ip])}
        for ip, count in count_failures_by_ip(events).most_common()
        if count >= threshold
    ]


def detect_cve_ports(open_ports):
    """
    Rule 2: CVE-mapped open ports.

    open_ports -- set of ints from port_scan.get_open_ports()
    Returns one finding per open port that appears in CVE_PORT_MAP:
        [{"port": 445, "cve": "CVE-2017-0144", "description": "EternalBlue: ..."}, ...]
    """
    findings = []
    for port in sorted(open_ports):
        if port in CVE_PORT_MAP:
            cve, description = CVE_PORT_MAP[port]
            findings.append({"port": port, "cve": cve, "description": description})
    return findings
