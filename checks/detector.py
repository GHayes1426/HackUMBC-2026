"""
Detection rules for the IOC / CVE Analyzer.

Pure functions: structured data in, findings out. No file access, no
network, no socket scanning, so each rule can be tested with a
hand-written list or set.

    parse_failed_logins() --events-->  detect_brute_force()  --> findings
    get_open_ports()      --ports--->  detect_cve_ports()    --> findings
"""

from checks.signatures import BRUTE_FORCE_THRESHOLD, CVE_PORT_MAP


def detect_brute_force(events, threshold=BRUTE_FORCE_THRESHOLD):
    """
    Rule 1: brute-force SSH detection.

    events -- output of log_parser.parse_failed_logins()
    Returns one finding per IP with >= threshold failures, most
    attempts first:
        [{"ip": "203.0.113.45", "count": 6, "users": ["admin", "root"]}, ...]

    TODO:
      - Count events per ip (collections.Counter works well).
      - Collect the set of usernames tried per ip.
      - Keep ips where count >= threshold, sort by count descending.
    """
    return []


def detect_cve_ports(open_ports):
    """
    Rule 2: CVE-mapped open ports.

    open_ports -- set of ints from port_scan.get_open_ports()
    Returns one finding per open port that appears in CVE_PORT_MAP:
        [{"port": 445, "cve": "CVE-2017-0144", "description": "EternalBlue: ..."}, ...]

    TODO:
      - For each port in sorted(open_ports) that is in CVE_PORT_MAP,
        unpack (cve, description) and append a finding.
    """
    return []
