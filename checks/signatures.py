"""
Detection data for the IOC / CVE Analyzer: thresholds, log patterns,
and the port -> CVE table. Data only, no logic, so tuning a rule or
adding a CVE means editing this file and nothing else.

Used by:
    log_parser.py  -> FAILED_SSH_PATTERN
    detector.py    -> BRUTE_FORCE_THRESHOLD, CVE_PORT_MAP
    ioc_analyzer.py -> CVE_PORT_MAP.keys() (which ports to scan)
"""

import re

# Rule 1: an IP with this many failed SSH logins (or more) is flagged.
BRUTE_FORCE_THRESHOLD = 4

# Matches the standard Linux sshd line, including the "invalid user" variant:
#   ... sshd[123]: Failed password for root from 203.0.113.45 port 52144 ssh2
#   ... sshd[123]: Failed password for invalid user admin from 198.51.100.23 port 40022 ssh2
FAILED_SSH_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Rule 2: port -> (CVE ID, one-line explanation).
# Static, hand-picked list; an open port does NOT prove the vulnerable
# version is running (known false-positive risk, see README).
CVE_PORT_MAP = {
    21:   ("CVE-2011-2523", "vsftpd 2.3.4 backdoor gives a remote root shell"),
    23:   ("CVE-2020-10188", "Buffer overflow in netkit telnetd allows remote code execution"),
    445:  ("CVE-2017-0144", "EternalBlue: SMBv1 remote code execution used by WannaCry"),
    3306: ("CVE-2012-2122", "MySQL/MariaDB authentication bypass via repeated login attempts"),
    3389: ("CVE-2019-0708", "BlueKeep: pre-auth RDP remote code execution, wormable"),
    5900: ("CVE-2006-2369", "RealVNC 4.1.1 authentication bypass"),
}
