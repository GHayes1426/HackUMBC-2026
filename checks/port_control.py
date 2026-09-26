"""
Close (firewall-block) and reopen local TCP ports.

"Closing" a port adds a firewall rule that rejects incoming connections
to it. The program listening on the port keeps running, so reopening is
just removing the rule. Ports this dashboard has closed are saved in
.state/closed_ports.json, so they can be reopened later, even after a restart.

Backends:
    macOS -- rules in the pf anchor com.apple/hackumbc, applied through the
             standard macOS administrator password prompt
    Linux -- iptables rules tagged "hackumbc", applied with sudo -n
             (works when app.py runs as root or sudo is already authorized)

Not a Check: app.py calls close_port()/reopen_port() from its API routes,
and the port checks call closed_ports() to decide which button to show.
"""

import json
import platform
import re
import shlex
import subprocess
from pathlib import Path

DASHBOARD_PORT = 5000  # never closable: it would cut off the dashboard itself

STATE_DIR = Path(__file__).resolve().parent.parent / ".state"
STATE_FILE = STATE_DIR / "closed_ports.json"
PF_ANCHOR = "com.apple/hackumbc"  # evaluated by the default `anchor "com.apple/*"` in /etc/pf.conf
IPTABLES_TAG = "hackumbc"


class PortControlError(Exception):
    """A close/reopen failed; the message is shown to the user."""


def closed_ports():
    """Return the set of ports this dashboard has closed."""
    try:
        return set(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        return set()


def close_port(port):
    _validate(port)
    ports = closed_ports()
    if port in ports:
        return
    _apply(ports | {port}, port, closing=True)
    _save(ports | {port})


def reopen_port(port):
    _validate(port)
    ports = closed_ports()
    if port not in ports:
        raise PortControlError(f"Port {port} wasn't closed by this dashboard")
    _apply(ports - {port}, port, closing=False)
    _save(ports - {port})


def _validate(port):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise PortControlError("Invalid port number")
    if port == DASHBOARD_PORT:
        raise PortControlError(f"Port {DASHBOARD_PORT} is the dashboard's own port and can't be closed here")


def _save(ports):
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(sorted(ports)))


def _apply(all_closed, port, closing):
    system = platform.system()
    if system == "Darwin":
        _apply_pf(all_closed)
    elif system == "Linux":
        _apply_iptables(port, closing)
    else:
        raise PortControlError(f"Closing ports isn't supported on {system} yet")


def _apply_pf(all_closed):
    """Rewrite the whole anchor from the saved set, so close and reopen share one path."""
    # Rules go in on stdin, not from a file: macOS privacy protection blocks
    # even root from reading files in ~/Desktop, where this project may live.
    # Ports are ints, so the printf string can't contain shell metacharacters.
    rules = "".join(
        f"block return in quick proto tcp from any to any port {p}\\n" for p in sorted(all_closed)
    )
    # Load the anchor, then make sure pf is on ("already enabled" exits 1, which is fine).
    shell = (
        f"printf '{rules}' | /sbin/pfctl -a {PF_ANCHOR} -f - && "
        "(/sbin/pfctl -e 2>/dev/null; true)"
    )
    shell = shell.replace("\\", "\\\\").replace('"', '\\"')  # AppleScript string escaping
    result = subprocess.run(
        ["osascript", "-e", f'do shell script "{shell}" with administrator privileges'],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        if "-128" in result.stderr:
            raise PortControlError("Cancelled at the administrator password prompt")
        raise PortControlError(f"Firewall update failed: {_pf_error(result.stderr)}")


def _pf_error(stderr):
    """Pick the real error out of pfctl's output, skipping its routine warnings."""
    noise = ("ALTQ", "flushing of rules", "main ruleset", "/etc/pf.conf")
    for message in re.findall(r"pfctl: ([^\r\n]+)", stderr):
        if not any(n in message for n in noise):
            return message.strip()
    return stderr.strip()[-300:] or "unknown error"


def _apply_iptables(port, closing):
    rule = [
        "INPUT", "-p", "tcp", "--dport", str(port),
        "-m", "comment", "--comment", IPTABLES_TAG,
        "-j", "REJECT", "--reject-with", "tcp-reset",
    ]
    cmd = ["iptables", "-I" if closing else "-D", *rule]
    result = subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True)
    if result.returncode != 0:
        raise PortControlError(
            f"Needs root. Run the dashboard with sudo, or run: sudo {' '.join(cmd)}"
        )
