# Network Security Dashboard

A local port assessor with a plugin-style dashboard: each security
check is a self-contained module, so the app grows by adding files,
not by rewriting existing code.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000/ — it scans on every page load.

## What's in it right now

- **Local Port Assessor** (`checks/port_scan.py`): scans localhost
  for 10 commonly risky ports (FTP, Telnet, SMB, RDP, etc.), shows
  open/closed status with red/green indicators, and gives a
  one-line recommendation for anything open.

- **IOC / CVE Analyzer** (`checks/ioc_analyzer.py`): two detection
  rules, described in detail below.

- **Listening Services** (`checks/listening_services.py`): lists every
  program accepting TCP connections (via `lsof`) and flags any that
  listen on all interfaces, i.e. are reachable from other devices on
  the network. Without admin rights it only sees the current user's
  programs.

- **System Hardening** (`checks/hardening.py`): reads the macOS
  firewall, stealth mode, FileVault, Gatekeeper and SIP status (ufw on
  Linux) and says how to turn on anything that's off.

- **Threat summary** (`checks/summary.py`): the top of the page shows
  the total number of potential threats, a tile per check, a
  threats-by-category bar chart, and any chart a check provides (the
  IOC analyzer adds failed SSH logins per source IP).

- **Close / Reopen port buttons** (`checks/port_control.py`): open
  risky or network-exposed ports get a *Close port* button. It adds a
  firewall rule blocking the port (macOS pf, with the normal admin
  password prompt; iptables on Linux). The program keeps running, so
  *Reopen port* just removes the rule. Closed ports are remembered in
  `.state/closed_ports.json`. Port 5000 (the dashboard) can't be closed.

### IOC / CVE Analyzer — detection logic

**Rule 1: Brute-force SSH detection.** Parses SSH auth-log lines
(`checks/log_parser.py`) matching the standard Linux
`Failed password for <user> from <ip>` format, counts failed
attempts per source IP, and flags any IP with 4 or more failed
logins. This is a well-known indicator of a credential-stuffing or
brute-force attack in progress.
*Limitation:* the count is taken across the whole log rather than
a rolling time window, and only this one log line format is
recognized (no Windows Event Log, no non-standard SSH configs). An
attacker who stays just under the threshold, or whose attempts are
spread across a much longer log than the threshold accounts for,
won't be flagged.

**Rule 2: CVE-mapped open ports.** Cross-references open ports
(reusing the same scanner as the Port Assessor) against a
hand-maintained table of 6 ports tied to specific, well-documented
CVEs — e.g. port 445 → CVE-2017-0144 (EternalBlue, used by
WannaCry), port 3389 → CVE-2019-0708 (BlueKeep). If one of these
ports is open, it's flagged with the CVE ID and a one-line
explanation.
*Limitation:* this is a static, hand-picked list, not a live feed
from the National Vulnerability Database — it won't catch a CVE
published after this table was written, and an open port doesn't
guarantee the vulnerable software version is actually running.
That's flagged as a known false-positive risk, not a certainty.

**No real attack log?** The analyzer falls back to a bundled
sample log (`sample_data/sample_auth.log`) with fabricated
brute-force entries, so the panel always has something meaningful
to show. It labels itself clearly when it's using sample data
instead of a real system log.

## Adding a new feature

The dashboard loops over every *registered* check automatically —
`app.py` and `templates/index.html` never need to change. To add
something new:

1. Create `checks/your_check.py`
2. Subclass `Check` from `checks.base`:

    ```python
    from checks.base import Check, register

    @register
    class YourCheck(Check):
        NAME = "Your Check Name"
        DESCRIPTION = "One-line description shown on the dashboard"

        def run(self):
            return {
                "status": "ok",       # or "warning" / "error"
                "summary": "Short headline",
                "items": [
                    {"label": "...", "status": "ok", "detail": "..."},
                    # optional: add a Close/Reopen button to an item
                    # "action": {"kind": "close", "port": 1234},
                ],
                # optional: a bar chart in the Threat summary
                # "chart": {"title": "...", "note": "...",
                #           "bars": [{"label": "...", "value": 3, "flagged": True}]},
            }
    ```

3. Add one line to `checks/__init__.py`:
   `from checks import your_check  # noqa: F401`
4. Refresh the page — your panel appears.

## Ideas for add-ons (from the original brainstorm)

- `remediation_links.py` — clickable links next to open ports
  explaining how to close them
- PDF export button — generate a report of the current scan
  (natural fit for the pdf skill if you want help with this later)
- Expand `CVE_PORT_MAP` with more entries, or swap it for a live
  NVD API lookup if you have time left over

Each is a single new file plus one import line — nothing else
in the project needs to change.

## Notes

- Scans `127.0.0.1` only — it's assessing the local machine, not
  the network, which keeps it zero-risk to run during judging.
- Written for the "assess/harden a system" track of the
  competition rubric; documentation above covers what the tool
  does and how it's structured, per the Execution criteria.
