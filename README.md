# Port a Potty

A local port assessor with a plugin-style dashboard: each security
check is a self-contained module, so the app grows by adding files,
not by rewriting existing code.

## Run it

Works on **macOS**, **Windows** and **Linux** (Python 3.10+). Run these
from the project folder.

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python app.py
```

Windows (PowerShell):

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python app.py
```

If PowerShell refuses to run `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or skip the
venv and just run `pip install -r requirements.txt` then `python app.py`.

Then open http://127.0.0.1:5000/ — it scans on every page load. Stop it
with Ctrl+C.

### What each OS checks

| | macOS | Windows | Linux |
|---|---|---|---|
| Listening services | `lsof` | `Get-NetTCPConnection` | `ss` |
| Hardening | Firewall, stealth mode, FileVault, Gatekeeper, SIP | Defender Firewall, Defender antivirus, BitLocker, UAC | ufw, SSH root/password login, auto-updates |
| Close / Reopen port | pf (password prompt) | Defender Firewall rule (UAC prompt) | iptables (needs sudo) |

## Reading the dashboard

Every item has a colored tag, and a key at the top of the page explains them:

| Tag | Color | Meaning |
|---|---|---|
| **RISK** | red | Dangerous: an open risky port no known app explains, an attack sign, or a protection that's off. Fix first. |
| **REVIEW** | amber | Probably needed but worth a look: a risky port a recognized app uses, or an unrecognized program other devices can reach. |
| **IN USE** | blue | A recognized app or OS feature needs this port (AirPlay, VS Code, Windows services...). Normal. |
| **SAFE** | green | Closed, only reachable from this computer, or a protection that's on. |
| **UNKNOWN** | gray | Couldn't be checked, usually because it needs admin rights. |

Programs and ports are recognized using `checks/port_catalog.py`, which
also supplies the plain-English description of what each one does. To
teach the dashboard a new app, add one line to `PROGRAMS` there.
Checks report these as the item statuses `warning`, `review`, `info`,
`ok` and `error` (see `checks/base.py`).

The **Detection thresholds** panel saves its values to the ignored local
file `.state/detection_settings.json`; each machine can use its own alert
thresholds without changing the team repository.

### Static demo log source

The dashboard reads only bundled, simulated SSH logs. Choose a scenario in
the **Demo scenario** picker to demonstrate combined attacks, brute force,
password spraying, or clean activity. No VM or live system-log access is
required.

### Hosted dashboard with the local helper

The Vercel dashboard intentionally uses only the simulated-log analyzer. To
show the three checks that need access to the judge's computer, build the
downloadable helper. It runs **Local Port Assessor**, **Listening Services**,
and **System Hardening** on that computer, then uploads display-only results
to Tiger Data through the Vercel API. The website can view results but cannot
run commands, close ports, or change any local settings.

1. Add a long random `PORT_A_POTTY_AGENT_KEY` to the Vercel environment and
   put the exact same value in a `.env` file beside the helper.
2. Put the Vercel deployment address in `PORT_A_POTTY_API_URL` in that file.
3. Run `powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_helper.ps1`.
4. Put the resulting `dist\Port-a-Potty-Helper.exe` and its `.env` together,
   then run the EXE. It prints a pairing ID.
5. Open the **Local device helper** panel in the hosted dashboard, paste that
   pairing ID once, and select **Connect helper**.

The helper uploads once a minute by default. It can be tested from the repo
with `python port_a_potty_helper.py --once`.

If Vercel Deployment Protection is enabled, an EXE cannot use the browser's
Vercel sign-in cookie. Either allow public access for the deployment or create
a Vercel Protection Bypass secret and place it in the helper-side `.env` as
`PORT_A_POTTY_VERCEL_BYPASS_SECRET`. Keep that secret out of Git and out of
the hosted app's environment variables.

## What's in it right now

- **Local Port Assessor** (`checks/port_scan.py`): scans localhost
  for 10 commonly risky ports (FTP, Telnet, SMB, RDP, etc.), shows
  open/closed status with red/green indicators, and gives a
  one-line recommendation for anything open.

- **IOC / CVE Analyzer** (`checks/ioc_analyzer.py`): two detection
  rules, described in detail below.

- **Listening Services** (`checks/listening_services.py`): lists every
  program accepting TCP connections and flags any that listen on all
  interfaces, i.e. are reachable from other devices on the network.
  On macOS, without admin rights it only sees the current user's
  programs.

- **System Hardening** (`checks/hardening.py`): reads the OS's
  built-in protections (see the table above) and says how to turn on
  anything that's off.

- **Threat summary** (`checks/summary.py`): the top of the page shows
  the total number of potential threats, a tile per check, a
  threats-by-category bar chart, and any chart a check provides (the
  IOC analyzer adds failed SSH logins per source IP).

- **Close / Reopen port buttons** (`checks/port_control.py`): open
  risky or network-exposed ports get a *Close port* button. It adds a
  firewall rule blocking the port after the OS's admin prompt (see the
  table above). The program keeps running, so *Reopen port* just
  removes the rule. Closed ports are remembered in
  `.state/closed_ports.json`. Port 5000 (the dashboard) can't be closed.
  Windows Firewall doesn't filter connections a PC makes to itself, so
  on Windows a closed port still answers local scans; the dashboard
  confirms the rule exists instead, and blocks other devices.

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
