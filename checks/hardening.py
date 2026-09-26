"""
System Hardening check.

Reads the OS's built-in protections with read-only commands that don't
need admin rights. macOS is fully supported; Linux gets a firewall check
(ufw) when available.

Each entry in MACOS_CHECKS is (label, command, text that means "on",
fix shown when it's off).
"""

import platform
import subprocess

from checks.base import Check, register

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

MACOS_CHECKS = [
    ("Firewall", [SOCKETFILTERFW, "--getglobalstate"], "enabled",
     "Turn on in System Settings > Network > Firewall"),
    ("Firewall stealth mode", [SOCKETFILTERFW, "--getstealthmode"], "stealth mode is on",
     "Turn on in Firewall > Options so the Mac ignores probes like ping"),
    ("FileVault disk encryption", ["fdesetup", "status"], "filevault is on",
     "Turn on in System Settings > Privacy & Security > FileVault"),
    ("Gatekeeper", ["spctl", "--status"], "assessments enabled",
     "Run: sudo spctl --master-enable"),
    ("System Integrity Protection", ["csrutil", "status"], "enabled.",
     "Re-enable from Recovery mode: csrutil enable"),
]

LINUX_CHECKS = [
    ("Firewall (ufw)", ["ufw", "status"], "status: active",
     "Run: sudo ufw enable"),
]


def _run(command):
    """Return lowercased output, or None if the command couldn't run."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return (result.stdout + result.stderr).lower()


@register
class HardeningCheck(Check):
    NAME = "System Hardening"
    DESCRIPTION = "Built-in OS protections: firewall, disk encryption, app security"

    def run(self):
        checks = {"Darwin": MACOS_CHECKS, "Linux": LINUX_CHECKS}.get(platform.system())
        if checks is None:
            return {"status": "error", "summary": f"Not supported on {platform.system()} yet", "items": []}

        items = []
        off_count = 0
        for label, command, on_text, fix in checks:
            output = _run(command)
            if output is None or "permission" in output or "root" in output:
                items.append({"label": label, "status": "error", "detail": "Couldn't be read on this system"})
            elif on_text in output and "disabled" not in output:
                items.append({"label": label, "status": "ok", "detail": "On"})
            else:
                off_count += 1
                items.append({"label": label, "status": "warning", "detail": f"OFF. {fix}."})

        if off_count:
            status, summary = "warning", f"{off_count} protection(s) turned off"
        else:
            status, summary = "ok", "All checked protections are on"
        return {"status": status, "summary": summary, "items": items}
