"""
System Hardening check.

Reads the OS's built-in protections with read-only commands, avoiding
ones that need admin rights where possible. Each OS has its own list of
probes; a probe returns (status, detail):
    ("ok", "On")  /  ("warning", "OFF. <how to fix>")  /  ("error", "<why it couldn't be read>")

    macOS   -- firewall, stealth mode, FileVault, Gatekeeper, SIP
    Windows -- Defender Firewall profiles, Defender antivirus, BitLocker, UAC
    Linux   -- ufw firewall, SSH root/password login, automatic security updates
"""

from pathlib import Path

from checks.base import Check, register
from checks.system import OS, powershell_json, run

UNREADABLE = ("error", "Couldn't be read on this system")


def _text_probe(command, on_text, fix):
    """Probe that runs a command and looks for on_text in its output."""
    def probe():
        code, out = run(command)
        out = out.lower()
        if code is None or "permission" in out or "root" in out:
            return UNREADABLE
        if on_text in out and "disabled" not in out:
            return "ok", "On"
        return "warning", f"OFF. {fix}."
    return probe


# ---- macOS ----

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

MACOS_PROBES = [
    ("Firewall", _text_probe([SOCKETFILTERFW, "--getglobalstate"], "enabled",
                             "Turn on in System Settings > Network > Firewall")),
    ("Firewall stealth mode", _text_probe([SOCKETFILTERFW, "--getstealthmode"], "stealth mode is on",
                                          "Turn on in Firewall > Options so the Mac ignores probes like ping")),
    ("FileVault disk encryption", _text_probe(["fdesetup", "status"], "filevault is on",
                                              "Turn on in System Settings > Privacy & Security > FileVault")),
    ("Gatekeeper", _text_probe(["spctl", "--status"], "assessments enabled",
                               "Run: sudo spctl --master-enable")),
    ("System Integrity Protection", _text_probe(["csrutil", "status"], "enabled.",
                                                "Re-enable from Recovery mode: csrutil enable")),
]


# ---- Windows ----

def _windows_firewall():
    rows = powershell_json(
        "Get-NetFirewallProfile | Select-Object Name, @{n='On'; e={[string]$_.Enabled}}"
    )
    if not rows:
        return UNREADABLE
    off = [row["Name"] for row in rows if row.get("On") != "True"]
    if off:
        return "warning", (f"OFF for {', '.join(off)} network(s). Turn on in Windows Security > "
                           "Firewall & network protection.")
    return "ok", "On for Domain, Private and Public networks"


def _windows_defender():
    rows = powershell_json(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled"
    )
    if not rows:
        return "error", "Couldn't read Defender status (a third-party antivirus may replace it)"
    status = rows[0]
    if status.get("AntivirusEnabled") and status.get("RealTimeProtectionEnabled"):
        return "ok", "Antivirus and real-time protection on"
    return "warning", ("Real-time protection OFF. Turn on in Windows Security > "
                       "Virus & threat protection.")


def _windows_bitlocker():
    # Read through the Explorer shell, which (unlike Get-BitLockerVolume) doesn't need admin.
    rows = powershell_json(
        "(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\\')"
        ".Self.ExtendedProperty('System.Volume.BitLockerProtection')"
    )
    value = rows[0] if rows else None
    if value in (1, 3, 6):
        return "ok", "On for the system drive"
    if value == 5:
        return "warning", "SUSPENDED. Resume in Control Panel > BitLocker Drive Encryption."
    if value == 2:
        return "warning", ("OFF. Turn on in Control Panel > BitLocker Drive Encryption "
                           "(Windows Home: Settings > Privacy & security > Device encryption).")
    return "error", "Not available on this edition of Windows, or couldn't be read"


def _windows_uac():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enabled, _ = winreg.QueryValueEx(key, "EnableLUA")
    except (ImportError, OSError):
        return UNREADABLE
    if enabled == 1:
        return "ok", "On"
    return "warning", "OFF. Turn on in Control Panel > User Accounts > Change User Account Control settings."


WINDOWS_PROBES = [
    ("Windows Defender Firewall", _windows_firewall),
    ("Microsoft Defender Antivirus", _windows_defender),
    ("BitLocker disk encryption", _windows_bitlocker),
    ("User Account Control (UAC)", _windows_uac),
]


# ---- Linux ----

def _linux_ufw():
    code, out = run(["ufw", "status"])
    out = out.lower()
    if code is None:
        return "warning", "ufw isn't installed. Install it and run: sudo ufw enable"
    if "root" in out or "permission" in out:
        return "error", "Needs root to read (run the dashboard as root to check)"
    if "status: active" in out:
        return "ok", "On"
    return "warning", "OFF. Run: sudo ufw allow ssh && sudo ufw enable"


def _sshd_option(name):
    """First value of an sshd_config option (sshd uses the first one it sees), or None."""
    paths = sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")) + [Path("/etc/ssh/sshd_config")]
    for path in paths:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return parts[1].lower()
    return None


def _linux_ssh_root():
    if not Path("/etc/ssh/sshd_config").exists():
        return "ok", "No SSH server installed"
    if _sshd_option("PermitRootLogin") == "yes":
        return "warning", "Root can log in with a password. Set PermitRootLogin no in /etc/ssh/sshd_config."
    return "ok", "Root password login blocked"


def _linux_ssh_passwords():
    if not Path("/etc/ssh/sshd_config").exists():
        return "ok", "No SSH server installed"
    if _sshd_option("PasswordAuthentication") == "no":
        return "ok", "Key-only logins"
    return "warning", ("Password logins allowed (brute-force target). Set up SSH keys, "
                       "then set PasswordAuthentication no.")


def _linux_auto_updates():
    config = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if not Path("/usr/bin/apt").exists():
        return "error", "Only checked on Debian/Ubuntu"
    try:
        if 'Unattended-Upgrade "1"' in config.read_text():
            return "ok", "On"
    except OSError:
        pass
    return "warning", "OFF. Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades"


LINUX_PROBES = [
    ("Firewall (ufw)", _linux_ufw),
    ("SSH root login", _linux_ssh_root),
    ("SSH password login", _linux_ssh_passwords),
    ("Automatic security updates", _linux_auto_updates),
]


@register
class HardeningCheck(Check):
    NAME = "System Hardening"
    DESCRIPTION = "Built-in OS protections: firewall, disk encryption, antivirus, login security"

    def run(self):
        probes = {"Darwin": MACOS_PROBES, "Windows": WINDOWS_PROBES, "Linux": LINUX_PROBES}.get(OS)
        if probes is None:
            return {"status": "error", "summary": f"Not supported on {OS} yet", "items": []}

        items = []
        for label, probe in probes:
            status, detail = probe()
            items.append({"label": label, "status": status, "detail": detail})

        off_count = sum(1 for item in items if item["status"] == "warning")
        if off_count:
            status, summary = "warning", f"{off_count} protection(s) turned off"
        else:
            status, summary = "ok", "All checked protections are on"
        return {"status": status, "summary": summary, "items": items}
