"""
Plain-English descriptions of common programs and ports. Not a Check.

Listening Services uses describe() to decide whether an open port belongs
to a recognized app or OS feature (shown blue, "IN USE") or to something
unrecognized (amber, "REVIEW"). The Port Assessor uses it to explain what
each risky port is for.

    PROGRAMS: process name (lowercase, prefix match) -> (friendly name, what it does, advice)
    PORTS:    port -> (service name, what it does, advice)

Program matches win over port matches. A port match alone only counts as
"known" for generic Windows hosts (svchost, System) or when the OS hides the
program name ("?"); otherwise an unrecognized program on a familiar port
(e.g. something unknown on 8080) stays unknown, with the port's usual use
given as context. To teach the dashboard a new app, add a line to PROGRAMS.
"""

from checks.port_control import DASHBOARD_PORT

PROGRAMS = {
    # ---- macOS ----
    "controlcenter": (
        "AirPlay Receiver (macOS)",
        "Lets iPhones, iPads and other Macs stream music, video or screen mirroring to this Mac.",
        "Turn off in System Settings > General > AirDrop & Handoff > AirPlay Receiver if you don't use it.",
    ),
    "rapportd": (
        "Apple Continuity (rapportd)",
        "Lets your Apple devices find and talk to each other for Handoff, Universal Clipboard and iPhone remote features.",
        "Needed for Continuity features; turning off Handoff in System Settings > General > AirDrop & Handoff stops most of it.",
    ),
    "sharingd": (
        "AirDrop & Sharing (macOS)",
        "Handles AirDrop and file or screen sharing with nearby devices.",
        "Set AirDrop to Contacts Only or Receiving Off when you're on public Wi-Fi.",
    ),
    "screensharingd": (
        "macOS Screen Sharing",
        "Lets another computer see and control this Mac's screen.",
        "Turn off in System Settings > General > Sharing unless you use remote control.",
    ),
    # ---- Windows ----
    "lsass": (
        "Windows sign-in service (LSASS)",
        "Handles logins, passwords and security policy; listens for internal Windows RPC requests.",
        "Built into Windows. Don't close it; keep Windows Firewall on so other devices can't reach it.",
    ),
    "wininit": (
        "Windows startup process (wininit)",
        "Core Windows process that starts other services; listens for internal RPC requests.",
        "Built into Windows. Don't close it; keep Windows Firewall on.",
    ),
    "services": (
        "Windows Service Control Manager",
        "Starts and stops Windows background services; listens for internal RPC requests.",
        "Built into Windows. Don't close it; keep Windows Firewall on.",
    ),
    "spoolsv": (
        "Windows Print Spooler",
        "Manages printing, including printing to and from other computers.",
        "If you never print over the network, disabling the Print Spooler service removes a known attack target (PrintNightmare).",
    ),
    "nvidia web helper": (
        "NVIDIA GeForce Experience",
        "Helper for NVIDIA's app: driver updates, game optimization and streaming.",
        "Normal if you use GeForce Experience.",
    ),
    "nvcontainer": (
        "NVIDIA Container",
        "Runs NVIDIA's background driver and app services.",
        "Normal on PCs with NVIDIA graphics.",
    ),
    "jhi_service": (
        "Intel Dynamic Application Loader",
        "Intel driver service used by some security and media features.",
        "Normal on Intel PCs; only reachable from this computer.",
    ),
    # ---- Apps (any OS) ----
    "code": (
        "Visual Studio Code",
        "VS Code and its helpers talk to extensions such as language servers and debuggers over these ports.",
        "Normal while VS Code is open.",
    ),
    "cursor": (
        "Cursor editor",
        "Editor helpers talk to extensions and language servers over these ports.",
        "Normal while the editor is open.",
    ),
    "spotify": (
        "Spotify",
        "Finds other Spotify devices on your network (Spotify Connect) so you can control playback between them.",
        "Normal while Spotify is open.",
    ),
    "dropbox": (
        "Dropbox",
        "LAN sync: copies files directly from other computers on your network that run Dropbox.",
        "Turn off LAN sync in Dropbox preferences if you don't need it.",
    ),
    "discord": (
        "Discord",
        "Lets games and the Discord website talk to the app (Rich Presence, joining calls).",
        "Normal while Discord is open.",
    ),
    "steam": (
        "Steam",
        "Steam Remote Play and local game transfers between your own PCs.",
        "Normal while Steam is open; turn off Remote Play in Steam settings if you don't use it.",
    ),
    "zoom": (
        "Zoom",
        "Local helper that lets the Zoom website open meetings in the app.",
        "Normal while Zoom is installed.",
    ),
    "ms-teams": (
        "Microsoft Teams",
        "Local helper used for calls, meetings and device integration.",
        "Normal while Teams is open.",
    ),
    "teams": (
        "Microsoft Teams",
        "Local helper used for calls, meetings and device integration.",
        "Normal while Teams is open.",
    ),
    "onedrive": (
        "Microsoft OneDrive",
        "Syncs your files with OneDrive.",
        "Normal while OneDrive is running.",
    ),
    "figma_agent": (
        "Figma font helper",
        "Lets figma.com use fonts installed on this computer.",
        "Normal if you use Figma in a browser.",
    ),
    "com.docker": (
        "Docker Desktop",
        "Forwards ports from containers you're running so you can reach them.",
        "Stop containers you aren't using.",
    ),
    "docker": (
        "Docker",
        "Forwards ports from containers you're running so you can reach them.",
        "Stop containers you aren't using.",
    ),
    "postgres": (
        "PostgreSQL database",
        "A database server, usually for software you're developing.",
        "Should only listen on 127.0.0.1 unless other computers need it.",
    ),
    "mysqld": (
        "MySQL database",
        "A database server, usually for software you're developing.",
        "Should only listen on 127.0.0.1 unless other computers need it.",
    ),
    "mongod": (
        "MongoDB database",
        "A database server, usually for software you're developing.",
        "Should only listen on 127.0.0.1; exposed MongoDB servers are a common data-leak cause.",
    ),
    "redis-server": (
        "Redis",
        "An in-memory database/cache, usually for software you're developing.",
        "Should only listen on 127.0.0.1; Redis has no password by default.",
    ),
    "sshd": (
        "SSH server",
        "Lets people log in to this computer's command line remotely over an encrypted connection.",
        "Keep only if you log in remotely; use SSH keys instead of passwords.",
    ),
    "cupsd": (
        "Printing service (CUPS)",
        "Manages printers and print jobs.",
        "Normal; should only be reachable from this computer unless you share a printer.",
    ),
    "systemd-resolve": (
        "DNS resolver (systemd-resolved)",
        "Looks up website names for programs on this computer.",
        "Normal; only reachable from this computer.",
    ),
    "avahi-daemon": (
        "Network discovery (Avahi/Bonjour)",
        "Lets printers and other devices on your network find this computer by name.",
        "Normal on home networks.",
    ),
    "nginx": ("nginx web server", "Serves websites or apps from this computer.", "Keep only if you're hosting something."),
    "httpd": ("Apache web server", "Serves websites or apps from this computer.", "Keep only if you're hosting something."),
    "apache2": ("Apache web server", "Serves websites or apps from this computer.", "Keep only if you're hosting something."),
}

PORTS = {
    21: ("FTP", "Old file-transfer protocol; sends usernames, passwords and files unencrypted.",
         "Use SFTP instead and turn FTP off."),
    22: ("SSH", "Encrypted remote login to this computer's command line.",
         "Keep only if you log in remotely; use keys, not passwords."),
    23: ("Telnet", "Very old remote login that sends everything, including passwords, unencrypted.",
         "Turn it off and use SSH."),
    25: ("SMTP", "Sends email between mail servers.", "Should not be open on a personal computer."),
    53: ("DNS", "Looks up website names.", "Normal when only reachable from this computer."),
    80: ("HTTP", "Unencrypted website or web app.", "Keep only if you're hosting something."),
    135: ("Windows RPC (MSRPC)", "Tells other computers which port each Windows service is on; used for remote management.",
          "Keep Windows Firewall on so only trusted networks can reach it."),
    139: ("NetBIOS", "Old Windows file/printer sharing and computer-name lookups.",
          "Turn off NetBIOS over TCP/IP if you don't use old network shares."),
    443: ("HTTPS", "Encrypted website or web app.", "Keep only if you're hosting something."),
    445: ("SMB file sharing", "Windows file and printer sharing (Macs use it to share with Windows too).",
          "Turn off file sharing if you don't use it; never expose it to the internet."),
    631: ("IPP printing", "Printing to and from this computer.", "Normal if you use a printer."),
    1433: ("Microsoft SQL Server", "A Microsoft database server.", "Should only be reachable by the apps that use it."),
    2869: ("Windows network discovery (UPnP)", "Lets printers, TVs and media players on your network find this PC.",
           "Turn off network discovery on public networks."),
    3000: ("Development web server", "Common port for web apps you're building (Node, React, Rails).",
           "Normal while you're developing."),
    3306: ("MySQL", "A MySQL database server.", "Bind it to 127.0.0.1 unless other computers need it."),
    3389: ("Remote Desktop (RDP)", "Lets another computer see and control this PC's screen.",
           "Turn off Remote Desktop unless you use it; if you do, only use it over a VPN."),
    5000: ("AirPlay / development server", "Used by AirPlay on Macs and by many development web servers.",
           "Check which program it belongs to."),
    5040: ("Windows Connected Devices Platform", "Links your PC with your phone and nearby devices (Phone Link, Nearby sharing).",
           "Normal on Windows 10/11."),
    5357: ("Windows network discovery (WSD)", "Lets printers and scanners on your network find this PC.",
           "Turn off network discovery on public networks."),
    5432: ("PostgreSQL", "A PostgreSQL database server.", "Bind it to 127.0.0.1 unless other computers need it."),
    5900: ("VNC screen sharing", "Remote view and control of this computer's screen (macOS Screen Sharing uses it).",
           "Turn off screen sharing unless you use it; always set a strong password."),
    6379: ("Redis", "An in-memory database/cache.", "Bind it to 127.0.0.1; it has no password by default."),
    7000: ("AirPlay", "AirPlay streaming to this Mac.", "Turn off AirPlay Receiver if you don't use it."),
    7680: ("Windows Delivery Optimization", "Shares Windows updates with other PCs on your network to save bandwidth.",
           "Normal; can be limited in Settings > Windows Update > Advanced options > Delivery Optimization."),
    8000: ("Development web server", "Common port for web apps you're building (Python, Django).",
           "Normal while you're developing."),
    8080: ("Web server / proxy", "Common alternative port for websites, proxies and dev servers.",
           "Keep only if you're hosting something."),
    27017: ("MongoDB", "A MongoDB database server.", "Bind it to 127.0.0.1; exposed MongoDB is a common data-leak cause."),
}

# Generic Windows process names; for these the port tells you which service it is.
GENERIC_HOSTS = {"svchost", "system"}

WINDOWS_DYNAMIC_RPC = (
    "Windows internal service port",
    "Windows services such as sign-in, scheduling and event logging listen here for RPC requests (ports 49664+).",
    "Built into Windows. Keep Windows Firewall on so other devices can't reach it.",
)


def _normalize(command):
    name = command.lower().strip()
    return name[:-4] if name.endswith(".exe") else name


def describe(command, port):
    """
    Return {"name", "what", "advice", "known"} for a program listening on a port.
    known=False means neither the program nor the port was recognized.
    """
    name = _normalize(command)

    if port == DASHBOARD_PORT and name.startswith("python"):
        return {"name": "This dashboard", "what": "The Network Security Dashboard you're looking at.",
                "advice": "", "known": True}

    if name not in GENERIC_HOSTS:
        # Longest prefix first, so "code helper" matches "code" but "controlcenter" isn't matched by "co".
        for key in sorted(PROGRAMS, key=len, reverse=True):
            if name.startswith(key):
                friendly, what, advice = PROGRAMS[key]
                return {"name": friendly, "what": what, "advice": advice, "known": True}

    trusted_by_port = name in GENERIC_HOSTS or name == "?"
    if port in PORTS:
        service, what, advice = PORTS[port]
        if trusted_by_port:
            return {"name": service, "what": what, "advice": advice, "known": True}
        return {"name": command, "what": f"Port {port} is normally used for {service} ({what[0].lower()}{what[1:].rstrip('.')}).",
                "advice": "", "known": False}

    if name in GENERIC_HOSTS and 49152 <= port <= 65535:
        friendly, what, advice = WINDOWS_DYNAMIC_RPC
        return {"name": friendly, "what": what, "advice": advice, "known": True}

    return {"name": command, "what": "", "advice": "", "known": False}


def port_info(port):
    """(service name, what it does) for a port, or None."""
    entry = PORTS.get(port)
    return (entry[0], entry[1]) if entry else None
