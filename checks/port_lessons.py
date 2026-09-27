"""
Beginner lessons: how common ports get exploited, and how to stay safe. Not a Check.

The dashboard shows these in two places:
  * the "Common ports explained" guide at the bottom of the page, and
  * a "How attackers use this port" drop-down on any finding whose label
    starts with "Port <number>", including results sent by the local helper.

Each lesson is written for someone with no security background: what the
port is, how attackers take advantage of it (conceptually, never step by
step), a real incident, an everyday analogy, and how to close or protect it.

    PORT_LESSONS:  port -> {name, what, how, example, analogy, protect}
    lesson_for_label("Port 445 · SMB") -> the port-445 lesson (or None)
"""

import re

PORT_LESSONS = {
    21: {
        "name": "FTP (file transfer)",
        "what": "An old way to copy files between computers, from the 1970s.",
        "how": ("FTP sends your username, password and files as plain, readable text. Anyone on the same network, "
                "like the same café Wi-Fi, can capture them with free tools. Attackers also try \"anonymous\" logins "
                "and common passwords to read or plant files, and some old FTP programs contain known backdoors."),
        "example": ("In 2011 the download of the popular vsftpd 2.3.4 FTP server was secretly altered to include a "
                    "backdoor (CVE-2011-2523): a username ending in a smiley face \":)\" opened a hidden admin "
                    "command line for anyone who connected."),
        "analogy": "Like mailing a postcard with your house key taped to it: every mail carrier along the way can read it.",
        "protect": "Turn FTP off. To move files, use SFTP, a cloud drive or a USB drive instead.",
    },
    22: {
        "name": "SSH (remote login)",
        "what": "Encrypted remote control of a computer's command line.",
        "how": ("SSH is encrypted, so attackers usually guess instead: bots scan the whole internet around the clock "
                "and try thousands of common usernames and passwords (like root / 123456). If one works, the "
                "attacker has full control. The example log in this app shows exactly this pattern."),
        "example": ("Security researchers who put a brand-new SSH server on the internet typically see automated "
                    "password guesses within minutes, and botnets use guessed SSH passwords to install "
                    "crypto-mining software on servers."),
        "analogy": "Like a strong front-door lock, but someone stands outside all night trying every key on a giant key ring.",
        "protect": ("Turn off remote login if you don't use it (Mac: System Settings > General > Sharing > Remote "
                    "Login). If you need it, use SSH keys instead of passwords and block repeated failed logins."),
    },
    23: {
        "name": "Telnet (old remote login)",
        "what": "A remote login from 1969 that sends everything, including passwords, as plain text.",
        "how": ("Nothing is encrypted, so passwords can be read by anyone watching the network. Many cheap cameras, "
                "routers and smart devices shipped with Telnet turned on and a factory password such as admin / "
                "admin, so attackers simply log in."),
        "example": ("In 2016 the Mirai botnet scanned the internet for Telnet, logged in to hundreds of thousands of "
                    "cameras and routers using about 60 factory-default passwords, and used them to knock Twitter, "
                    "Netflix, Reddit and other major sites offline (the Dyn DNS attack)."),
        "analogy": "Like reading your PIN out loud over a loudspeaker every time you use the ATM.",
        "protect": ("Turn Telnet off everywhere and use SSH instead. Change the default password on every router, "
                    "camera and smart device you own."),
    },
    25: {
        "name": "SMTP (email servers)",
        "what": "How mail servers pass email to each other. A personal computer should not be running one.",
        "how": ("If a mail server on your device is open and misconfigured as an \"open relay\", spammers use it to "
                "send huge amounts of junk and phishing email that appears to come from you, and your internet "
                "address gets blocklisted. Malware that turns a PC into a spam bot often opens this port."),
        "example": ("Spam botnets such as Rustock and Cutwail used infected home computers to send billions of spam "
                    "emails a day before they were taken down."),
        "analogy": "Like leaving your company letterhead and postage machine on the sidewalk for anyone to use.",
        "protect": ("Close it on personal computers. If a program you don't recognize opened it, run a full "
                    "malware scan."),
    },
    80: {
        "name": "HTTP (unencrypted web)",
        "what": "Plain, unencrypted web pages, including the admin pages of routers, printers and cameras.",
        "how": ("Anything typed into an HTTP page, including passwords, travels as readable text. Device admin pages "
                "left reachable on port 80 are targets for password guessing and for bugs in outdated firmware."),
        "example": ("In 2018 the VPNFilter malware used known bugs in home routers and network storage devices to "
                    "infect an estimated 500,000 of them in over 50 countries."),
        "analogy": "Like talking through a paper-thin wall: anyone in the next room can hear every word.",
        "protect": ("Only run a web server if you're hosting something on purpose, and prefer HTTPS (port 443). "
                    "Update router and camera firmware and change their default admin passwords."),
    },
    135: {
        "name": "Windows RPC (MSRPC)",
        "what": "A Windows \"directory\" that tells other computers where each Windows service is listening.",
        "how": ("It is a doorway to many internal Windows services. Bugs in those services have let worms jump "
                "from computer to computer with no one clicking anything."),
        "example": ("In 2003 the Blaster worm used a bug reachable through port 135 to infect hundreds of thousands "
                    "of Windows PCs, which then kept crashing and restarting on a countdown timer."),
        "analogy": "Like the directory in a building lobby: it helps visitors find each office, and helps burglars too.",
        "protect": ("Keep Windows Firewall on (it blocks this port from other devices by default) and keep Windows "
                    "Update turned on."),
    },
    139: {
        "name": "NetBIOS (old Windows sharing)",
        "what": "Older Windows file and printer sharing and computer-name lookups.",
        "how": ("It can reveal your computer's name, user names and shared folders to anyone on the same network, "
                "and it carries old versions of file sharing with weaker security."),
        "example": ("The Nimda worm (2001) spread partly by copying itself into open Windows file shares reachable "
                    "this way, and became one of the fastest-spreading worms of its time."),
        "analogy": "Like a name tag that also lists your home address and which of your windows are unlocked.",
        "protect": ("Turn off NetBIOS over TCP/IP if you don't use old network shares, and choose \"Public network\" "
                    "when you join public Wi-Fi."),
    },
    445: {
        "name": "SMB (file sharing)",
        "what": "Windows file and printer sharing. Macs use it to share files too.",
        "how": ("SMB gives direct access to files. Bugs in it have let attackers run their own programs on a "
                "computer without any password, and once one computer is infected the attack spreads to every "
                "other computer on the network that has port 445 open."),
        "example": ("In May 2017 WannaCry ransomware used the EternalBlue SMB bug (CVE-2017-0144) to lock the files "
                    "on over 200,000 computers in about 150 countries within days, including UK hospital systems. "
                    "Microsoft had released the fix two months earlier; the victims simply hadn't updated."),
        "analogy": "Like a shared hallway between apartments: if one catches fire and the doors are open, it spreads to all of them.",
        "protect": ("Turn off file sharing if you don't use it (Windows: Settings > Network & internet > Advanced "
                    "sharing settings; Mac: System Settings > General > Sharing > File Sharing). Keep updates on "
                    "and never expose port 445 to the internet."),
    },
    1433: {
        "name": "Microsoft SQL Server (database)",
        "what": "A Microsoft database server, which often holds customer records and passwords.",
        "how": ("Attackers scan for exposed database ports and try common administrator passwords. Once inside, "
                "they steal the data or install crypto-mining software."),
        "example": ("In 2003 the SQL Slammer worm, spreading through SQL Server's companion port 1434, infected about "
                    "75,000 servers in 10 minutes and slowed down large parts of the internet."),
        "analogy": "Like keeping the company safe in the lobby instead of in the vault.",
        "protect": "Only let the apps that need the database reach it, never expose it to the internet, and use strong passwords.",
    },
    3306: {
        "name": "MySQL (database)",
        "what": "A MySQL or MariaDB database, common behind websites and apps.",
        "how": ("An exposed database invites password guessing, and bugs in old versions have let attackers skip "
                "the password entirely. The prize is whatever the database stores."),
        "example": ("A 2012 MySQL bug (CVE-2012-2122) let an attacker log in without the password just by retrying "
                    "a few hundred times, because about 1 in 256 wrong passwords was accepted."),
        "analogy": "Like a lock that opens for the wrong key once in every 256 tries.",
        "protect": ("Make it listen only on 127.0.0.1 (this computer) unless another machine truly needs it, keep it "
                    "updated and use a strong password."),
    },
    3389: {
        "name": "Remote Desktop (RDP)",
        "what": "Lets someone see and control a Windows PC's screen from somewhere else.",
        "how": ("An attacker who gets in sees your desktop exactly as you do. Bots guess passwords constantly, and "
                "bugs have let attackers in with no password at all. Exposed Remote Desktop is one of the most "
                "common ways ransomware gangs break into organizations."),
        "example": ("BlueKeep (CVE-2019-0708) let attackers take over unpatched Windows PCs through Remote Desktop "
                    "with no login. Microsoft and the NSA both urged everyone to patch, warning it could spread "
                    "like WannaCry."),
        "analogy": "Like handing a stranger the remote control to your computer, keyboard and mouse included.",
        "protect": ("Turn off Remote Desktop unless you use it (Settings > System > Remote Desktop). If you need it, "
                    "reach it only through a VPN and use a strong password."),
    },
    5432: {
        "name": "PostgreSQL (database)",
        "what": "A PostgreSQL database server, common in apps you or your tools are developing.",
        "how": "Exposed databases attract automated password guessing; once in, attackers steal data or run their own programs.",
        "example": ("In 2020 the PGMiner botnet broke into PostgreSQL servers on the internet by guessing passwords, "
                    "then used them to mine cryptocurrency."),
        "analogy": "Like a filing cabinet left on the sidewalk with a cheap combination lock.",
        "protect": "Make it listen only on 127.0.0.1 unless other computers need it, and use a strong password.",
    },
    5555: {
        "name": "Android Debug Bridge (ADB)",
        "what": "A developer tool that gives full control of an Android phone, tablet or TV box over the network.",
        "how": ("ADB can install apps and read files, and on many devices it asks for no password when reached over "
                "the network. If wireless debugging is left on, anyone on the same Wi-Fi may be able to connect."),
        "example": ("In 2018 the ADB.Miner worm spread across thousands of Android phones and TV boxes with port 5555 "
                    "open, using them to mine cryptocurrency and to find the next victim."),
        "analogy": "Like leaving your phone unlocked on a café table with the settings app open.",
        "protect": ("On Android: Settings > System > Developer options > turn off USB debugging and Wireless "
                    "debugging, or turn Developer options off completely."),
    },
    5900: {
        "name": "VNC (screen sharing)",
        "what": "Remote view and control of a screen. macOS Screen Sharing uses it.",
        "how": ("Many VNC setups use weak passwords or none, and old versions had bugs that skipped the password "
                "check. An attacker sees everything on your screen and can type and click as you."),
        "example": ("RealVNC 4.1.1 had a bug (CVE-2006-2369) that let anyone skip the password. In 2022 researchers "
                    "found about 9,000 VNC servers on the internet with no password at all, some controlling "
                    "industrial equipment."),
        "analogy": "Like leaving your screen facing an open window with a keyboard on the sidewalk.",
        "protect": ("Turn off Screen Sharing unless you use it (Mac: System Settings > General > Sharing). If you "
                    "need it, use a strong password and a VPN."),
    },
    6379: {
        "name": "Redis (developer database)",
        "what": "A fast in-memory database and cache used by developers.",
        "how": ("Redis was designed to trust anyone who can connect and historically had no password by default. "
                "Attackers use exposed Redis servers to erase data or plant crypto-mining malware."),
        "example": ("In 2023 researchers found the HeadCrab malware had taken over more than 1,200 exposed Redis "
                    "servers to mine cryptocurrency."),
        "analogy": "Like a notebook left on a park bench labeled \"secrets, feel free to edit\".",
        "protect": "Make it listen only on 127.0.0.1, set a password, and never expose it to the internet.",
    },
    8080: {
        "name": "Alternate web port (dev servers, admin pages)",
        "what": "Often used by development servers, proxies and admin pages such as Tomcat or Jenkins.",
        "how": ("Test and admin pages on this port were often never meant to be public and still have default "
                "passwords or debug features turned on."),
        "example": ("Attackers routinely scan for Apache Tomcat admin pages left with default logins and use them to "
                    "upload malicious programs to the server."),
        "analogy": "Like the kitchen's side door that staff forget to lock at night.",
        "protect": ("Stop development servers when you're done, make them listen only on 127.0.0.1, and change "
                    "default passwords."),
    },
    27017: {
        "name": "MongoDB (database)",
        "what": "A MongoDB database server.",
        "how": ("Older MongoDB setups accepted connections from anywhere with no password. Attackers copy or delete "
                "the data and demand a ransom."),
        "example": ("In January 2017 attackers wiped more than 27,000 MongoDB databases that were open on the "
                    "internet without a password and left ransom notes demanding Bitcoin."),
        "analogy": "Like a storage unit with the door rolled all the way up.",
        "protect": "Make it listen only on 127.0.0.1 and turn on authentication.",
    },
}

# The big-picture rules shown above the port guide.
SAFETY_RULES = [
    ("Close what you don't use.",
     "Every open port is a program waiting for strangers to talk to it. A closed port can't be attacked at all."),
    ("Turn on automatic updates.",
     "Most big attacks, like WannaCry, used bugs that already had a fix. Updates close those holes."),
    ("Keep the firewall on.",
     "The firewall decides which doors other devices may knock on. Windows and macOS both include one."),
    ("Replace default passwords.",
     "Botnets like Mirai simply log in with factory passwords. Use long, unique passwords and turn on MFA."),
    ("Be careful on public Wi-Fi.",
     "Everyone on the same network can reach your open ports. Choose \"Public network\" and turn off sharing."),
]

_PORT_LABEL = re.compile(r"^Port (\d{1,5})\b")


def lesson_for_port(port):
    """The lesson for a port number, or None."""
    return PORT_LESSONS.get(port)


def lesson_for_label(label):
    """The lesson for a finding labeled "Port <n> ...", or None."""
    match = _PORT_LABEL.match(label or "")
    return PORT_LESSONS.get(int(match[1])) if match else None


# Everyday names people use in questions ("is RDP dangerous?").
_PORT_KEYWORDS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http": 80, "rpc": 135, "msrpc": 135,
    "netbios": 139, "smb": 445, "file sharing": 445, "sql server": 1433, "mssql": 1433,
    "mysql": 3306, "rdp": 3389, "remote desktop": 3389, "postgres": 5432, "adb": 5555,
    "android debug": 5555, "vnc": 5900, "screen sharing": 5900, "redis": 6379, "mongodb": 27017,
}


def lessons_in_text(text, limit=3):
    """[(port, lesson)] for ports a question mentions by number or name, in order, at most limit."""
    text = (text or "").lower()
    found = [(match.start(), int(match[0])) for match in re.finditer(r"\b\d{2,5}\b", text)]
    found += [(match.start(), port) for word, port in _PORT_KEYWORDS.items()
              for match in re.finditer(rf"\b{re.escape(word)}\b", text)]
    ports = []
    for _, port in sorted(found):
        if port in PORT_LESSONS and port not in ports:
            ports.append(port)
    return [(port, PORT_LESSONS[port]) for port in ports[:limit]]
