"""
"Check this device" guides: no-download security steps per device type. Not a Check.

A web page can't see a phone's (or any device's) open ports; browsers are
sandboxed so websites can't inspect the device they run on. These guides
work anywhere, including iPhone and Android: the dashboard picks the guide
for the visitor's device and walks them through the settings that open
ports or accept connections from other devices.

    DEVICE_GUIDES: key -> {title, intro, steps: [(what to do, where, why)]}
"""

DEVICE_GUIDES = {
    "ios": {
        "title": "iPhone / iPad",
        "intro": ("iPhones keep almost no ports open to other devices, and apps can't run servers in the "
                  "background, so the main risks are sharing features and outdated software."),
        "steps": [
            ("Limit AirDrop to Contacts Only (or Receiving Off).",
             "Settings > General > AirDrop",
             "Stops strangers nearby from sending you files and photos, and shows your phone to fewer people."),
            ("Turn off Personal Hotspot when you aren't using it.",
             "Settings > Personal Hotspot > Allow Others to Join",
             "A hotspot turns your phone into a small router. With a weak password, strangers can join its network."),
            ("Turn on automatic updates.",
             "Settings > General > Software Update > Automatic Updates",
             "Updates fix bugs attackers can reach over the network, like the 2021 FORCEDENTRY iMessage attack "
             "that needed no taps at all."),
            ("Review which apps can reach your local network.",
             "Settings > Privacy & Security > Local Network",
             "Apps listed here can find and connect to the open ports of other devices on your Wi-Fi. Turn off any "
             "app that doesn't need it."),
            ("Remove profiles and VPNs you don't recognize.",
             "Settings > General > VPN & Device Management",
             "A malicious profile can quietly send your traffic through an attacker's server."),
        ],
    },
    "android": {
        "title": "Android phone / tablet",
        "intro": "Menu names vary a little by phone maker; use the Settings search bar if a path doesn't match.",
        "steps": [
            ("Turn off USB debugging and Wireless debugging.",
             "Settings > System > Developer options",
             "Wireless debugging opens port 5555 (ADB), which gives full control of the phone. The 2018 ADB.Miner "
             "worm spread through exactly this port."),
            ("Set Quick Share (Nearby Share) to Contacts or Your devices.",
             "Settings > Google > Devices & sharing > Quick Share",
             "Stops strangers nearby from sending you files."),
            ("Turn off the hotspot when you aren't using it, and give it a strong password.",
             "Settings > Network & internet > Hotspot & tethering",
             "A hotspot turns your phone into a small router other devices can join."),
            ("Install system and security updates.",
             "Settings > System > Software update (and Security & privacy > Updates)",
             "Google publishes Android security fixes every month; they only protect you once installed."),
            ("Block apps from unknown sources.",
             "Settings > Apps > Special app access > Install unknown apps",
             "Apps installed from outside the Play Store are a common way malware gets on a phone and opens ports."),
        ],
    },
    "mac": {
        "title": "Mac",
        "intro": "Download the Mac helper above to see the exact ports open on this Mac. These settings close the common ones.",
        "steps": [
            ("Turn off sharing features you don't use.",
             "System Settings > General > Sharing",
             "File Sharing opens port 445, Screen Sharing opens 5900 and Remote Login opens 22, all popular attack targets."),
            ("Turn on the firewall and stealth mode.",
             "System Settings > Network > Firewall (then Options)",
             "The firewall blocks connections to apps you haven't allowed; stealth mode hides the Mac from network scans."),
            ("Turn off AirPlay Receiver if you don't stream to this Mac.",
             "System Settings > General > AirDrop & Handoff > AirPlay Receiver",
             "AirPlay Receiver keeps ports 5000 and 7000 open to devices on your network."),
            ("Turn on automatic updates.",
             "System Settings > General > Software Update > Automatic updates",
             "Updates fix bugs in the programs behind open ports."),
        ],
    },
    "windows": {
        "title": "Windows PC",
        "intro": "Download the Windows helper above to see the exact ports open on this PC. These settings close the common ones.",
        "steps": [
            ("Keep Windows Firewall on for every network type.",
             "Windows Security > Firewall & network protection",
             "The firewall blocks other devices from reaching ports like 135, 139 and 445."),
            ("Mark public Wi-Fi as a Public network.",
             "Settings > Network & internet > Wi-Fi > (your network) > Public network",
             "Public mode hides the PC and turns off file sharing and network discovery."),
            ("Turn off Remote Desktop unless you use it.",
             "Settings > System > Remote Desktop",
             "Remote Desktop (port 3389) is one of the most common ways ransomware gangs break in."),
            ("Turn off file and printer sharing if you don't share.",
             "Settings > Network & internet > Advanced network settings > Advanced sharing settings",
             "File sharing uses port 445, the port the WannaCry ransomware spread through."),
            ("Keep Windows Update on.",
             "Settings > Windows Update",
             "WannaCry's victims were computers that had skipped a fix released two months earlier."),
        ],
    },
}
