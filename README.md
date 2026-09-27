# Port a Potty

Port a Potty is a beginner-friendly defensive cybersecurity dashboard built for HackUMBC. It teaches non-technical people what ports are, how attackers exploit open ones, and how to close them, using an example security log, optional local-device checks, plain-language guides and a voice-enabled assistant.

**Live app:** [hackumbc-portapotty.vercel.app](https://hackumbc-portapotty.vercel.app)

## What it does

### IOC / CVE Analyzer (example log)

The **IOC / CVE Analyzer** reads a **static example log file** bundled with the app (clearly labeled on the panel, with the file name) so visitors can safely see what real attacks look like. Visitors can switch between example scenarios or upload their own UTF-8 `.log`/`.txt` file up to 512 KB. It detects:

- **Brute-force attempts:** 4+ failed logins against one account from one source within 120 seconds.
- **Password spraying:** one source trying a few passwords across 4+ accounts within 300 seconds.
- **CVE-mapped ports:** when run on a real device, open ports tied to famous vulnerabilities (EternalBlue, BlueKeep, ...). On the website this is skipped, because the site runs on a cloud server, not the visitor's device.

Detection rules are fixed (see `checks/runtime_settings.py`) so every visitor gets the same, easy-to-explain result.

### Learning guides (work on any device, including phones)

- **Common ports explained:** for 17 common ports, what each one is, how attackers exploit it, a real incident (Mirai, WannaCry, BlueKeep, ADB.Miner, ...), an everyday analogy, and how to close it. The same lesson appears as a **How attackers use this port** drop-down on every port finding, including results from the helper. Content lives in `checks/port_lessons.py`.
- **Check this device (no download):** websites can't read a device's open ports, so this is a guided checklist for iPhone/iPad, Android, Mac and Windows (AirDrop, hotspot, wireless debugging/ADB, sharing settings, updates). The visitor's device is picked automatically. Content lives in `checks/device_guides.py`.

### Local device helper

The website cannot safely inspect a visitor's computer by itself. The optional **Local device helper** runs on the user's Windows PC or Mac and uploads only read-only findings to the hosted dashboard:

1. **Local Port Assessor** checks commonly risky localhost ports.
2. **Listening Services** lists programs accepting connections and whether they are exposed to the network.
3. **System Hardening** reports built-in protections: the firewall, Microsoft Defender, BitLocker and UAC on Windows; the firewall, stealth mode, FileVault, Gatekeeper and SIP on macOS.

- **Windows:** click **Download for Windows**, extract the ZIP, and double-click `Port-a-Potty-Helper.exe`. No Python needed.
- **Mac:** click **Download for Mac**, then run `cd ~/Downloads/Port-a-Potty-Mac-Helper && python3 port_a_potty_helper.py` in Terminal (or double-click `Start Port a Potty Helper.command`). It uses the `python3` that comes with macOS (Apple's Command Line Tools) and only the Python standard library. On a Mac, program names come from `lsof` and system services (File Sharing, Screen Sharing, Remote Login) are identified from `netstat` plus the Sharing setting that opens each port, since macOS hides their names without admin rights.

Each package includes a unique, device-scoped enrollment token, so the user does not need an API key or a manual `.env` setup. The page checks for the first scan every 10 seconds after a download and then shows the panels in this order:

1. Local Port Assessor
2. Listening Services
3. IOC / CVE Analyzer
4. System Hardening

The helper is deliberately one-way: the hosted app can display results, but it cannot run commands, alter firewall rules, or change settings on the PC.

### Port a Potty Assistant

The assistant starts minimized to an **Ask the assistant** button (it remembers if you open it). Minimizing turns the microphone off. It can answer questions about the selected log and the latest paired local helper scan. For example, it can explain why a scanned port is risky, identify what a listening service means, or suggest safe remediation steps.

- **Gemini** generates concise defensive explanations. Requests use the economical Flash Lite model by default, are limited to 300 words, and are rate-limited to five per minute per client.
- A built-in response keeps the demo useful if Gemini is unavailable or rate-limited; questions that mention a port (by number or name, such as "RDP") get that port's full lesson.
- **ElevenLabs** powers dictation, conversation-mode speech-to-text, and read-aloud responses through the selected ElevenLabs voice.

## Architecture

```text
Browser dashboard
  ├─ Flask app on Vercel
  │   ├─ simulated/uploaded log analysis
  │   ├─ Gemini assistant API
  │   ├─ ElevenLabs speech-to-text and text-to-speech API
  │   └─ helper enrollment and scan API
  └─ optional Windows / Mac helper
      └─ read-only local checks → authenticated Vercel API → Tiger Data
```

Tiger Data stores uploaded logs, the selected example log, alerts, helper enrollments, and the most recent local-device results. API keys and database credentials remain server-side; they are never sent to the browser.

## Running locally

Requirements: Python 3.12+ and PowerShell on Windows.

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e .
Copy-Item .env.example .env
.\.venv\Scripts\python app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000). For Gemini, ElevenLabs, and Tiger Data locally, fill the corresponding values in `.env`. Never commit that file.

## Building the helper EXE

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_helper.ps1
```

The build appears at `dist\Port-a-Potty-Helper.exe`. For the hosted app, users should download the scoped helper ZIP from the dashboard instead of manually configuring this developer build.

## Development checks

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

The test suite covers the detection rules, the example-log labeling, port lessons, macOS listener parsing and descriptions, the Windows and Mac helper packages (including running the Mac helper's checks on bare Python), helper authentication, Tiger-backed result retrieval contracts, and the assistant's paired-helper and port-lesson context.

## Safety boundaries

- The project is a **defensive demonstration**, not a network attack tool.
- It scans only the helper machine's localhost ports; the website never scans visitors' devices or networks.
- Uploaded logs are treated as data, not executable content.
- Local helper findings are display-only on the hosted dashboard.
- The assistant gives defensive explanations and remediation guidance only.
