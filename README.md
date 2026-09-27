# Port a Potty

Port a Potty is a defensive cybersecurity dashboard built for HackUMBC. It turns simulated security logs and optional local-device checks into plain-language findings, remediation guidance, and a voice-enabled assistant.

**Live app:** [hackumbc-portapotty.vercel.app](https://hackumbc-portapotty.vercel.app)

## What it does

### Simulated log analysis

The hosted dashboard starts with curated SSH-style demo logs and also accepts UTF-8 `.log` and `.txt` uploads up to 512 KB. It detects:

- **Brute-force attempts:** repeated failed logins from one source in a configurable time window.
- **Password spraying:** a small number of attempts against many accounts.
- **IOC/CVE context:** log findings are explained alongside a static, defensive port-to-CVE demonstration map.

Detection thresholds are editable in the **Detection thresholds** panel. The panel can collapse after setup while keeping the dashboard uncluttered.

### Local device helper

The website cannot safely inspect a visitor's PC by itself. The optional **Local device helper** runs on the user's Windows computer and uploads only read-only findings to the hosted dashboard:

1. **Local Port Assessor** checks commonly risky localhost ports.
2. **Listening Services** lists programs accepting connections and whether they are exposed to the network.
3. **System Hardening** reports the state of Windows protections such as the firewall, Microsoft Defender, BitLocker, and UAC.

Use **Download local helper** in the app. The site detects the browser platform and downloads either a Windows EXE or a macOS `.command` launcher. Extract the ZIP and open the helper. The package includes a unique, device-scoped enrollment token, so the user does not need Python, an API key, or a manual `.env` setup. Once the helper reports its first scan, the browser automatically shows the panels in this order:

1. Local Port Assessor
2. Listening Services
3. IOC / CVE Analyzer
4. System Hardening

The helper is deliberately one-way: the hosted app can display results, but it cannot run commands, alter firewall rules, or change settings on the PC.

### Port a Potty Assistant

The floating assistant can answer questions about the selected log and the latest paired local helper scan. For example, it can explain why a scanned port is risky, identify what a listening service means, or suggest safe remediation steps.

- **Gemini** generates concise defensive explanations. Requests use the economical Flash Lite model by default, are limited to 300 words, and are rate-limited to five per minute per client.
- A built-in rules-based response keeps the demo useful if Gemini is unavailable or rate-limited.
- **ElevenLabs** powers dictation, conversation-mode speech-to-text, and read-aloud responses through the selected ElevenLabs voice.

## Architecture

```text
Browser dashboard
  ├─ Flask app on Vercel
  │   ├─ simulated/uploaded log analysis
  │   ├─ Gemini assistant API
  │   ├─ ElevenLabs speech-to-text and text-to-speech API
  │   └─ helper enrollment and scan API
  └─ optional Windows helper
      └─ read-only local checks → authenticated Vercel API → Tiger Data
```

Tiger Data stores uploaded logs, threshold settings, alerts, helper enrollments, and the most recent local-device results. API keys and database credentials remain server-side; they are never sent to the browser.

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

The Windows build appears at `dist\Port-a-Potty-Helper.exe`. For the hosted app, users should download the scoped helper ZIP from the dashboard instead of manually configuring this developer build. On macOS, the dashboard ships a native `.command` helper that uses built-in macOS tools for the same read-only checks.

## Development checks

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

The test suite covers detection thresholds, helper authentication, helper package creation, Tiger-backed result retrieval contracts, and the assistant's paired-helper context.

## Safety boundaries

- The project is a **defensive demonstration**, not a network attack tool.
- It scans only the helper machine's localhost ports.
- Uploaded logs are treated as data, not executable content.
- Local helper findings are display-only on the hosted dashboard.
- The assistant gives defensive explanations and remediation guidance only.
