"""
Flask backend for Port a Potty.

    GET  /                          -> runs every check, renders html/index.html
    GET  /api/scan                  -> same results (plus summary) as JSON
    POST /api/ports/<port>/close    -> firewall-block a port (checks/port_control.py)
    POST /api/ports/<port>/reopen   -> remove that block

This file should not need to change when checks are added; see
checks/__init__.py and checks/base.py.

Folders: templates live in html/ and static files in frontend/
(Flask's defaults would be templates/ and static/).
"""

from dataclasses import asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
import json
import os
import re
import hmac
import secrets
from threading import Lock
from time import monotonic
from pathlib import Path
from urllib import parse, request as urlrequest
from urllib.error import HTTPError
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from flask import Flask, Response, abort, jsonify, render_template, request

import checks  # noqa: F401  -- importing the package registers every check
from checks.base import run_all
from checks.port_control import DASHBOARD_PORT, PortControlError, close_port, is_blocked, reopen_port
from checks.summary import build_summary
from checks.runtime_settings import load_detection_settings, save_detection_settings
from checks.demo_logs import load_log_source, log_sources, save_log_source, store_uploaded_log
from werkzeug.utils import secure_filename
from dawgwatch.settings import DetectionSettings
from dawgwatch.storage import (
    claim_agent_enrollment,
    create_agent_enrollment,
    latest_agent_scan,
    latest_agent_scan_for_package,
    recent_alerts,
    record_agent_scan,
    record_scan,
)

app = Flask(
    __name__,
    template_folder="html",
    static_folder="frontend",
    static_url_path="/static",
)

# The port routes change the firewall, so only this page may call them:
# the Host check stops DNS-rebinding sites, and the custom header can't be
# sent cross-origin without a CORS preflight, which Flask never approves.
ALLOWED_HOSTS = {f"127.0.0.1:{DASHBOARD_PORT}", f"localhost:{DASHBOARD_PORT}"}
HOSTED_MODE = bool(os.environ.get("VERCEL")) or os.environ.get("PORT_A_POTTY_HOSTED") == "1"
GEMINI_REQUEST_LIMIT = 5
GEMINI_WINDOW_SECONDS = 60
_gemini_requests: dict[str, deque[float]] = defaultdict(deque)
_gemini_request_lock = Lock()
AGENT_CHECK_NAMES = {"Local Port Assessor", "Listening Services", "System Hardening"}
DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
PACKAGE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
HELPER_PACKAGE_LIMIT = 5
_helper_package_requests: dict[str, deque[float]] = defaultdict(deque)
_helper_package_lock = Lock()
HELPER_EXE = Path(__file__).resolve().parent / "helper_package" / "Port-a-Potty-Helper.exe"
HELPER_MACOS_COMMAND = Path(__file__).resolve().parent / "helper_package" / "Port-a-Potty-Helper.command"


def _settings_request_allowed() -> bool:
    """Accept same-origin dashboard writes in Vercel and local development."""
    return request.headers.get("X-Dashboard") == "1" and (HOSTED_MODE or request.host in ALLOWED_HOSTS)


def _gemini_request_allowed() -> bool:
    """Allow at most five upstream Gemini calls per client per rolling minute."""
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",", 1)[0].strip()
    now = monotonic()
    with _gemini_request_lock:
        calls = _gemini_requests[client]
        while calls and now - calls[0] >= GEMINI_WINDOW_SECONDS:
            calls.popleft()
        if len(calls) >= GEMINI_REQUEST_LIMIT:
            return False
        calls.append(now)
        return True


def _agent_request_allowed() -> bool:
    """Authenticate the local helper without exposing its key to browsers."""
    expected = os.environ.get("PORT_A_POTTY_AGENT_KEY", "")
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        supplied = supplied[7:]
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _helper_package_request_allowed() -> bool:
    """Keep anonymous package creation from becoming an unbounded token mint."""
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",", 1)[0].strip()
    now = monotonic()
    with _helper_package_lock:
        calls = _helper_package_requests[client]
        while calls and now - calls[0] >= GEMINI_WINDOW_SECONDS:
            calls.popleft()
        if len(calls) >= HELPER_PACKAGE_LIMIT:
            return False
        calls.append(now)
        return True


def _agent_enrollment_request_allowed(device_id: str) -> bool:
    """Authorize an individual downloaded helper and bind it to one device."""
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        supplied = supplied[7:]
    if not supplied:
        return False
    if _agent_request_allowed():
        return True
    return claim_agent_enrollment(sha256(supplied.encode("utf-8")).hexdigest(), device_id) is not None


def _assistant_helper_context(payload: dict | None) -> list[dict[str, object]]:
    """Return a compact snapshot of the helper scan paired in this browser."""
    if not isinstance(payload, dict):
        return []
    package_id = payload.get("helper_package_id", "")
    device_id = payload.get("helper_device_id", "")
    scan = None
    if isinstance(package_id, str) and PACKAGE_ID_PATTERN.fullmatch(package_id):
        scan = latest_agent_scan_for_package(package_id)
    elif isinstance(device_id, str) and DEVICE_ID_PATTERN.fullmatch(device_id):
        scan = latest_agent_scan(device_id)
    if not scan:
        return []
    context = []
    remaining_items = 40
    for result in scan.get("results", []):
        if result.get("name") not in AGENT_CHECK_NAMES or remaining_items <= 0:
            continue
        items = []
        for item in result.get("items", []):
            if not isinstance(item, dict) or remaining_items <= 0:
                continue
            items.append({
                "label": str(item.get("label", ""))[:300],
                "status": str(item.get("status", "error")),
                "detail": str(item.get("detail", ""))[:800],
            })
            remaining_items -= 1
        context.append({
            "check": result.get("name"),
            "status": result.get("status"),
            "summary": str(result.get("summary", ""))[:500],
            "items": items,
        })
    return context


def _safe_agent_results(value) -> list[dict[str, object]] | None:
    """Accept only the read-only result shape rendered by the hosted dashboard."""
    if not isinstance(value, list) or len(value) > 12:
        return None
    cleaned = []
    for result in value:
        if not isinstance(result, dict) or result.get("name") not in AGENT_CHECK_NAMES:
            return None
        name = result["name"]
        description = result.get("description", "")
        summary = result.get("summary", "")
        status = result.get("status", "error")
        items = result.get("items", [])
        if not all(isinstance(text, str) and len(text) <= 2000 for text in (description, summary)):
            return None
        if status not in {"warning", "review", "info", "ok", "error"} or not isinstance(items, list) or len(items) > 100:
            return None
        safe_items = []
        for item in items:
            if not isinstance(item, dict):
                return None
            label, detail, item_status = item.get("label", ""), item.get("detail", ""), item.get("status", "error")
            if (not isinstance(label, str) or not isinstance(detail, str) or len(label) > 500 or len(detail) > 4000
                    or item_status not in {"warning", "review", "info", "ok", "error"}):
                return None
            # Deliberately do not accept local firewall action metadata. The
            # hosted dashboard is observational and cannot change this PC.
            safe_items.append({"label": label, "detail": detail, "status": item_status})
        cleaned.append({"name": name, "description": description, "summary": summary, "status": status, "items": safe_items})
    return cleaned


def _built_in_explanation(findings: list[dict[str, str]], reason: str) -> str:
    """Keep the demo useful if an AI provider is unavailable or rate-limited."""
    parts = [f"Built-in analysis: {reason}"]
    labels = {item["label"] for item in findings}
    if "Possible brute-force login activity" in labels:
        parts.append("Brute-force activity means one source made repeated failed sign-in attempts against an account in a short time. Verify there were no successful logins, block unexpected sources, disable direct root login, and prefer SSH keys.")
    if "Possible password-spraying activity" in labels:
        parts.append("Password spraying means one source tried a small number of passwords across many accounts. Review affected accounts, enforce strong unique passwords and MFA, and add sign-in rate limiting.")
    if not findings:
        parts.append("No current warning or review findings are present in the selected log. Continue monitoring and keep authentication controls enabled.")
    parts.append("This is a simulated-log assessment, so treat it as a demonstration of the recommended investigation steps rather than proof of a live attack.")
    return "\n\n".join(parts)


def current_results():
    """Run local checks, keeping cloud deployments focused on uploaded/demo logs."""
    results = run_all()
    if HOSTED_MODE:
        results = [result for result in results if result["name"] == "IOC / CVE Analyzer"]
    record_scan(results, host="vercel" if HOSTED_MODE else "local")
    return results


@app.route("/")
def dashboard():
    results = current_results()
    return render_template(
        "index.html",
        results=results,
        summary=build_summary(results),
        detection_settings=asdict(load_detection_settings()),
        log_sources=log_sources(),
        selected_log_source=load_log_source(),
    )


@app.route("/api/scan")
def api_scan():
    results = current_results()
    return jsonify(
        results=results,
        summary=build_summary(results),
        detection_settings=asdict(load_detection_settings()),
    )


@app.get("/api/history")
def alert_history():
    """Recent Tiger Data findings for a future history view."""
    return jsonify(alerts=recent_alerts())


@app.post("/api/agent/scan")
def agent_scan_upload():
    """Receive a read-only local scan from the downloadable desktop helper."""
    if not os.environ.get("PORT_A_POTTY_AGENT_KEY"):
        return jsonify(error="The local helper has not been configured on this deployment."), 503
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) and request.form:
        raw_results = request.form.get("results", "")
        try:
            parsed_results = json.loads(raw_results)
        except (TypeError, ValueError):
            parsed_results = None
        payload = {
            "device_id": request.form.get("device_id", ""),
            "hostname": request.form.get("hostname", ""),
            "results": parsed_results,
        }
    if not isinstance(payload, dict):
        return jsonify(error="Expected a JSON scan payload."), 400
    device_id = payload.get("device_id", "")
    hostname = payload.get("hostname", "")
    results = _safe_agent_results(payload.get("results"))
    if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
        return jsonify(error="Invalid helper pairing ID."), 400
    if not _agent_enrollment_request_allowed(device_id):
        return jsonify(error="The local helper key was rejected."), 401
    if not isinstance(hostname, str) or not hostname.strip() or len(hostname) > 255:
        return jsonify(error="Invalid helper computer name."), 400
    if results is None:
        return jsonify(error="Invalid local scan results."), 400
    if not record_agent_scan(device_id, hostname.strip(), results):
        return jsonify(error="Tiger Data could not save this local scan."), 503
    return jsonify(saved=True), 202


@app.get("/api/agent/scan/<device_id>")
def agent_scan_latest(device_id: str):
    """Get the newest result after the user has paired this browser to a helper."""
    if not DEVICE_ID_PATTERN.fullmatch(device_id):
        abort(404)
    scan = latest_agent_scan(device_id)
    if scan is None:
        return jsonify(error="No local scan received yet. Run the Port a Potty Helper and try again."), 404
    return jsonify(scan)


@app.post("/api/agent/package")
def agent_helper_package():
    """Issue a ready-to-run Windows helper package with a scoped enrollment token."""
    if not _settings_request_allowed():
        abort(403)
    if not _helper_package_request_allowed():
        return jsonify(error="Please wait a minute before creating another helper package."), 429
    requested = request.get_json(silent=True) or {}
    platform = requested.get("platform") if isinstance(requested, dict) else None
    is_macos = platform == "macos"
    helper_file = HELPER_MACOS_COMMAND if is_macos else HELPER_EXE
    helper_name = "Port-a-Potty-Helper.command" if is_macos else "Port-a-Potty-Helper.exe"
    if not helper_file.is_file():
        return jsonify(error=f"The {'macOS' if is_macos else 'Windows'} helper package is being prepared. Try again shortly."), 503
    package_id = secrets.token_urlsafe(24)
    enrollment_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    if not create_agent_enrollment(package_id, sha256(enrollment_token.encode("utf-8")).hexdigest(), expires_at):
        return jsonify(error="Tiger Data could not create the helper package."), 503
    public_url = os.environ.get("PORT_A_POTTY_PUBLIC_URL", request.url_root.rstrip("/"))
    config = "\n".join((
        f"PORT_A_POTTY_API_URL={public_url.rstrip('/')}",
        f"PORT_A_POTTY_ENROLLMENT_TOKEN={enrollment_token}",
        "PORT_A_POTTY_HELPER_INTERVAL_SECONDS=60",
        "",
    ))
    launch_instruction = "Double-click Port-a-Potty-Helper.command. If macOS warns about an unidentified developer, Control-click it and choose Open." if is_macos else "Double-click Port-a-Potty-Helper.exe."
    readme = (
        "Port a Potty Local Helper\r\n\r\n"
        "1. Extract this ZIP.\r\n"
        f"2. {launch_instruction}\r\n"
        "3. Keep its window open while you use the hosted dashboard.\r\n\r\n"
        "No Python, API keys, or other setup is required. This package's .env contains a\r\n"
        "device-scoped enrollment token. Keep the files together and do not share the .env.\r\n"
    )
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zip_file:
        if is_macos:
            command_info = ZipInfo(helper_name)
            command_info.create_system = 3  # Unix permissions are meaningful on macOS.
            command_info.external_attr = 0o100755 << 16
            zip_file.writestr(command_info, helper_file.read_bytes(), compress_type=ZIP_DEFLATED)
        else:
            zip_file.write(helper_file, helper_name)
        zip_file.writestr(".env", config)
        zip_file.writestr("START-HERE.txt", readme)
    archive.seek(0)
    return Response(
        archive.getvalue(),
        mimetype="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=Port-a-Potty-Local-Helper-{'macOS' if is_macos else 'Windows'}.zip",
            "Cache-Control": "no-store",
            "X-Port-A-Potty-Package-ID": package_id,
        },
    )


@app.get("/api/agent/package/<package_id>")
def agent_package_latest(package_id: str):
    """Let the browser that downloaded a package follow its paired helper automatically."""
    if not PACKAGE_ID_PATTERN.fullmatch(package_id):
        abort(404)
    scan = latest_agent_scan_for_package(package_id)
    if scan is None:
        return jsonify(error="The downloaded helper has not reported a scan yet. Extract the ZIP and run the EXE."), 404
    return jsonify(scan)


@app.post("/api/assistant")
def assistant():
    """Gemini-backed security explanation; the browser never receives the API key."""
    payload = request.get_json(silent=True)
    question = payload.get("question", "") if isinstance(payload, dict) else ""
    if not isinstance(question, str) or not question.strip() or len(question) > 1200:
        return jsonify(error="Ask a short security question (up to 1,200 characters)."), 400
    findings = [
        {"check": result["name"], "label": item["label"], "detail": item["detail"], "status": item["status"]}
        for result in current_results()
        for item in result.get("items", []) if item.get("status") in {"warning", "review"}
    ]
    helper_context = _assistant_helper_context(payload)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return jsonify(answer=_built_in_explanation(findings, "Gemini is not configured."), fallback=True)
    prompt = (
        "You are Port a Potty, a defensive cybersecurity demo assistant. Explain findings plainly, "
        "avoid claiming certainty, and give safe remediation steps. Do not provide offensive instructions.\n"
        "Use plain text only: no Markdown headings, asterisks, backticks, or hash symbols. "
        "Use short paragraphs and simple numbered steps when useful. Keep the response below 300 words.\n"
        f"Current log findings: {json.dumps(findings)}\n"
        f"Latest paired local helper scan (ports, services, and hardening): {json.dumps(helper_context)}\n"
        "When asked about ports, services, or hardening, answer from the paired local helper scan when present. "
        "If it is absent, say that no local helper data is paired instead of guessing.\n"
        f"User question: {question.strip()}"
    )
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 450},
    }).encode()
    # Flash Lite is the economical default. The general Flash alias is a
    # fallback if the Lite endpoint is temporarily unavailable.
    models = [os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite"), "gemini-flash-latest"]
    try:
        answer = None
        for model in dict.fromkeys(models):
            if not _gemini_request_allowed():
                return jsonify(answer=_built_in_explanation(findings, "Gemini is limited to five requests per minute."), fallback=True)
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{parse.quote(model, safe='-._')}:generateContent?key=" + parse.quote(api_key, safe="")
            try:
                with urlrequest.urlopen(urlrequest.Request(endpoint, data=body, headers={"Content-Type": "application/json"}), timeout=20) as response:
                    data = json.load(response)
                    answer = data["candidates"][0]["content"]["parts"][0]["text"]
                    # Keep the browser's text-only message display clean even if
                    # a model returns a few Markdown markers despite the prompt.
                    answer = re.sub(r"(?m)^#{1,6}\s*", "", answer)
                    answer = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", answer)
                    answer = re.sub(r"(?m)^\s*[-*]\s+", "• ", answer)
                    words = answer.split()
                    answer = " ".join(words[:300])
                    break
            except HTTPError as exc:
                provider_detail = exc.read().decode("utf-8", errors="replace")[:500]
                app.logger.warning("Gemini model %s failed with HTTP %s: %s", model, exc.code, provider_detail)
                if exc.code not in {429, 503}:
                    raise
        if not answer:
            raise RuntimeError("All configured Gemini models were unavailable")
    except Exception as exc:
        # Keep the key and prompt out of the response, but retain enough detail
        # in Vercel logs to diagnose provider configuration problems.
        app.logger.warning("Gemini request failed: %s", exc)
        return jsonify(answer=_built_in_explanation(findings, "Gemini is temporarily unavailable."), fallback=True)
    return jsonify(answer=answer)


@app.post("/api/assistant/speak")
def assistant_speak():
    """Return ElevenLabs speech without exposing the API key or voice ID."""
    payload = request.get_json(silent=True)
    text = payload.get("text", "") if isinstance(payload, dict) else ""
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        return jsonify(error="ElevenLabs voice is not configured on this deployment."), 503
    if not isinstance(text, str) or not text.strip() or len(text) > 5000:
        return jsonify(error="Speech text must be between 1 and 5,000 characters."), 400
    try:
        eleven_request = urlrequest.Request(
            f"https://api.elevenlabs.io/v1/text-to-speech/{parse.quote(voice_id, safe='')}",
            data=json.dumps({"text": text.strip(), "model_id": "eleven_multilingual_v2"}).encode(),
            headers={"Content-Type": "application/json", "xi-api-key": api_key, "Accept": "audio/mpeg"},
        )
        with urlrequest.urlopen(eleven_request, timeout=30) as eleven_response:
            audio = eleven_response.read()
    except Exception as exc:
        app.logger.warning("ElevenLabs speech request failed: %s", exc)
        return jsonify(error="ElevenLabs could not generate speech right now."), 502
    return Response(audio, mimetype="audio/mpeg", headers={"Cache-Control": "no-store"})


@app.post("/api/assistant/transcribe")
def assistant_transcribe():
    """Transcribe a short microphone recording through ElevenLabs Scribe."""
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    audio = request.files.get("audio")
    if not api_key:
        return jsonify(error="ElevenLabs speech-to-text is not configured on this deployment."), 503
    if audio is None or not audio.filename:
        return jsonify(error="Record a short audio clip first."), 400
    audio_bytes = audio.read(10 * 1024 * 1024 + 1)
    if not audio_bytes or len(audio_bytes) > 10 * 1024 * 1024:
        return jsonify(error="Audio recordings must be between 1 byte and 10 MB."), 400
    boundary = f"----PortAPotty{uuid4().hex}"
    content_type = audio.mimetype or "audio/webm"
    body = b"".join((
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"model_id\"\r\n\r\nscribe_v2\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{secure_filename(audio.filename) or 'recording.webm'}\"\r\nContent-Type: {content_type}\r\n\r\n".encode(),
        audio_bytes,
        f"\r\n--{boundary}--\r\n".encode(),
    ))
    try:
        eleven_request = urlrequest.Request(
            "https://api.elevenlabs.io/v1/speech-to-text",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "xi-api-key": api_key},
        )
        with urlrequest.urlopen(eleven_request, timeout=45) as eleven_response:
            transcript = json.load(eleven_response).get("text", "").strip()
    except Exception as exc:
        app.logger.warning("ElevenLabs transcription request failed: %s", exc)
        return jsonify(error="ElevenLabs could not transcribe that recording right now."), 502
    if not transcript:
        return jsonify(error="No speech was detected in that recording."), 422
    return jsonify(text=transcript)


@app.route("/api/settings/detection", methods=["GET", "POST"])
def detection_settings():
    if request.method == "GET":
        return jsonify(asdict(load_detection_settings()))
    if not _settings_request_allowed():
        abort(403)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Expected a JSON object."), 400
    try:
        settings = DetectionSettings(**payload)
    except (TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400
    save_detection_settings(settings)
    return jsonify(asdict(settings))


@app.post("/api/settings/log-source")
def log_source():
    if not _settings_request_allowed():
        abort(403)
    payload = request.get_json(silent=True)
    source = payload.get("source") if isinstance(payload, dict) else None
    try:
        save_log_source(source)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(source=source)


@app.post("/api/logs/upload")
def upload_log():
    if request.host not in ALLOWED_HOSTS or request.headers.get("X-Dashboard") != "1":
        abort(403)
    uploaded = request.files.get("log_file")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Choose a .log or .txt file first."), 400
    name = secure_filename(uploaded.filename)
    if not name or Path(name).suffix.lower() not in {".log", ".txt"}:
        return jsonify(error="Only .log and .txt files are supported."), 400
    content = uploaded.read(512 * 1024 + 1)
    if len(content) > 512 * 1024:
        return jsonify(error="Log files must be 512 KB or smaller."), 400
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return jsonify(error="The log must be UTF-8 text."), 400
    try:
        source = store_uploaded_log(name, text)
    except ValueError as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(source=source, name=name)


@app.post("/api/ports/<int:port>/<any(close, reopen):action>")
def port_action(port, action):
    if request.host not in ALLOWED_HOSTS or request.headers.get("X-Dashboard") != "1":
        abort(403)
    try:
        (close_port if action == "close" else reopen_port)(port)
    except PortControlError as exc:
        return jsonify(error=str(exc)), 400

    # Tell the user whether the change actually took effect.
    blocked = is_blocked(port)
    if action == "close" and not blocked:
        level = "warning"
        message = (f"The firewall rule was added, but port {port} is still accepting connections. "
                   "Try Reopen, then Close again, or stop the program using the port.")
    elif action == "close":
        level, message = "success", f"Port {port} closed. Use Reopen if something stops working."
    else:
        level, message = "success", f"Port {port} reopened."
    return jsonify(port=port, action=action, blocked=blocked, level=level, message=message)


if __name__ == "__main__":
    # 127.0.0.1 only: the dashboard is never reachable from the network.
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=True)
