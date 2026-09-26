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
import json
import os
from pathlib import Path
from urllib import parse, request as urlrequest
from uuid import uuid4

from flask import Flask, Response, abort, jsonify, render_template, request

import checks  # noqa: F401  -- importing the package registers every check
from checks.base import run_all
from checks.port_control import DASHBOARD_PORT, PortControlError, close_port, is_blocked, reopen_port
from checks.summary import build_summary
from checks.runtime_settings import load_detection_settings, save_detection_settings
from checks.demo_logs import load_log_source, log_sources, save_log_source, store_uploaded_log
from werkzeug.utils import secure_filename
from dawgwatch.settings import DetectionSettings
from dawgwatch.storage import recent_alerts, record_scan

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


def _settings_request_allowed() -> bool:
    """Accept same-origin dashboard writes in Vercel and local development."""
    return request.headers.get("X-Dashboard") == "1" and (HOSTED_MODE or request.host in ALLOWED_HOSTS)


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


@app.post("/api/assistant")
def assistant():
    """Gemini-backed security explanation; the browser never receives the API key."""
    payload = request.get_json(silent=True)
    question = payload.get("question", "") if isinstance(payload, dict) else ""
    if not isinstance(question, str) or not question.strip() or len(question) > 1200:
        return jsonify(error="Ask a short security question (up to 1,200 characters)."), 400
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return jsonify(error="Gemini is not configured on this deployment."), 503
    findings = [
        {"check": result["name"], "label": item["label"], "detail": item["detail"], "status": item["status"]}
        for result in current_results()
        for item in result.get("items", []) if item.get("status") in {"warning", "review"}
    ]
    prompt = (
        "You are Port a Potty, a defensive cybersecurity demo assistant. Explain findings plainly, "
        "avoid claiming certainty, and give safe remediation steps. Do not provide offensive instructions.\n"
        f"Current findings: {json.dumps(findings)}\nUser question: {question.strip()}"
    )
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
    # The ``-latest`` alias keeps the demo on the currently enabled Flash text
    # model for this API key. A deployment may override it without code changes.
    model = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{parse.quote(model, safe='-._')}:generateContent?key=" + parse.quote(api_key, safe="")
    try:
        response = urlrequest.urlopen(urlrequest.Request(endpoint, data=body, headers={"Content-Type": "application/json"}), timeout=20)
        data = json.load(response)
        answer = data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as exc:
        # Keep the key and prompt out of the response, but retain enough detail
        # in Vercel logs to diagnose provider configuration problems.
        app.logger.warning("Gemini request failed: %s", exc)
        return jsonify(error="Gemini could not generate an explanation right now."), 502
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
