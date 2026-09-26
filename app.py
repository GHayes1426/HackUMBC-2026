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
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

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


@app.route("/")
def dashboard():
    results = run_all()
    record_scan(results)
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
    results = run_all()
    record_scan(results)
    return jsonify(
        results=results,
        summary=build_summary(results),
        detection_settings=asdict(load_detection_settings()),
    )


@app.get("/api/history")
def alert_history():
    """Recent Tiger Data findings for a future history view."""
    return jsonify(alerts=recent_alerts())


@app.route("/api/settings/detection", methods=["GET", "POST"])
def detection_settings():
    if request.method == "GET":
        return jsonify(asdict(load_detection_settings()))
    if request.host not in ALLOWED_HOSTS or request.headers.get("X-Dashboard") != "1":
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
    if request.host not in ALLOWED_HOSTS or request.headers.get("X-Dashboard") != "1":
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
    source = store_uploaded_log(name, text)
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
