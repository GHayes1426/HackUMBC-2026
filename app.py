"""
Flask backend for the Network Security Dashboard.

    GET  /                          -> runs every check, renders html/index.html
    GET  /api/scan                  -> same results (plus summary) as JSON
    POST /api/ports/<port>/close    -> firewall-block a port (checks/port_control.py)
    POST /api/ports/<port>/reopen   -> remove that block

This file should not need to change when checks are added; see
checks/__init__.py and checks/base.py.

Folders: templates live in html/ and static files in frontend/
(Flask's defaults would be templates/ and static/).
"""

from flask import Flask, abort, jsonify, render_template, request

import checks  # noqa: F401  -- importing the package registers every check
from checks.base import run_all
from checks.port_control import DASHBOARD_PORT, PortControlError, close_port, reopen_port
from checks.port_scan import get_open_ports
from checks.summary import build_summary

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
    return render_template("index.html", results=results, summary=build_summary(results))


@app.route("/api/scan")
def api_scan():
    results = run_all()
    return jsonify(results=results, summary=build_summary(results))


@app.post("/api/ports/<int:port>/<any(close, reopen):action>")
def port_action(port, action):
    if request.host not in ALLOWED_HOSTS or request.headers.get("X-Dashboard") != "1":
        abort(403)
    try:
        (close_port if action == "close" else reopen_port)(port)
    except PortControlError as exc:
        return jsonify(error=str(exc)), 400

    # Re-scan so the user is told whether the change actually took effect.
    still_open = port in get_open_ports([port])
    if action == "close" and still_open:
        level = "warning"
        message = (f"The firewall rule was added, but port {port} is still accepting connections. "
                   "Try Reopen, then Close again, or stop the program using the port.")
    elif action == "close":
        level, message = "success", f"Port {port} closed. Use Reopen if something stops working."
    else:
        level, message = "success", f"Port {port} reopened."
    return jsonify(port=port, action=action, open=still_open, level=level, message=message)


if __name__ == "__main__":
    # 127.0.0.1 only: the dashboard is never reachable from the network.
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=True)
