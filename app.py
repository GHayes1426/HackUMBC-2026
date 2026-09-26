"""
Flask backend for the Network Security Dashboard.

    GET /          -> runs every registered check, renders html/index.html
    GET /api/scan  -> same results as JSON (for scripts, JS refresh, PDF export)

This file should not need to change when checks are added; see
checks/__init__.py and checks/base.py.

Folders: templates live in html/ and static files in frontend/
(Flask's defaults would be templates/ and static/).
"""

from flask import Flask, jsonify, render_template

import checks  # noqa: F401  -- importing the package registers every check
from checks.base import run_all

app = Flask(
    __name__,
    template_folder="html",
    static_folder="frontend",
    static_url_path="/static",
)


@app.route("/")
def dashboard():
    return render_template("index.html", results=run_all())


@app.route("/api/scan")
def api_scan():
    return jsonify(run_all())


if __name__ == "__main__":
    # 127.0.0.1 only: the dashboard is never reachable from the network.
    app.run(host="127.0.0.1", port=5000, debug=True)
