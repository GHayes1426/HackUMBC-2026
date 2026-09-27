"""Double-click entry point for the packaged Port a Potty desktop app."""

from __future__ import annotations

from threading import Timer
import webbrowser

from app import app
from checks.port_control import DASHBOARD_PORT


def open_dashboard() -> None:
    webbrowser.open_new(f"http://127.0.0.1:{DASHBOARD_PORT}")


if __name__ == "__main__":
    Timer(0.8, open_dashboard).start()
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=False, use_reloader=False)
