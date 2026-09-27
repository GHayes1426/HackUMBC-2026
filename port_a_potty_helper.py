"""Port a Potty's downloadable local-device helper.

This process runs three read-only checks on the computer where it is opened:
Local Port Assessor, Listening Services, and System Hardening. It sends their
display-only results to the hosted dashboard; it never accepts remote commands
and the hosted dashboard cannot change this computer's firewall or settings.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib import error, request
from uuid import uuid4

from dotenv import load_dotenv


CHECK_NAMES = {"Local Port Assessor", "Listening Services", "System Hardening"}


def app_directory() -> Path:
    """Use the EXE's folder when packaged and the repo root while developing."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_configuration() -> None:
    # A colocated helper .env is the explicit pairing configuration. Let it
    # win over an unrelated system environment variable left by another tool.
    load_dotenv(app_directory() / ".env", override=True)


def device_id() -> str:
    """Create a stable random pairing ID without collecting account details."""
    configured = os.environ.get("PORT_A_POTTY_DEVICE_ID", "").strip()
    if configured:
        return configured
    state_path = Path(os.environ.get("APPDATA", app_directory())) / "Port a Potty Helper" / "device_id.txt"
    try:
        if state_path.exists():
            value = state_path.read_text(encoding="utf-8").strip()
            if len(value) >= 20:
                return value
        state_path.parent.mkdir(parents=True, exist_ok=True)
        value = uuid4().hex
        state_path.write_text(value, encoding="utf-8")
        return value
    except OSError:
        # The helper can still work on a locked-down computer, but pairing will
        # use a new ID the next time it starts.
        return uuid4().hex


def local_results() -> list[dict[str, object]]:
    import checks  # noqa: F401 - registers checks
    from checks.base import run_all

    return [result for result in run_all() if result["name"] in CHECK_NAMES]


def upload_scan() -> str:
    load_configuration()
    base_url = os.environ.get("PORT_A_POTTY_API_URL", "").strip().rstrip("/")
    api_key = os.environ.get("PORT_A_POTTY_AGENT_KEY", "").strip()
    vercel_bypass = os.environ.get("PORT_A_POTTY_VERCEL_BYPASS_SECRET", "").strip()
    pairing_id = device_id()
    if not base_url or not api_key:
        raise RuntimeError(
            "Create a .env file beside this helper with PORT_A_POTTY_API_URL and PORT_A_POTTY_AGENT_KEY."
        )
    payload = json.dumps({
        "device_id": pairing_id,
        "hostname": socket.gethostname(),
        "results": local_results(),
    }).encode("utf-8")
    try:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        if vercel_bypass:
            # Supports Vercel Deployment Protection without putting a browser
            # cookie or the bypass value into the hosted page.
            headers["x-vercel-protection-bypass"] = vercel_bypass
        http_request = request.Request(
            f"{base_url}/api/agent/scan",
            data=payload,
            headers=headers,
            method="POST",
        )
        with request.urlopen(http_request, timeout=25) as response:
            if response.status not in {200, 201, 202}:
                raise RuntimeError(f"Server returned HTTP {response.status}.")
    except error.HTTPError as exc:
        raise RuntimeError(f"Server rejected the scan (HTTP {exc.code}). Check the helper key and deployment URL.") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Could not reach the hosted dashboard: {exc.reason}") from exc
    return pairing_id


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Port a Potty local checks and upload their display-only results.")
    parser.add_argument("--once", action="store_true", help="Run one scan and exit.")
    arguments = parser.parse_args()
    interval = max(15, int(os.environ.get("PORT_A_POTTY_HELPER_INTERVAL_SECONDS", "60")))
    print("Port a Potty Helper: local scans only; no remote commands are accepted.")
    while True:
        try:
            pairing_id = upload_scan()
            print(f"Uploaded local scan. Pair this browser with ID: {pairing_id}")
        except Exception as exc:
            print(f"Local scan was not uploaded: {exc}", file=sys.stderr)
            if arguments.once:
                return 1
        if arguments.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
