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
import ssl
import sys
import time
from pathlib import Path
from urllib import error, request
from uuid import uuid4


CHECK_NAMES = {"Local Port Assessor", "Listening Services", "System Hardening"}


def app_directory() -> Path:
    """Use the EXE's folder when packaged and the repo root while developing."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_configuration() -> None:
    # A colocated helper .env is the explicit pairing configuration. Let it
    # win over an unrelated system environment variable left by another tool.
    path = app_directory() / ".env"
    try:
        from dotenv import load_dotenv
    except ImportError:
        # The Mac package runs on the Python that ships with macOS, which has
        # no python-dotenv; its .env is simple KEY=value lines.
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines:
            key, sep, value = line.strip().partition("=")
            if sep and key and not key.startswith("#"):
                os.environ[key.strip()] = value.strip().strip("\"'")
        return
    load_dotenv(path, override=True)


def state_directory() -> Path:
    """Where the pairing ID is remembered: %APPDATA% on Windows, Application Support on a Mac."""
    if os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"])
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    return app_directory()


def https_context() -> ssl.SSLContext:
    """Verify HTTPS certificates, even on Mac Pythons that ship without a CA bundle."""
    context = ssl.create_default_context()
    if not context.cert_store_stats().get("x509_ca") and Path("/etc/ssl/cert.pem").is_file():
        context.load_verify_locations("/etc/ssl/cert.pem")
    return context


def device_id() -> str:
    """Create a stable random pairing ID without collecting account details."""
    configured = os.environ.get("PORT_A_POTTY_DEVICE_ID", "").strip()
    if configured:
        return configured
    state_path = state_directory() / "Port a Potty Helper" / "device_id.txt"
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

    return run_all(CHECK_NAMES)


def upload_scan() -> str:
    load_configuration()
    base_url = os.environ.get("PORT_A_POTTY_API_URL", "").strip().rstrip("/")
    # Downloaded packages use their own device-scoped enrollment token. The
    # legacy shared key remains useful for a developer's local checkout.
    api_key = os.environ.get("PORT_A_POTTY_ENROLLMENT_TOKEN", "").strip() or os.environ.get("PORT_A_POTTY_AGENT_KEY", "").strip()
    vercel_bypass = os.environ.get("PORT_A_POTTY_VERCEL_BYPASS_SECRET", "").strip()
    pairing_id = device_id()
    if not base_url or not api_key:
        raise RuntimeError(
            "This helper is missing its package configuration. Download a fresh helper ZIP from Port a Potty."
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
        with request.urlopen(http_request, timeout=25, context=https_context()) as response:
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
