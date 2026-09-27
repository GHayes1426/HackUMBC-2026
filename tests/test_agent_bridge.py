import os
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

os.environ["PORT_A_POTTY_AGENT_KEY"] = "test-shared-helper-key"

from app import app


PAYLOAD = {
    "device_id": "localhelperdeviceid12345",
    "hostname": "judge-pc",
    "results": [{
        "name": "Local Port Assessor",
        "description": "Checks local ports",
        "status": "ok",
        "summary": "No risky ports",
        "items": [{"label": "Port 23", "status": "ok", "detail": "Closed"}],
    }],
}


class LocalHelperBridgeTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_helper_requires_shared_key(self):
        response = self.client.post("/api/agent/scan", json=PAYLOAD)
        self.assertEqual(response.status_code, 401)

    @patch("app.record_agent_scan", return_value=True)
    def test_helper_stores_read_only_local_result(self, store):
        response = self.client.post(
            "/api/agent/scan", json=PAYLOAD,
            headers={"Authorization": "Bearer test-shared-helper-key"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.get_json()["saved"])
        stored = store.call_args.args[2]
        self.assertNotIn("action", stored[0]["items"][0])

    @patch("app.latest_agent_scan")
    def test_browser_gets_latest_paired_result(self, latest):
        latest.return_value = {"device_id": PAYLOAD["device_id"], "hostname": "judge-pc", "observed_at": "2026-09-26T00:00:00+00:00", "results": PAYLOAD["results"]}
        response = self.client.get(f"/api/agent/scan/{PAYLOAD['device_id']}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["hostname"], "judge-pc")

    @patch("app.latest_agent_scan_for_package")
    def test_assistant_context_uses_paired_helper_scan(self, latest):
        latest.return_value = {
            "results": [{
                "name": "Local Port Assessor", "status": "warning", "summary": "One risky port open",
                "items": [{"label": "Port 3389 · RDP", "status": "warning", "detail": "Open to the network."}],
            }],
        }
        from app import _assistant_helper_context
        context = _assistant_helper_context({"helper_package_id": "packageidentifier1234567890"})
        self.assertEqual(context[0]["check"], "Local Port Assessor")
        self.assertEqual(context[0]["items"][0]["label"], "Port 3389 · RDP")

    @patch("app.create_agent_enrollment", return_value=True)
    def test_download_package_contains_only_scoped_connection_config(self, enrollment):
        with TemporaryDirectory() as directory:
            helper = os.path.join(directory, "Port-a-Potty-Helper.exe")
            with open(helper, "wb") as file:
                file.write(b"not-a-real-exe")
            with patch("app.HOSTED_MODE", True), patch("app.HELPER_EXE", Path(helper)):
                response = self.client.post("/api/agent/package", headers={"X-Dashboard": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/zip")
        self.assertTrue(response.headers["X-Port-A-Potty-Package-ID"])
        with ZipFile(BytesIO(response.data)) as archive:
            self.assertEqual(set(archive.namelist()), {"Port-a-Potty-Helper.exe", ".env", "START-HERE.txt"})
            config = archive.read(".env").decode()
        self.assertIn("PORT_A_POTTY_ENROLLMENT_TOKEN=", config)
        self.assertNotIn("GEMINI", config)
        self.assertNotIn("ELEVENLABS", config)

    @patch("app.create_agent_enrollment", return_value=True)
    def test_macos_download_uses_executable_command_file(self, enrollment):
        with TemporaryDirectory() as directory:
            helper = Path(directory) / "Port-a-Potty-Helper.command"
            helper.write_text("#!/bin/zsh\necho helper\n", encoding="utf-8")
            with patch("app.HOSTED_MODE", True), patch("app.HELPER_MACOS_COMMAND", helper):
                response = self.client.post(
                    "/api/agent/package", json={"platform": "macos"}, headers={"X-Dashboard": "1"}
                )
        self.assertEqual(response.status_code, 200)
        self.assertIn("macOS", response.headers["Content-Disposition"])
        with ZipFile(BytesIO(response.data)) as archive:
            info = archive.getinfo("Port-a-Potty-Helper.command")
            self.assertEqual((info.external_attr >> 16) & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
