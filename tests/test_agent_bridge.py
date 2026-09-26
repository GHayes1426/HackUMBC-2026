import os
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
