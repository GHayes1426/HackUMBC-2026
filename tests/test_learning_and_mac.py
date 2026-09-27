"""Beginner-mode page, port lessons, Mac support and the Mac helper package."""

import ast
from collections import defaultdict, deque
import os
from io import BytesIO
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

os.environ.setdefault("PORT_A_POTTY_AGENT_KEY", "test-shared-helper-key")

from app import MAC_HELPER_FOLDER, app
from checks import ioc_analyzer, listeners, port_scan
from checks.base import run_all
from checks.device_guides import DEVICE_GUIDES
from checks.port_catalog import describe
from checks.port_lessons import PORT_LESSONS, lesson_for_label, lessons_in_text
from checks.signatures import CVE_PORT_MAP

ROOT = Path(__file__).resolve().parent.parent


def ioc_only(*_):
    return run_all({"IOC / CVE Analyzer"})


class BeginnerPageTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch("app.run_all", side_effect=ioc_only)
    def test_hosted_page_has_no_thresholds_and_labels_example_data(self, _):
        with patch("app.HOSTED_MODE", True), patch.object(ioc_analyzer, "HOSTED", True):
            page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("Detection thresholds", page)
        self.assertNotIn("brute_force_failures", page)
        self.assertIn("Static example file", page)
        self.assertIn("sample_auth.log", page)
        self.assertIn("It is not your device&#39;s log", page)
        self.assertIn("Check this device: no download", page)
        self.assertIn("Common ports explained", page)
        self.assertIn("WannaCry", page)
        self.assertIn('id="assistant-minimize"', page)
        self.assertIn("assistant-dock is-minimized", page)

    def test_threshold_settings_api_is_gone(self):
        response = self.client.post("/api/settings/detection", json={"brute_force_failures": 1},
                                    headers={"X-Dashboard": "1"})
        self.assertEqual(response.status_code, 404)

    def test_hosted_ioc_panel_does_not_scan_the_cloud_server(self):
        with patch.object(ioc_analyzer, "HOSTED", True), \
                patch.object(ioc_analyzer, "get_open_ports", side_effect=AssertionError("scanned")):
            result = ioc_analyzer.IOCAnalyzerCheck().run()
        self.assertFalse(any(item["label"].startswith("Port ") for item in result["items"]))
        self.assertIn("example log", result["summary"])
        self.assertFalse(result["example"]["uploaded"])
        self.assertIn("cloud server", result["note"])
        # The bundled example contains both attack types, explained in plain words.
        details = " ".join(item["detail"] for item in result["items"])
        self.assertIn("What it means", details)

    def test_detection_rules_are_fixed(self):
        from checks.runtime_settings import load_detection_settings
        self.assertEqual(load_detection_settings().brute_force_failures, 4)

    @patch("app.store_uploaded_log", return_value="upload:abc")
    def test_hosted_site_accepts_log_uploads(self, store):
        data = {"log_file": (BytesIO(b"Sep 26 03:14:07 host sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"), "mine.log")}
        with patch("app.HOSTED_MODE", True):
            response = self.client.post("/api/logs/upload", data=data, headers={"X-Dashboard": "1"},
                                        base_url="https://hackumbc-portapotty.vercel.app")
        self.assertEqual(response.status_code, 200)
        store.assert_called_once()

    def test_upload_still_requires_the_dashboard_header(self):
        data = {"log_file": (BytesIO(b"x\n"), "mine.log")}
        with patch("app.HOSTED_MODE", True):
            response = self.client.post("/api/logs/upload", data=data)
        self.assertEqual(response.status_code, 403)

    def test_assistant_fallback_teaches_the_port_asked_about(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}), patch("app.current_results", return_value=[]):
            response = self.client.post("/api/assistant", json={"question": "Why is port 445 dangerous?"})
        answer = response.get_json()["answer"]
        self.assertIn("WannaCry", answer)
        self.assertIn("How to protect yourself", answer)


class PortLessonTests(unittest.TestCase):
    def test_every_scanned_and_cve_port_has_a_complete_lesson(self):
        for port in set(port_scan.RISKY_PORTS) | set(CVE_PORT_MAP):
            lesson = PORT_LESSONS.get(port)
            self.assertIsNotNone(lesson, port)
            for field in ("name", "what", "how", "example", "analogy", "protect"):
                self.assertTrue(lesson[field].strip(), (port, field))

    def test_lessons_attach_to_port_findings_only(self):
        self.assertEqual(lesson_for_label("Port 3389 · RDP")["name"], "Remote Desktop (RDP)")
        self.assertEqual(lesson_for_label("Port 445: CVE-2017-0144"), PORT_LESSONS[445])
        self.assertIsNone(lesson_for_label("Firewall"))
        self.assertIsNone(lesson_for_label("Port 49664 · Windows internal service port"))

    def test_questions_find_ports_by_number_or_name(self):
        ports = [port for port, _ in lessons_in_text("Is RDP worse than port 23 or telnet?")]
        self.assertEqual(ports, [3389, 23])

    def test_device_guides_cover_phones_and_computers(self):
        self.assertEqual(set(DEVICE_GUIDES), {"ios", "android", "mac", "windows"})
        android = " ".join(step[2] for step in DEVICE_GUIDES["android"]["steps"])
        self.assertIn("5555", android)


LSOF_OUTPUT = "p101\ncControlCenter\nn*:5000\nn*:7000\np102\ncrapportd\nn*:49152\n"
NETSTAT_OUTPUT = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.5000                 *.*                    LISTEN
tcp46      0      0  *.445                  *.*                    LISTEN
tcp4       0      0  127.0.0.1.631          *.*                    LISTEN
tcp6       0      0  ::1.631                *.*                    LISTEN
tcp4       0      0  192.168.1.5.52000      17.1.1.1.443           ESTABLISHED
"""


def fake_mac_run(command, timeout=15):
    if command[0] == "lsof":
        return 0, LSOF_OUTPUT
    if command[0] == "netstat":
        return 0, NETSTAT_OUTPUT
    return None, ""


class MacSupportTests(unittest.TestCase):
    def setUp(self):
        listeners._cache.update(time=0.0, value=None)

    def tearDown(self):
        listeners._cache.update(time=0.0, value=None)

    def test_mac_listeners_use_full_names_and_include_system_services(self):
        with patch.object(listeners, "OS", "Darwin"), patch.object(listeners, "run", side_effect=fake_mac_run) as run:
            found = listeners.get_listeners()
        lsof_args = run.call_args_list[0].args[0]
        self.assertEqual(lsof_args[1:3], ["+c", "0"])
        self.assertTrue(found[("ControlCenter", 5000)])
        self.assertTrue(found[("?", 445)])           # root-owned File Sharing, seen via netstat
        self.assertFalse(found[("?", 631)])          # printing, local only
        self.assertNotIn(("?", 5000), found)         # already named by lsof
        self.assertNotIn(("?", 52000), found)        # not a listening socket

    def test_mac_programs_and_hidden_sharing_services_are_explained(self):
        self.assertTrue(describe("ControlCenter", 5000, "Darwin")["known"])
        sharing = describe("?", 445, "Darwin")
        self.assertTrue(sharing["known"])
        self.assertIn("System Settings > General > Sharing > File Sharing", sharing["advice"])
        self.assertEqual(describe("?", 445, "Windows")["name"], "SMB file sharing")
        self.assertEqual(describe("?", 61000, "Darwin")["name"], "Hidden system program")

    def test_mac_port_assessor_names_the_sharing_setting(self):
        with patch.object(port_scan, "get_open_ports", return_value={5900}), \
                patch.object(port_scan, "programs_on_port", return_value=["?"]), \
                patch.object(port_scan, "closed_ports", return_value=set()), \
                patch("checks.port_catalog.OS", "Darwin"):
            items = port_scan.PortScanCheck().run()["items"]
        vnc = next(item for item in items if item["label"].startswith("Port 5900"))
        self.assertEqual(vnc["status"], "review")
        self.assertIn("macOS Screen Sharing", vnc["detail"])
        self.assertNotIn("(?)", vnc["detail"])


class MacHelperPackageTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch("app.create_agent_enrollment", return_value=True)
    def test_mac_package_runs_the_three_checks_with_plain_python(self, _):
        with patch("app.HOSTED_MODE", True), patch("app._helper_package_requests", defaultdict(deque)):
            response = self.client.post("/api/agent/package?platform=mac", headers={"X-Dashboard": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{MAC_HELPER_FOLDER}.zip", response.headers["Content-Disposition"])
        with ZipFile(BytesIO(response.data)) as archive, TemporaryDirectory() as directory:
            names = set(archive.namelist())
            script = archive.getinfo(f"{MAC_HELPER_FOLDER}/Start Port a Potty Helper.command")
            self.assertEqual((script.external_attr >> 16) & 0o777, 0o755)
            self.assertIn(f"{MAC_HELPER_FOLDER}/.env", names)
            self.assertIn("PORT_A_POTTY_ENROLLMENT_TOKEN=", archive.read(f"{MAC_HELPER_FOLDER}/.env").decode())
            self.assertFalse(any("dawgwatch" in name or "ioc_analyzer" in name for name in names))
            archive.extractall(directory)
            helper_dir = Path(directory) / MAC_HELPER_FOLDER
            # Must import without the project's packages (dotenv, dawgwatch, Flask) on the path.
            code = ("import sys; sys.path[:0] = ['.']; import checks, port_a_potty_helper as h; "
                    "from checks.base import run_all; "
                    "print(sorted(r['name'] for r in run_all()))")
            result = subprocess.run([sys.executable, "-S", "-c", code], cwd=helper_dir,
                                    capture_output=True, text=True, timeout=120,
                                    env={**os.environ, "PYTHONPATH": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("['Listening Services', 'Local Port Assessor', 'System Hardening']", result.stdout)

    def test_mac_helper_sources_parse_on_macos_python_3_9(self):
        from app import MAC_HELPER_SOURCES
        for relative in MAC_HELPER_SOURCES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            ast.parse(source, filename=relative, feature_version=(3, 9))

    def test_unknown_platform_is_rejected(self):
        with patch("app.HOSTED_MODE", True):
            response = self.client.post("/api/agent/package?platform=linux", headers={"X-Dashboard": "1"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()


class SummaryAndListeningTests(unittest.TestCase):
    def test_summary_has_a_tile_for_each_section_on_the_website(self):
        from app import _summary_tiles
        with patch("app.HOSTED_MODE", True), patch.object(ioc_analyzer, "HOSTED", True):
            tiles = _summary_tiles(ioc_only())
        self.assertEqual([tile["name"] for tile in tiles],
                         ["Local Port Assessor", "Listening Services", "IOC / CVE Analyzer", "System Hardening"])
        self.assertEqual([tile["pending"] for tile in tiles], [True, True, False, True])
        self.assertEqual(tiles[2]["counts"]["warning"], 2)

    def test_listening_services_shows_its_ten_most_important_ports(self):
        from app import _display_items
        items = ([{"label": f"Port {n}", "status": "ok", "detail": ""} for n in range(20)]
                 + [{"label": "Port 9999", "status": "review", "detail": ""}])
        shown, hidden = _display_items({"name": "Listening Services", "items": items})
        self.assertEqual((len(shown), hidden), (10, 11))
        grouped, _ = _display_items({"name": "Listening Services", "items": [
            {"label": f"Port {n} · GlideXService", "status": "review", "detail": ""} for n in (49672, 49673)]})
        self.assertEqual([item["label"] for item in grouped], ["Ports 49672, 49673 · GlideXService"])
        self.assertEqual(shown[0]["label"], "Port 9999")
        shown, hidden = _display_items({"name": "Local Port Assessor", "items": items})
        self.assertEqual((len(shown), hidden), (21, 0))
