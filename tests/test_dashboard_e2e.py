from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import importlib.util
from pathlib import Path
import tempfile
import threading
import time
import unittest

from fastapi.testclient import TestClient

from examples.test_app import Handler
from sentinel_ai.api import create_app


@unittest.skipUnless(importlib.util.find_spec("playwright"), "requires Playwright and installed Chromium")
class DashboardEndToEndTests(unittest.TestCase):
    def test_authorize_validate_scan_live_findings_and_download_reports(self):
        temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(temp.cleanup)
        app = create_app(Path(temp.name), bootstrap_token="end-to-end-bootstrap-token", start_worker=False)
        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        fixture_thread.start()
        self.addCleanup(fixture.server_close)
        self.addCleanup(fixture_thread.join, 2)
        self.addCleanup(fixture.shutdown)
        base_url = f"http://127.0.0.1:{fixture.server_address[1]}/"
        with TestClient(app) as client:
            setup = client.post("/api/auth/setup", json={
                "bootstrap_token":"end-to-end-bootstrap-token", "organization_name":"Fixture Workspace",
                "email":"e2e@example.test", "password":"another-long-test-password-2026",
            })
            self.assertEqual(setup.status_code, 200, setup.text)
            headers = {"X-CSRF-Token":setup.json()["csrf_token"]}
            target = client.post("/api/targets", headers=headers, json={
                "name":"Local test fixture", "base_url":base_url, "authorized_by":"Fixture owner",
                "authorization_reference":"E2E-LOCAL-ONLY", "expires_at":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                "documented_authorization":True, "allow_loopback":True,
            })
            self.assertEqual(target.status_code, 200, target.text)
            target_id = target.json()["id"]
            probe = client.post("/api/targets/validate", json={"url":base_url,"target_id":target_id})
            self.assertEqual(probe.json()["state"], "reachable", probe.text)

            app.state.manager.start()
            self.addCleanup(app.state.manager.shutdown)
            created = client.post("/api/scans", headers=headers, json={
                "target_id":target_id, "target_url":base_url,
                "selected_checks":["passive_transport","passive_forms","browser_discovery"],
                "headless":True, "capture_screenshots":True, "ai_analysis":False,
                "limits":{"max_pages":2,"max_depth":1,"max_requests":100,"max_duration_seconds":30,
                          "request_delay_seconds":0,"navigation_delay_seconds":0,"navigation_timeout_ms":8000},
            })
            self.assertEqual(created.status_code, 200, created.text)
            scan_id = created.json()["id"]
            deadline = time.monotonic() + 25
            status = "queued"
            while time.monotonic() < deadline:
                status = client.get(f"/api/scans/{scan_id}").json()["status"]
                if status in {"completed","failed","cancelled"}:
                    break
                time.sleep(0.15)
            self.assertEqual(status,"completed",client.get(f"/api/scans/{scan_id}").text)
            detail = client.get(f"/api/scans/{scan_id}").json()
            self.assertGreaterEqual(detail["pages_count"],1)
            self.assertGreaterEqual(detail["requests_count"],1)
            self.assertTrue(any(event["event"]=="page_observed" for event in detail["events"]))
            findings = client.get(f"/api/findings?scan_id={scan_id}").json()
            self.assertTrue(findings)
            self.assertTrue(any(finding["id"].startswith(scan_id+":") for finding in findings))
            screenshot = next(event["details"]["screenshot"] for event in detail["events"] if event["event"]=="page_observed" and event["details"].get("screenshot"))
            image = client.get(f"/api/scans/{scan_id}/screenshots/{screenshot}")
            self.assertEqual(image.status_code,200)
            self.assertEqual(image.headers["content-type"],"image/png")
            for fmt,content_type in (("html","text/html"),("json","application/json"),("pdf","application/pdf")):
                report = client.get(f"/api/scans/{scan_id}/report.{fmt}")
                self.assertEqual(report.status_code,200,report.text[:500])
                self.assertIn(content_type,report.headers.get("content-type",""))
            self.assertNotIn("fixture-secret",client.get(f"/api/scans/{scan_id}/report.json").text)


if __name__ == "__main__":
    unittest.main()
