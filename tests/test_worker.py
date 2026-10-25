from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_ai.models import AuthorizationRecord
from sentinel_ai.store import Store
from sentinel_ai.worker import ScanManager


class FakeController:
    def __init__(self):
        self.paused = False
        self.resumed = False
        self.stopped = False
        self.emergency = False

    def pause(self): self.paused = True
    def resume(self): self.resumed = True
    def stop(self): self.stopped = True
    def emergency_stop(self): self.emergency = True


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = Store(root / "db.sqlite3")
        user = self.store.bootstrap_owner("worker@example.test", "hashed", "Worker test")
        auth = AuthorizationRecord(
            authorized_by="Local test owner", authorization_reference="WORKER-TEST",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            allowed_domains=["127.0.0.1"], allow_loopback=True,
        )
        self.target = self.store.create_target({
            "organization_id": user["organization_id"], "name": "Local fixture", "base_url": "http://127.0.0.1:8000/",
            "authorization": auth.model_dump(mode="json"), "authorization_reference": auth.authorization_reference,
            "authorized_by": auth.authorized_by, "expires_at": auth.expires_at.isoformat(), "created_by": user["user_id"],
        })
        self.user = user
        self.manager = ScanManager(self.store, root / "scans")

    def create_scan(self):
        return self.store.create_scan({
            "organization_id": self.user["organization_id"], "target_id": self.target["id"],
            "created_by": self.user["user_id"], "config": {
                "target_url": self.target["base_url"], "selected_checks": ["passive_headers"],
                "headless": True, "capture_screenshots": False, "ai_analysis": False,
                "limits": {"max_pages": 1, "max_depth": 0, "max_requests": 5, "max_duration_seconds": 10,
                           "request_delay_seconds": 0, "navigation_delay_seconds": 0, "navigation_timeout_ms": 1000},
            },
        })

    def test_pause_resume_stop_and_emergency_stop_control_the_controller(self):
        scan = self.create_scan()
        self.store.update_scan(scan["id"], status="running")
        controller = FakeController()
        self.manager._controllers[scan["id"]] = controller
        org = self.user["organization_id"]
        self.assertTrue(self.manager.pause(scan["id"], org))
        self.assertTrue(controller.paused)
        self.assertEqual(self.store.get_scan(scan["id"], org)["status"], "paused")
        self.assertTrue(self.manager.resume(scan["id"], org))
        self.assertTrue(controller.resumed)
        self.assertEqual(self.store.get_scan(scan["id"], org)["status"], "running")
        self.assertTrue(self.manager.stop(scan["id"], org, emergency=True))
        self.assertTrue(controller.emergency)
        self.assertEqual(self.store.get_scan(scan["id"], org)["status"], "cancelled")

    def test_browser_launch_failure_is_a_real_failed_job(self):
        scan = self.create_scan()

        class BrokenBrowser:
            def __init__(self, *_args, **_kwargs): pass
            def run(self): raise RuntimeError("browser launch failed")

        with patch("sentinel_ai.worker.BrowserController", BrokenBrowser):
            self.manager._execute(scan)
        stored = self.store.get_scan(scan["id"], self.user["organization_id"])
        self.assertEqual(stored["status"], "failed")
        self.assertIn("browser launch failed", stored["error"])

    def test_queued_cancellation_does_not_launch_a_browser(self):
        scan = self.create_scan()
        self.store.update_scan(scan["id"], cancel_requested=True, status="cancelled")
        with patch("sentinel_ai.worker.BrowserController") as browser:
            self.manager._execute(scan)
        browser.assert_not_called()
        stored = self.store.get_scan(scan["id"], self.user["organization_id"])
        self.assertEqual(stored["status"], "cancelled")

    def test_local_worker_reports_disconnected_until_heartbeat(self):
        self.assertFalse(self.manager.status()["connected"])
        self.store.heartbeat("local", "connected", "local", ["passive-browser-assessment"])
        self.assertTrue(self.manager.status()["connected"])


if __name__ == "__main__":
    unittest.main()
