from datetime import datetime, timedelta, timezone
import importlib.util
from http.server import ThreadingHTTPServer
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from examples.test_app import Handler
from sentinel_ai.agent import ActionProposal
from sentinel_ai.browser import BrowserController
from sentinel_ai.models import AuthorizationRecord, ScanLimits


class PlannedActions:
    """Deterministic test planner; this is not a live provider integration."""

    def __init__(self, actions):
        self.actions = iter(actions)

    def propose(self, _observation):
        return next(self.actions)


@unittest.skipUnless(
    importlib.util.find_spec("playwright"),
    "requires the Playwright package and installed Chromium browser",
)
class BrowserIntegrationTests(unittest.TestCase):
    def test_local_fixture_is_discovered_without_form_submission_or_secret_logging(self):
        from playwright.sync_api import Error, sync_playwright

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
                browser.close()
            except Error as exc:
                self.skipTest(f"Chromium browser binary is unavailable: {exc}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        output_path = Path(tempfile.mkdtemp(prefix="sentinel-integration-", dir=Path.cwd()))
        self.addCleanup(shutil.rmtree, output_path, ignore_errors=True)
        try:
            port = server.server_address[1]
            authorization = AuthorizationRecord(
                authorized_by="Local integration test",
                authorization_reference="Loopback fixture only",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                allowed_domains=["127.0.0.1"],
                allow_loopback=True,
            )
            result = BrowserController(
                authorization,
                f"http://127.0.0.1:{port}/",
                output_path,
                ScanLimits(max_pages=2, max_depth=1, max_requests=100,
                           request_delay_seconds=0, navigation_delay_seconds=0),
                headless=True,
                live_logs=False,
            ).run()
            self.assertEqual(len(result.pages), 2)
            self.assertTrue(all(Path(page.screenshot).is_file() for page in result.pages))
            self.assertTrue(any("/api/status" in endpoint for endpoint in result.api_endpoints))
            serialized = result.model_dump_json()
            self.assertNotIn("fixture-secret", serialized)
            self.assertFalse(any(event.details.get("method") == "POST" for event in result.activity))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_agent_click_requires_approval_and_records_verified_browser_actions(self):
        from playwright.sync_api import Error, sync_playwright

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
                browser.close()
            except Error as exc:
                self.skipTest(f"Chromium browser binary is unavailable: {exc}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        output_path = Path(tempfile.mkdtemp(prefix="sentinel-agent-integration-", dir=Path.cwd()))
        self.addCleanup(shutil.rmtree, output_path, ignore_errors=True)
        approvals = []
        try:
            port = server.server_address[1]
            base_url = f"http://127.0.0.1:{port}/"
            authorization = AuthorizationRecord(
                authorized_by="Local integration test",
                authorization_reference="Loopback fixture only",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                allowed_domains=["127.0.0.1"],
                allow_loopback=True,
            )
            planner = PlannedActions(
                [
                    ActionProposal(
                        objective="Read the fixture about page",
                        action="click",
                        target_id="link-0",
                        reason="It is a discovered same-scope link",
                        expected_result="The about page loads",
                    ),
                    ActionProposal(
                        objective="Finish the passive visit",
                        action="stop",
                        reason="No more pages are needed",
                        expected_result="The browser run stops",
                    ),
                ]
            )
            result = BrowserController(
                authorization,
                base_url,
                output_path,
                ScanLimits(max_pages=3, max_depth=2, max_requests=100,
                           request_delay_seconds=0, navigation_delay_seconds=0),
                headless=True,
                live_logs=False,
                ai_planner=planner,
                approval_gate=lambda proposal: approvals.append(proposal) or True,
            ).run()

            self.assertEqual(len(approvals), 1)
            self.assertTrue(approvals[0].requires_approval)
            self.assertEqual(len(result.pages), 2)
            events = [(event.event, event.details) for event in result.activity]
            self.assertTrue(any(name == "ai_observation" for name, _ in events))
            self.assertTrue(any(name == "ai_policy_decision" for name, _ in events))
            self.assertTrue(any(name == "ai_action_approved" for name, _ in events))
            self.assertTrue(any(
                name == "ai_action_executed" and details.get("action") == "click"
                for name, details in events
            ))
            self.assertTrue(any(
                name == "ai_action_verified" and details.get("action") == "click"
                and details.get("verified") is True
                for name, details in events
            ))
            self.assertTrue(all(Path(page.screenshot).is_file() for page in result.pages))
            self.assertNotIn("fixture-secret", result.model_dump_json())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
