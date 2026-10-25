from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sentinel_ai.browser import BrowserController, sanitize_security_header_value
from sentinel_ai.models import AuthorizationRecord, ScanLimits


class Request:
    def __init__(self, url, method="GET", resource_type="document"):
        self.url = url
        self.method = method
        self.resource_type = resource_type


class Route:
    def __init__(self, request):
        self.request = request
        self.continued = False
        self.aborted = None

    def continue_(self):
        self.continued = True

    def abort(self, reason):
        self.aborted = reason


class FakeContext:
    def set_default_navigation_timeout(self, _timeout):
        pass

    def set_default_timeout(self, _timeout):
        pass

    def route(self, *_args):
        pass

    def new_page(self):
        return FakePage()

    def close(self):
        pass


class FakePage:
    def on(self, *_args):
        pass


class FakeBrowser:
    version = "test-chromium"

    def new_context(self, **_kwargs):
        return FakeContext()

    def close(self):
        pass


class FakePlaywright:
    def __init__(self):
        self.launch_options = None
        self.chromium = self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def launch(self, **kwargs):
        self.launch_options = kwargs
        return FakeBrowser()


def controller(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    authorization = AuthorizationRecord(
        authorized_by="Test operator", authorization_reference="TEST-LOCAL",
        expires_at=datetime.now(timezone.utc) + timedelta(days=10),
        allowed_domains=["127.0.0.1"], allow_loopback=True,
    )
    result = BrowserController(authorization, "http://127.0.0.1:8000/", root,
                               ScanLimits(max_requests=10), headless=True, live_logs=False)
    result._started_monotonic = time.monotonic()
    return result


class BrowserPolicyTests(unittest.TestCase):
    def test_visible_channel_launch_keeps_chromium_sandbox_enabled(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            instance = controller(Path(tmp))
            instance.headless = False
            instance.browser_channel = "chrome-beta"
            instance._crawl = lambda _page: None
            fake_playwright = FakePlaywright()
            with patch("playwright.sync_api.sync_playwright", return_value=fake_playwright):
                result = instance.run()

            self.assertEqual(
                fake_playwright.launch_options,
                {"headless": False, "chromium_sandbox": True, "channel": "chrome-beta"},
            )
            self.assertEqual(result.browser_metadata["browser_channel"], "chrome-beta")
            self.assertFalse(result.browser_metadata["headless"])
            self.assertTrue(result.browser_metadata["chromium_sandbox"])

    def test_security_header_values_redact_nonce_and_query(self):
        value = "script-src 'nonce-verysecretnonce'; report-uri https://example.com/report?token=secret"
        safe = sanitize_security_header_value("content-security-policy", value)
        self.assertNotIn("verysecretnonce", safe)
        self.assertNotIn("token=secret", safe)

    def test_pause_resume_and_stop_controls_update_controller_state(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            instance = controller(Path(tmp))
            instance.pause()
            self.assertFalse(instance._resume.is_set())
            instance.resume()
            self.assertTrue(instance._resume.is_set())
            instance.stop()
            self.assertTrue(instance._stop.is_set())
            self.assertTrue(instance._resume.is_set())

    def test_emergency_stop_signals_cancellation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            instance = controller(Path(tmp))
            instance.emergency_stop()
            self.assertTrue(instance._stop.is_set())
            self.assertTrue(instance._resume.is_set())

    def test_browser_route_allows_scoped_request_and_sanitizes_log(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root = Path(tmp)
            instance = controller(root)
            instance._activity_path = root / "activity.jsonl"
            route = Route(Request("http://127.0.0.1:8000/page?secret=value"))
            instance._route_request(route)
            self.assertTrue(route.continued)
            self.assertFalse(route.aborted)
            logged = instance._activity_path.read_text(encoding="utf-8")
            self.assertNotIn("secret", logged)
            self.assertNotIn("value", logged)

    def test_browser_route_blocks_mutations_and_out_of_scope_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            instance = controller(Path(tmp))
            post_route = Route(Request("http://127.0.0.1:8000/submit", method="POST"))
            instance._route_request(post_route)
            self.assertEqual(post_route.aborted, "blockedbyclient")
            other_host_route = Route(Request("https://example.net/"))
            instance._route_request(other_host_route)
            self.assertEqual(other_host_route.aborted, "blockedbyclient")
            sensitive_route = Route(Request("http://127.0.0.1:8000/logout"))
            instance._route_request(sensitive_route)
            self.assertEqual(sensitive_route.aborted, "blockedbyclient")
            encoded_sensitive_route = Route(Request("http://127.0.0.1:8000/account?do=log_out"))
            instance._route_request(encoded_sensitive_route)
            self.assertEqual(encoded_sensitive_route.aborted, "blockedbyclient")

    def test_browser_route_paces_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            authorization = AuthorizationRecord(
                authorized_by="Test operator", authorization_reference="TEST-LOCAL",
                expires_at=datetime.now(timezone.utc) + timedelta(days=10),
                allowed_domains=["127.0.0.1"], allow_loopback=True,
            )
            instance = BrowserController(
                authorization, "http://127.0.0.1:8000/", Path(tmp),
                ScanLimits(max_requests=10, request_delay_seconds=0.02), headless=True,
                live_logs=False,
            )
            instance._started_monotonic = time.monotonic()
            instance._route_request(Route(Request("http://127.0.0.1:8000/one")))
            started = time.monotonic()
            instance._route_request(Route(Request("http://127.0.0.1:8000/two")))
            self.assertGreaterEqual(time.monotonic() - started, 0.015)


if __name__ == "__main__":
    unittest.main()
