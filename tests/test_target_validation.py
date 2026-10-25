from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch

from sentinel_ai.models import AuthorizationRecord
from sentinel_ai.scope import ScopeGuardian, ScopeViolation
from sentinel_ai.target_validation import TargetInputError, head_probe, normalize_http_url


class RedirectHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == "/allowed/":
            self.send_response(302)
            self.send_header("Location", "/outside/")
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class TargetValidationTests(unittest.TestCase):
    def test_normalization_rejects_unsupported_schemes_credentials_and_query(self):
        for url in ("file:///etc/passwd", "ftp://example.com/", "https://user:pass@example.com/", "https://example.com/?token=secret"):
            with self.subTest(url=url), self.assertRaises(TargetInputError):
                normalize_http_url(url)
        normalized, _ = normalize_http_url("HTTPS://Example.COM.:443/app")
        self.assertEqual(normalized, "https://example.com/app")
        self.assertEqual(normalize_http_url("example.com/app")[0], "https://example.com/app")

    def test_dns_failures_fail_closed(self):
        authorization = AuthorizationRecord(
            authorized_by="Test owner", authorization_reference="TEST-DNS",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10), allowed_domains=["example.com"],
        )
        with patch.object(ScopeGuardian, "validate_url", side_effect=ScopeViolation("DNS resolution failed")):
            result = head_probe("https://example.com/", authorization)
        self.assertFalse(result.reachable)
        self.assertEqual(result.state, "unreachable")

    def test_redirect_outside_registered_path_is_blocked(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        base = f"http://127.0.0.1:{port}/allowed/"
        authorization = AuthorizationRecord(
            authorized_by="Local test owner", authorization_reference="TEST-REDIRECT",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10), allowed_domains=["127.0.0.1"],
            allowed_url_prefixes=[base], allow_loopback=True,
        )
        result = head_probe(base, authorization)
        self.assertTrue(result.reachable)
        self.assertEqual(result.state, "redirect_out_of_scope")
        self.assertIsNone(result.final_url)


if __name__ == "__main__":
    unittest.main()
