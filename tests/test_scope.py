from datetime import datetime, timedelta, timezone
import unittest

from sentinel_ai.models import AuthorizationRecord
from sentinel_ai.scope import ScopeGuardian, ScopeViolation, sanitize_url


def authorization(**overrides):
    values = {
        "authorized_by": "Test operator",
        "authorization_reference": "TEST-123",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
        "allowed_domains": ["example.com"],
    }
    values.update(overrides)
    return AuthorizationRecord(**values)


class ScopeTests(unittest.TestCase):
    def test_scope_requires_exact_host_and_resolves_public_ip(self):
        guardian = ScopeGuardian(authorization(), resolver=lambda _host: ["93.184.216.34"])
        self.assertEqual(guardian.validate_url("https://example.com/").hostname, "example.com")
        with self.assertRaisesRegex(ScopeViolation, "allowlist"):
            guardian.validate_url("https://sub.example.com/")

    def test_scope_can_explicitly_include_subdomains(self):
        guardian = ScopeGuardian(
            authorization(include_subdomains=True), resolver=lambda _host: ["93.184.216.34"]
        )
        self.assertEqual(guardian.validate_url("https://app.example.com/").hostname, "app.example.com")
        with self.assertRaises(ScopeViolation):
            guardian.validate_url("https://example.com.attacker.test/")

    def test_private_and_metadata_destinations_are_blocked_by_default(self):
        for address in ("127.0.0.1", "10.2.3.4", "169.254.169.254", "::1", "fe80::1"):
            with self.subTest(address=address):
                guardian = ScopeGuardian(authorization(), resolver=lambda _host: [address])
                with self.assertRaises(ScopeViolation):
                    guardian.validate_url("https://example.com/")

    def test_loopback_requires_explicit_local_test_authorization(self):
        guardian = ScopeGuardian(
            authorization(allowed_domains=["127.0.0.1"], allow_loopback=True),
            resolver=lambda _host: ["127.0.0.1"],
        )
        self.assertEqual(guardian.validate_url("http://127.0.0.1:8000/").hostname, "127.0.0.1")

    def test_private_exception_does_not_allow_link_local_metadata(self):
        guardian = ScopeGuardian(
            authorization(allow_private_networks=True), resolver=lambda _host: ["169.254.169.254"]
        )
        with self.assertRaisesRegex(ScopeViolation, "prohibited"):
            guardian.validate_url("https://example.com/")

    def test_dns_mixed_public_and_private_answer_fails_closed(self):
        guardian = ScopeGuardian(
            authorization(), resolver=lambda _host: ["93.184.216.34", "10.0.0.1"]
        )
        with self.assertRaisesRegex(ScopeViolation, "private"):
            guardian.validate_url("https://example.com/")

    def test_url_prefixes_enforce_origin_and_path_boundary(self):
        guardian = ScopeGuardian(
            authorization(allowed_url_prefixes=["https://example.com/app"]),
            resolver=lambda _host: ["93.184.216.34"],
        )
        guardian.validate_url("https://example.com/app/settings")
        for url in ("https://example.com/application", "https://example.com/other"):
            with self.subTest(url=url), self.assertRaisesRegex(ScopeViolation, "prefixes"):
                guardian.validate_url(url)

    def test_url_prefixes_reject_encoded_or_literal_parent_path_escape(self):
        guardian = ScopeGuardian(
            authorization(allowed_url_prefixes=["https://example.com/app"]),
            resolver=lambda _host: ["93.184.216.34"],
        )
        for url in (
            "https://example.com/app/../admin",
            "https://example.com/app/%2e%2e/admin",
            "https://example.com/app%2f%2e%2e/admin",
            "https://example.com/app/%252e%252e/admin",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(ScopeViolation, "prefixes"):
                guardian.validate_url(url)

    def test_authorization_rejects_url_prefix_for_unregistered_host(self):
        with self.assertRaisesRegex(ValueError, "allowed_domains"):
            authorization(allowed_url_prefixes=["https://attacker.test/app"])

    def test_credentials_and_non_http_schemes_are_rejected(self):
        guardian = ScopeGuardian(authorization(), resolver=lambda _host: ["93.184.216.34"])
        with self.assertRaisesRegex(ScopeViolation, "credentials"):
            guardian.validate_url("https://user:password@example.com/")
        with self.assertRaisesRegex(ScopeViolation, "HTTP"):
            guardian.validate_url("file:///etc/passwd")

    def test_sanitizer_drops_query_and_redacts_high_entropy_path_segment(self):
        url = "https://example.com/reset/abcde12345abcde12345abcde12345abcd?token=secret#top"
        self.assertEqual(sanitize_url(url), "https://example.com/reset/{redacted}")

    def test_authorization_requires_timezone_aware_expiration(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            authorization(expires_at=datetime(2030, 1, 1))


if __name__ == "__main__":
    unittest.main()

