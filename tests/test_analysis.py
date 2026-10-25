import unittest

from sentinel_ai.analysis import analyze_pages, discover_form_observations, parse_set_cookie
from sentinel_ai.models import PageObservation


def page(**overrides):
    values = {
        "url": "https://example.com/", "title": "Example", "status_code": 200,
        "security_headers": {
            "strict-transport-security": None, "content-security-policy": None,
            "x-content-type-options": "nosniff", "referrer-policy": None,
            "permissions-policy": None, "x-frame-options": None,
        },
        "cookies": [], "forms": [], "links": [], "controls": [],
    }
    values.update(overrides)
    return PageObservation(**values)


class AnalysisTests(unittest.TestCase):
    def test_cookie_parser_keeps_attributes_but_discards_value(self):
        cookie = parse_set_cookie("sessionid=do-not-store; Path=/; SameSite=Lax")
        self.assertIsNotNone(cookie)
        self.assertEqual(cookie.name, "sessionid")
        self.assertFalse(cookie.secure)
        self.assertFalse(cookie.http_only)
        self.assertEqual(cookie.same_site, "Lax")
        self.assertNotIn("do-not-store", cookie.model_dump_json())

    def test_analysis_reports_missing_headers_and_weak_cookie_as_potential(self):
        cookie = parse_set_cookie("sessionid=secret; Path=/; SameSite=Lax")
        by_id = {finding.id: finding for finding in analyze_pages([page(cookies=[cookie])])}
        self.assertEqual(by_id["missing-strict-transport-security"].status, "potential")
        self.assertEqual(by_id["missing-content-security-policy"].status, "potential")
        self.assertEqual(by_id["session-cookie-attributes"].status, "potential")
        self.assertNotIn("secret", str(by_id))

    def test_form_observations_report_csrf_clue_and_sanitized_action(self):
        observed = discover_form_observations([{
            "action": "https://example.com/pay?account=private", "method": "post",
            "field_count": 2, "has_password_field": False,
            "field_names": ["csrf_token", "email"],
        }])
        self.assertTrue(observed[0]["has_obvious_csrf_field"])
        self.assertEqual(observed[0]["action"], "https://example.com/pay")
        self.assertNotIn("private", str(observed))

    def test_http_password_form_is_potential_and_csrf_clue_is_inconclusive(self):
        observed = page(url="http://example.com/login", security_headers={}, forms=[{
            "action": "http://example.com/login", "method": "post", "field_count": 1,
            "has_password_field": True, "has_obvious_csrf_field": False,
        }])
        findings = {finding.id: finding for finding in analyze_pages([observed])}
        self.assertEqual(findings["password-form-over-http"].status, "potential")
        self.assertEqual(findings["post-form-no-obvious-csrf-field"].status, "inconclusive")

    def test_empty_observation_has_no_fabricated_findings(self):
        self.assertEqual(analyze_pages([]), [])


if __name__ == "__main__":
    unittest.main()

