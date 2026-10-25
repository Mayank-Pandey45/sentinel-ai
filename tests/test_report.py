from datetime import datetime, timezone
import unittest

from sentinel_ai.models import AssessmentResult, Finding
from sentinel_ai.report import render_html_report


class ReportTests(unittest.TestCase):
    def test_zero_finding_report_has_clear_non_security_conclusion(self):
        result = AssessmentResult(
            assessment_id="empty-123", started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc), target_url="https://example.com/",
            authorization_reference="AUTH-EMPTY", authorized_by="Operator", findings=[],
            browser_metadata={"engine":"Chromium","browser_version":"test","headless":True},
            selected_checks=["passive_headers"], limitations=["Partial coverage."],
        )
        report = render_html_report(result)
        self.assertIn("No findings were produced from the available observations", report)
        self.assertIn("not proof that the website is secure", report)
        self.assertIn("Headless Chromium", report)
        self.assertIn("15. Appendix", report)

    def test_report_escapes_untrusted_content_and_discloses_limitations(self):
        result = AssessmentResult(
            assessment_id="test-123", started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc), target_url="https://example.com/",
            authorization_reference="AUTH-1", authorized_by="Operator",
            findings=[Finding(
                id="example", title="<script>alert(1)</script>", severity="low",
                confidence="low", category="Test",
                affected_endpoints=["https://example.com/<img>", "https://example.com/?token=secret"],
                evidence=["<b>raw page evidence</b>"], business_impact="None",
                recommendation="Review", retest_guidance="Retest",
            )],
            limitations=["Coverage is limited."],
        )
        output = render_html_report(result)
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("&lt;img&gt;", output)
        self.assertIn("Coverage is limited.", output)


if __name__ == "__main__":
    unittest.main()

