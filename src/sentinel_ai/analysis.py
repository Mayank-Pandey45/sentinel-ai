"""Evidence-based passive checks; observations are deliberately not proof of exploitability."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from .models import CookieObservation, Finding, PageObservation
from .scope import sanitize_url


_SESSION_COOKIE = re.compile(r"(?:session|sess|auth|token|sid|jwt)", re.IGNORECASE)
_CSRF_FIELD = re.compile(r"(?:csrf|xsrf|authenticity|requestverification)", re.IGNORECASE)


def parse_set_cookie(value: str) -> CookieObservation | None:
    """Extract cookie attributes without retaining the cookie value."""
    pieces = [piece.strip() for piece in value.split(";")]
    if not pieces or "=" not in pieces[0]:
        return None
    name = pieces[0].split("=", 1)[0].strip()
    if not name:
        return None
    attributes: dict[str, str | bool] = {}
    for part in pieces[1:]:
        if not part:
            continue
        key, separator, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() if separator else True
    same_site = attributes.get("samesite")
    return CookieObservation(
        name=name[:120],
        secure="secure" in attributes,
        http_only="httponly" in attributes,
        same_site=str(same_site) if same_site is not None else None,
        domain=str(attributes["domain"]) if "domain" in attributes else None,
        path=str(attributes["path"]) if "path" in attributes else None,
        appears_session_related=bool(_SESSION_COOKIE.search(name)),
    )


def analyze_pages(pages: Iterable[PageObservation]) -> list[Finding]:
    pages = list(pages)
    findings: list[Finding] = []
    https_pages = [page for page in pages if urlsplit(page.url).scheme.lower() == "https"]
    http_pages = [page for page in pages if urlsplit(page.url).scheme.lower() == "http"]

    if https_pages:
        checks = [
            ("strict-transport-security", "HTTP Strict Transport Security is absent", "low", "CWE-319", "A02:2021 Cryptographic Failures", "A browser may accept a later plaintext connection, making transport downgrade or interception more likely."),
            ("content-security-policy", "Content Security Policy is absent", "low", "CWE-693", "A05:2021 Security Misconfiguration", "A restrictive content policy can reduce the impact of some script injection and content-loading issues."),
            ("x-content-type-options", "X-Content-Type-Options is absent", "informational", "CWE-16", "A05:2021 Security Misconfiguration", "Browsers may perform MIME sniffing in some contexts."),
            ("referrer-policy", "Referrer-Policy is absent", "informational", "CWE-200", "A05:2021 Security Misconfiguration", "A permissive browser default may disclose more referring URL information than intended."),
        ]
        for header, title, severity, cwe, owasp, impact in checks:
            affected = sorted({page.url for page in https_pages if not page.security_headers.get(header)})
            if affected:
                findings.append(Finding(
                    id=f"missing-{header}",
                    title=title,
                    severity=severity,
                    status="potential",
                    confidence="medium",
                    category="HTTP security headers",
                    affected_endpoints=affected,
                    evidence=[f"The {header} response header was not present on {len(affected)} observed HTTPS document response(s)."],
                    cwe=cwe,
                    owasp_reference=owasp,
                    business_impact=impact,
                    recommendation=f"Review the application threat model and configure an appropriate {header} policy at the application or edge.",
                    retest_guidance=f"Request each affected HTTPS page and confirm the response contains a correctly configured {header} header.",
                ))

    if http_pages:
        findings.append(Finding(
            id="plaintext-http-pages",
            title="Assessment encountered pages over plaintext HTTP",
            severity="medium",
            status="potential",
            confidence="high",
            category="Transport security",
            affected_endpoints=sorted({page.url for page in http_pages}),
            evidence=["The document navigation used an http:// URL; this observation does not inspect credentials or prove an exploitable data flow."],
            cwe="CWE-319",
            owasp_reference="A02:2021 Cryptographic Failures",
            business_impact="Data sent over plaintext HTTP can be observed or modified by a network attacker.",
            recommendation="Serve the application over HTTPS and redirect HTTP requests to HTTPS before handling sensitive data.",
            retest_guidance="Verify all in-scope pages and requests use HTTPS and that HTTP redirects to the approved HTTPS origin.",
        ))

    insecure_session_cookies = [
        (page.url, cookie)
        for page in pages
        for cookie in page.cookies
        if cookie.appears_session_related and (
            not cookie.secure or not cookie.http_only or cookie.same_site is None
        )
    ]
    if insecure_session_cookies:
        affected = sorted({url for url, _ in insecure_session_cookies})
        omissions = sorted({
            name for _, cookie in insecure_session_cookies
            for name, missing in (
                ("Secure", not cookie.secure),
                ("HttpOnly", not cookie.http_only),
                ("SameSite", cookie.same_site is None),
            ) if missing
        })
        findings.append(Finding(
            id="session-cookie-attributes",
            title="Session-like cookie is missing one or more protective attributes",
            severity="medium",
            status="potential",
            confidence="medium",
            category="Cookie configuration",
            affected_endpoints=affected,
            evidence=[f"Observed session-like cookie names with missing attributes: {', '.join(omissions)}. Cookie values were not stored."],
            cwe="CWE-614",
            owasp_reference="A05:2021 Security Misconfiguration",
            business_impact="Weak cookie attributes can increase exposure to script access, plaintext transport, or cross-site request risks depending on application behavior.",
            recommendation="Set Secure and HttpOnly where applicable and choose a SameSite policy that matches the application's cross-site flows.",
            retest_guidance="Inspect Set-Cookie responses for the session cookie and confirm the chosen attributes are present on every relevant response.",
        ))

    password_forms = [
        (page, form)
        for page in pages
        for form in page.forms
        if form.get("has_password_field") is True
    ]
    insecure_password_forms = [
        (page, form) for page, form in password_forms if urlsplit(page.url).scheme.lower() != "https"
    ]
    if insecure_password_forms:
        findings.append(Finding(
            id="password-form-over-http",
            title="Password form was observed on a plaintext HTTP page",
            severity="high",
            status="potential",
            confidence="high",
            category="Form security",
            affected_endpoints=sorted({page.url for page, _ in insecure_password_forms}),
            evidence=["A password input was present on an HTTP page. Sentinel AI did not submit the form."],
            cwe="CWE-319",
            owasp_reference="A02:2021 Cryptographic Failures",
            business_impact="Credentials entered on a plaintext page can be intercepted or altered in transit.",
            recommendation="Serve the login page and form action over HTTPS and enable HSTS after validating deployment behavior.",
            retest_guidance="Confirm the password page and form action use HTTPS; perform any credential-flow test separately with approved test credentials.",
        ))

    forms_without_obvious_csrf = [
        (page.url, form)
        for page in pages
        for form in page.forms
        if str(form.get("method", "get")).lower() == "post"
        and form.get("has_obvious_csrf_field") is False
    ]
    if forms_without_obvious_csrf:
        findings.append(Finding(
            id="post-form-no-obvious-csrf-field",
            title="POST form has no obvious anti-CSRF field in its visible DOM",
            severity="low",
            status="inconclusive",
            confidence="low",
            category="Form security",
            affected_endpoints=sorted({url for url, _ in forms_without_obvious_csrf}),
            evidence=["A POST form had no hidden field whose name resembled a common CSRF token. Header-based, cookie-based, or server-side controls were not evaluated."],
            cwe="CWE-352",
            owasp_reference="A01:2021 Broken Access Control",
            business_impact="If no effective CSRF defense exists, a victim's authenticated browser could be induced to submit unwanted state-changing requests.",
            recommendation="Review the server-side CSRF defense for each state-changing form; use framework protections or a well-designed token and SameSite cookie strategy.",
            retest_guidance="Verify the defense in application code and, if authorized, test with a dedicated account and non-production data.",
        ))

    return findings


def discover_form_observations(forms: list[dict[str, object]]) -> list[dict[str, str | int | bool | None]]:
    """Normalize page-evaluated form metadata without retaining field values."""
    normalized: list[dict[str, str | int | bool | None]] = []
    for form in forms[:100]:
        names = [str(name)[:120] for name in form.get("field_names", []) if isinstance(name, str)]
        normalized.append({
            "action": sanitize_url(str(form.get("action", "")))[:2048],
            "method": str(form.get("method", "get")).lower()[:16],
            "field_count": int(form.get("field_count", 0)),
            "has_password_field": bool(form.get("has_password_field", False)),
            "has_obvious_csrf_field": any(_CSRF_FIELD.search(name) for name in names),
        })
    return normalized
