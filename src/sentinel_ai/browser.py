"""Visible Playwright controller with bounded, read-only browser activity."""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .analysis import analyze_pages, discover_form_observations, parse_set_cookie
from .models import ActivityEvent, AssessmentResult, AuthorizationRecord, PageObservation, ScanLimits
from .scope import ScopeGuardian, ScopeViolation, sanitize_url


_SENSITIVE_ACTION = re.compile(
    r"(?:logout|signout|delete|destroy|remove|revoke|purchase|checkout|transfer|unsubscribe|"
    r"subscribe|confirm|resetpassword|changepassword|payment|update|create|submit|cancel|approve)",
    re.IGNORECASE,
)
_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-frame-options",
)


class BrowserController:
    """Run a bounded passive assessment in a visible Chromium browser window."""

    def __init__(
        self,
        authorization: AuthorizationRecord,
        target_url: str,
        output_dir: str | Path,
        limits: ScanLimits | None = None,
        *,
        headless: bool = False,
        live_logs: bool = True,
    ) -> None:
        self.authorization = authorization
        self.guardian = ScopeGuardian(authorization)
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.limits = limits or ScanLimits()
        self.headless = headless
        self.live_logs = live_logs
        self.assessment_id = uuid.uuid4().hex[:12]
        self._pages: list[PageObservation] = []
        self._activity: list[ActivityEvent] = []
        self._api_endpoints: set[str] = set()
        self._response_details: dict[str, dict[str, Any]] = {}
        self._request_count = 0
        self._last_request_at = 0.0
        self._rate_lock = threading.Lock()
        self._started_monotonic = 0.0
        self._stop = threading.Event()
        self._resume = threading.Event()
        self._resume.set()
        self._activity_path: Path | None = None
        self._browser: Any = None
        self._browser_metadata: dict[str, str | int | bool | None] = {}

    def pause(self) -> None:
        """Pause before the next navigation or request continuation."""
        self._resume.clear()
        self._record("paused")

    def resume(self) -> None:
        """Resume an assessment paused with pause()."""
        self._resume.set()
        self._record("resumed")

    def stop(self) -> None:
        """Request orderly cancellation at the next safe controller boundary."""
        self._stop.set()
        self._resume.set()
        self._record("stop_requested")

    def emergency_stop(self) -> None:
        """Immediately request cancellation and close Chromium when possible."""
        self._stop.set()
        self._resume.set()
        self._record("emergency_stop_requested")
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                # The normal run loop will still observe the stop event and clean up.
                pass

    def run(self) -> AssessmentResult:
        self.guardian.validate_url(self.target_url)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._activity_path = self.output_dir / "activity.jsonl"
        started_at = datetime.now(timezone.utc)
        self._started_monotonic = time.monotonic()
        self._record("assessment_started", self.target_url, {"assessment_id": self.assessment_id})
        try:
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:
                raise RuntimeError(
                    "Playwright is not installed. Install dependencies with: "
                    "python -m pip install -e '.[dev]' && python -m playwright install chromium"
                ) from exc

            with sync_playwright() as playwright:
                self._browser = playwright.chromium.launch(headless=self.headless)
                self._browser_metadata = {
                    "engine": "Chromium",
                    "browser_version": self._browser.version,
                    "headless": self.headless,
                    "viewport": "1280x720",
                }
                context = self._browser.new_context(service_workers="block", accept_downloads=False)
                context.set_default_navigation_timeout(self.limits.navigation_timeout_ms)
                context.set_default_timeout(self.limits.navigation_timeout_ms)
                context.route("**/*", self._route_request)
                page = context.new_page()
                page.on("request", self._on_request)
                page.on("response", self._on_response)
                self._crawl(page)
                context.close()
                self._browser.close()
                self._browser = None
        except Exception as exc:
            self._record("assessment_error", details={"error_type": type(exc).__name__, "message": str(exc)[:500]})
            raise
        finally:
            if self._browser is not None:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None
        completed_at = datetime.now(timezone.utc)
        self._record("assessment_completed", details={"pages": len(self._pages), "requests": self._request_count})
        return AssessmentResult(
            assessment_id=self.assessment_id,
            started_at=started_at,
            completed_at=completed_at,
            target_url=sanitize_url(self.target_url),
            authorization_reference=self.authorization.authorization_reference,
            authorized_by=self.authorization.authorized_by,
            authorized_domains=self.authorization.allowed_domains,
            allowed_url_prefixes=self.authorization.allowed_url_prefixes,
            browser_metadata=self._browser_metadata,
            pages=self._pages,
            api_endpoints=sorted(self._api_endpoints),
            findings=analyze_pages(self._pages),
            activity=self._activity.copy(),
            limitations=[
                "Checks are passive observations and do not provide complete vulnerability coverage.",
                "Forms are never submitted and the controller does not click page controls.",
                "The browser request guard is application-level. Use a dedicated VM/container and host or network firewall egress rules for enforcement below the browser and to reduce DNS rebinding risk.",
                "Requests are paced and total requests are capped, but no independent maximum in-flight request limit is enforced.",
                "Page JavaScript executes to render the site; non-GET/HEAD requests and common state-changing URL patterns are blocked, but safe assessment should still use an isolated browser environment.",
                "Authentication flows, authenticated pages, TLS cipher suites, server-side behavior, and dynamic authorization checks are not evaluated.",
                "Screenshots can contain sensitive page content; keep the local output directory access-controlled.",
            ],
        )

    def _crawl(self, page: Any) -> None:
        queue: deque[tuple[str, int]] = deque([(self.target_url, 0)])
        visited: set[str] = set()
        while queue and len(self._pages) < self.limits.max_pages and not self._stop.is_set():
            self._wait_until_resumed()
            self._check_bounds()
            if self._stop.is_set():
                break
            url, depth = queue.popleft()
            try:
                self.guardian.validate_url(url)
            except ScopeViolation as exc:
                self._record("navigation_blocked", url, {"reason": str(exc)[:240]})
                continue
            key = sanitize_url(url)
            if key in visited:
                continue
            visited.add(key)
            if self._has_sensitive_action(url):
                self._record("navigation_skipped_sensitive_pattern", url)
                continue
            if self._pages and self.limits.navigation_delay_seconds:
                time.sleep(self.limits.navigation_delay_seconds)
            self._record("navigation_started", url, {"depth": depth})
            try:
                response = page.goto(url, wait_until="domcontentloaded")
                if response is None:
                    status_code = None
                else:
                    status_code = response.status
                if self._stop.is_set():
                    break
                self._wait_until_resumed()
                data = page.evaluate(_PAGE_INSPECTOR)
                doc_url = page.url or url
                self.guardian.validate_url(doc_url)
                safe_doc_url = sanitize_url(doc_url)
                details = self._response_details.get(safe_doc_url, {})
                safe_links: list[dict[str, str]] = []
                crawl_candidates: list[str] = []
                for link in data.get("links", [])[:500]:
                    candidate = str(link.get("url", ""))
                    try:
                        self.guardian.validate_url(candidate)
                    except ScopeViolation:
                        continue
                    safe_links.append({
                        "url": sanitize_url(candidate),
                        "text": str(link.get("text", ""))[:160],
                    })
                    crawl_candidates.append(candidate)
                page_observation = PageObservation(
                    url=safe_doc_url,
                    title=str(data.get("title", ""))[:300],
                    status_code=status_code,
                    security_headers=details.get("security_headers", {}),
                    cookies=details.get("cookies", []),
                    forms=discover_form_observations(data.get("forms", [])),
                    links=safe_links,
                    controls=data.get("controls", [])[:200],
                )
                shot = self.output_dir / "screenshots" / f"{self.assessment_id}-{len(self._pages) + 1:03d}.png"
                shot.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(shot), full_page=False, animations="disabled", timeout=self.limits.navigation_timeout_ms)
                page_observation.screenshot = str(shot.resolve())
                self._pages.append(page_observation)
                self._record("page_observed", doc_url, {"status_code": status_code, "screenshot": shot.name})
                if depth < self.limits.max_depth:
                    for candidate in crawl_candidates:
                        if not candidate:
                            continue
                        try:
                            self.guardian.validate_url(candidate)
                        except ScopeViolation:
                            continue
                        if sanitize_url(candidate) not in visited and not self._has_sensitive_action(candidate):
                            queue.append((candidate, depth + 1))
            except Exception as exc:
                self._record("navigation_error", url, {"error_type": type(exc).__name__, "message": str(exc)[:300]})

    def _route_request(self, route: Any) -> None:
        request = route.request
        url = request.url
        method = request.method.upper()
        resource_type = request.resource_type.lower()
        try:
            if self._stop.is_set():
                raise ScopeViolation("assessment has been stopped")
            self._wait_until_resumed()
            self._check_bounds()
            if self._stop.is_set():
                raise ScopeViolation("assessment resource bound reached")
            self._pace_request()
            self._check_bounds()
            if self._stop.is_set():
                raise ScopeViolation("assessment resource bound reached")
            self._request_count += 1
            if self._request_count > self.limits.max_requests:
                raise ScopeViolation("maximum request count reached")
            self.guardian.validate_url(url)
            if method not in {"GET", "HEAD"}:
                raise ScopeViolation(f"HTTP method {method} is not permitted in passive mode")
            if resource_type in {"websocket", "eventsource"}:
                raise ScopeViolation(f"resource type {resource_type} is not permitted")
            parsed = urlsplit(url)
            if self._has_sensitive_action(url):
                raise ScopeViolation("URL matches a common state-changing action pattern")
            self._record("request_allowed", url, {"method": method, "resource_type": resource_type})
            route.continue_()
        except ScopeViolation as exc:
            self._record("request_blocked", url, {"method": method, "resource_type": resource_type, "reason": str(exc)[:240]})
            try:
                route.abort("blockedbyclient")
            except Exception:
                pass

    def _on_request(self, request: Any) -> None:
        if request.resource_type in {"fetch", "xhr"}:
            self._api_endpoints.add(sanitize_url(request.url))

    @staticmethod
    def _has_sensitive_action(url: str) -> bool:
        parsed = urlsplit(url)
        normalized = re.sub(r"[^a-z0-9]", "", parsed.path.lower() + parsed.query.lower())
        return bool(_SENSITIVE_ACTION.search(normalized))

    def _on_response(self, response: Any) -> None:
        request = response.request
        safe_url = sanitize_url(response.url)
        details = self._response_details.setdefault(safe_url, {"security_headers": {}, "cookies": []})
        try:
            headers = {key.lower(): value for key, value in response.headers.items()}
            if request.resource_type == "document":
                details["security_headers"] = {
                    key: sanitize_security_header_value(key, headers.get(key)) for key in _SECURITY_HEADERS
                }
            try:
                header_items = response.headers_array()
                set_cookie_values = [item["value"] for item in header_items if item["name"].lower() == "set-cookie"]
            except Exception:
                set_cookie_values = [headers["set-cookie"]] if headers.get("set-cookie") else []
            for value in set_cookie_values:
                observed = parse_set_cookie(value)
                if observed and observed not in details["cookies"]:
                    details["cookies"].append(observed)
        except Exception as exc:
            self._record("response_metadata_error", response.url, {"error_type": type(exc).__name__})

    def _wait_until_resumed(self) -> None:
        while not self._resume.wait(timeout=0.2):
            if self._stop.is_set():
                return
            self._check_bounds()

    def _pace_request(self) -> None:
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_request_at
            delay = self.limits.request_delay_seconds - elapsed
            if self._last_request_at and delay > 0:
                time.sleep(delay)
            self._last_request_at = time.monotonic()

    def _check_bounds(self) -> None:
        elapsed = time.monotonic() - self._started_monotonic
        if not self._stop.is_set() and elapsed > self.limits.max_duration_seconds:
            self._stop.set()
            self._record("limit_reached", details={"limit": "max_duration_seconds"})
        elif not self._stop.is_set() and self._request_count >= self.limits.max_requests:
            self._stop.set()
            self._record("limit_reached", details={"limit": "max_requests"})

    def _record(
        self,
        event: str,
        url: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        safe_details: dict[str, str | int | float | bool | None] = {}
        for key, value in (details or {}).items():
            safe_value = value if isinstance(value, (str, int, float, bool)) or value is None else str(value)[:300]
            if isinstance(safe_value, str):
                safe_value = re.sub(
                    r"https?://[^\s'\"<>]+",
                    lambda match: sanitize_url(match.group(0)),
                    safe_value,
                )[:500]
            safe_details[str(key)[:80]] = safe_value
        item = ActivityEvent(event=event, url=sanitize_url(url) if url else None, details=safe_details)
        self._activity.append(item)
        if self._activity_path:
            with self._activity_path.open("a", encoding="utf-8") as stream:
                stream.write(item.model_dump_json() + "\n")
        if self.live_logs:
            print(item.model_dump_json(), file=sys.stdout, flush=True)


_PAGE_INSPECTOR = """
() => {
  const trim = (value, max = 160) => (value || '').trim().replace(/\\s+/g, ' ').slice(0, max);
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500).map(a => ({
    url: a.href,
    text: trim(a.innerText || a.getAttribute('aria-label') || a.title)
  }));
  const forms = Array.from(document.forms).slice(0, 100).map(form => {
    const fields = Array.from(form.querySelectorAll('input[name], select[name], textarea[name]'));
    return {
      action: form.action || location.href,
      method: (form.method || 'get').toLowerCase(),
      field_count: fields.length,
      has_password_field: !!form.querySelector('input[type="password"]'),
      field_names: fields.map(field => field.name).slice(0, 100)
    };
  });
  const controls = Array.from(document.querySelectorAll('button, input[type="button"], input[type="submit"]')).slice(0, 200).map(control => ({
    type: trim(control.type, 40),
    name: trim(control.getAttribute('aria-label') || control.innerText || control.value || control.title)
  }));
  return { title: document.title || '', links, forms, controls };
}
"""


def sanitize_security_header_value(name: str, value: str | None) -> str | None:
    """Keep useful policy text while removing likely nonce and query secrets."""
    if not value:
        return None
    safe = value[:4096]
    if name == "content-security-policy":
        safe = re.sub(r"(?i)nonce-[\"']?[^\s;\"']+", "nonce-{redacted}", safe)
    return re.sub(
        r"https?://[^\s,;]+",
        lambda match: sanitize_url(match.group(0)),
        safe,
    )
