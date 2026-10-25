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
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from .agent import ActionPolicy, ActionProposal, OpenAICompatiblePlanner, ProviderError
from .analysis import analyze_pages, discover_form_observations, parse_set_cookie
from .models import ActivityEvent, AssessmentResult, AuthorizationRecord, PageObservation, ScanLimits
from .scope import ScopeGuardian, ScopeViolation, sanitize_url


_SENSITIVE_ACTION = re.compile(
    r"(?:logout|signout|delete|destroy|remove|revoke|purchase|checkout|transfer|unsubscribe|"
    r"subscribe|confirm|resetpassword|changepassword|payment|update|create|submit|cancel|approve)",
    re.IGNORECASE,
)
SUPPORTED_BROWSER_CHANNELS = {
    "chromium",
    "chrome",
    "chrome-beta",
    "chrome-dev",
    "chrome-canary",
    "msedge",
    "msedge-beta",
    "msedge-dev",
    "msedge-canary",
}
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
        capture_screenshots: bool = True,
        selected_checks: list[str] | None = None,
        browser_channel: str = "chromium",
        ai_planner: OpenAICompatiblePlanner | None = None,
        approval_gate: Callable[[ActionProposal], bool] | None = None,
        event_sink: Callable[[ActivityEvent], None] | None = None,
    ) -> None:
        self.authorization = authorization
        self.guardian = ScopeGuardian(authorization)
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.limits = limits or ScanLimits()
        self.headless = headless
        self.live_logs = live_logs
        self.capture_screenshots = capture_screenshots
        self.selected_checks = selected_checks or ["passive_baseline", "browser_discovery"]
        browser_channel = browser_channel.strip().lower()
        if browser_channel not in SUPPORTED_BROWSER_CHANNELS:
            allowed = ", ".join(sorted(SUPPORTED_BROWSER_CHANNELS))
            raise ValueError(f"Unsupported browser channel {browser_channel!r}; choose one of: {allowed}")
        self.browser_channel = browser_channel
        self.ai_planner = ai_planner
        self.approval_gate = approval_gate
        self.event_sink = event_sink
        self._agent_policy = ActionPolicy(self.guardian, max_iterations=min(20, self.limits.max_pages * 2))
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
        if datetime.now(timezone.utc) >= self.authorization.expires_at:
            raise ScopeViolation("authorization record expired before the browser run started")
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
                self._record(
                    "browser_launch_started",
                    self.target_url,
                    {
                        "channel": self.browser_channel,
                        "headless": self.headless,
                        "chromium_sandbox": True,
                    },
                )
                launch_options: dict[str, Any] = {
                    "headless": self.headless,
                    "chromium_sandbox": True,
                }
                if self.browser_channel != "chromium":
                    launch_options["channel"] = self.browser_channel
                self._browser = playwright.chromium.launch(**launch_options)
                self._browser_metadata = {
                    "engine": "Chromium",
                    "browser_version": self._browser.version,
                    "browser_channel": self.browser_channel,
                    "headless": self.headless,
                    "chromium_sandbox": True,
                    "viewport": "1280x720",
                }
                self._record(
                    "browser_launch_succeeded",
                    self.target_url,
                    {
                        "channel": self.browser_channel,
                        "browser_version": self._browser.version,
                        "headless": self.headless,
                        "chromium_sandbox": True,
                    },
                )
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
            selected_checks=self.selected_checks,
            worker_id="local",
            pages=self._pages,
            api_endpoints=sorted(self._api_endpoints),
            findings=self._selected_findings(),
            activity=self._activity.copy(),
            limitations=[
                "Checks are passive observations and do not provide complete vulnerability coverage.",
                "Forms are never submitted. The AI planner, when configured, may only activate a discovered in-scope hyperlink; buttons and form controls are never activated.",
                "The browser request guard is application-level. Use a dedicated VM/container and host or network firewall egress rules for enforcement below the browser and to reduce DNS rebinding risk.",
                "Requests are paced and total requests are capped, but no independent maximum in-flight request limit is enforced.",
                "Page JavaScript executes to render the site; non-GET/HEAD requests and common state-changing URL patterns are blocked, but safe assessment should still use an isolated browser environment.",
                "Authentication flows, authenticated pages, TLS cipher suites, server-side behavior, and dynamic authorization checks are not evaluated.",
                "Screenshots can contain sensitive page content; keep the local output directory access-controlled.",
                "A configured AI planner proposes bounded read-only actions; model output is not a security finding and is checked by deterministic policy before execution.",
            ],
        )

    def _selected_findings(self) -> list[Any]:
        findings = analyze_pages(self._pages)
        supported = {"passive_headers", "passive_cookie_attributes", "passive_transport", "passive_forms"}
        selected = set(self.selected_checks)
        if not selected.intersection(supported):
            # Preserve the original CLI's passive_baseline behavior for existing callers.
            if "passive_baseline" in selected:
                return findings
            return []
        def check_for(finding_id: str) -> str:
            if finding_id.startswith("missing-"):
                return "passive_headers"
            if finding_id == "plaintext-http-pages":
                return "passive_transport"
            if finding_id == "session-cookie-attributes":
                return "passive_cookie_attributes"
            return "passive_forms"
        return [finding for finding in findings if check_for(finding.id) in selected]

    def _crawl(self, page: Any) -> None:
        queue: deque[tuple[str, int, bool, str | None]] = deque([(self.target_url, 0, False, None)])
        visited: set[str] = set()
        while queue and len(self._pages) < self.limits.max_pages and not self._stop.is_set():
            self._wait_until_resumed()
            self._check_bounds()
            if self._stop.is_set():
                break
            url, depth, already_loaded, ai_proposal_id = queue.popleft()
            try:
                self.guardian.validate_url(url)
            except ScopeViolation as exc:
                self._record("navigation_blocked", url, {"reason": str(exc)[:240]})
                if ai_proposal_id:
                    self._record(
                        "ai_action_verified",
                        url,
                        {
                            "proposal_id": ai_proposal_id,
                            "action": "navigate",
                            "verified": False,
                            "expected_url": sanitize_url(url),
                            "actual_url": None,
                            "reason": str(exc)[:240],
                        },
                    )
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
            self._record("navigation_started", url, {"depth": depth, "via": "approved-link-click" if already_loaded else "navigation"})
            if ai_proposal_id:
                self._record(
                    "ai_action_started",
                    url,
                    {"proposal_id": ai_proposal_id, "action": "navigate", "destination": sanitize_url(url)},
                )
            try:
                if already_loaded and sanitize_url(page.url) == key:
                    status_code = self._response_details.get(key, {}).get("status_code")
                else:
                    response = page.goto(url, wait_until="domcontentloaded")
                    status_code = response.status if response is not None else None
                if ai_proposal_id:
                    self._record(
                        "ai_action_executed",
                        page.url or url,
                        {
                            "proposal_id": ai_proposal_id,
                            "action": "navigate",
                            "destination": sanitize_url(url),
                        },
                    )
                if self._stop.is_set():
                    break
                self._wait_until_resumed()
                data = page.evaluate(_PAGE_INSPECTOR)
                doc_url = page.url or url
                self.guardian.validate_url(doc_url)
                safe_doc_url = sanitize_url(doc_url)
                if ai_proposal_id:
                    verified = safe_doc_url == sanitize_url(url)
                    self._record(
                        "ai_action_verified",
                        doc_url,
                        {
                            "proposal_id": ai_proposal_id,
                            "action": "navigate",
                            "verified": verified,
                            "expected_url": sanitize_url(url),
                            "actual_url": safe_doc_url,
                        },
                    )
                details = self._response_details.get(safe_doc_url, {})
                safe_links: list[dict[str, str]] = []
                crawl_candidates: list[str] = []
                for index, link in enumerate(data.get("links", [])[:500]):
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
                shot: Path | None = None
                if self.capture_screenshots:
                    shot = self.output_dir / "screenshots" / f"{self.assessment_id}-{len(self._pages) + 1:03d}.png"
                    shot.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(shot), full_page=False, animations="disabled", timeout=self.limits.navigation_timeout_ms)
                    page_observation.screenshot = str(shot.resolve())
                self._pages.append(page_observation)
                self._record("page_observed", doc_url, {
                    "status_code": status_code,
                    "screenshot": shot.name if shot else None,
                    "page_count": len(self._pages),
                    "request_count": self._request_count,
                })
                selected_by_agent = False
                if self.ai_planner:
                    selected_by_agent = self._run_agent_step(
                        page,
                        page_observation,
                        visited,
                        queue,
                        depth,
                    )
                if depth < self.limits.max_depth and not selected_by_agent:
                    for candidate in crawl_candidates:
                        if not candidate:
                            continue
                        try:
                            self.guardian.validate_url(candidate)
                        except ScopeViolation:
                            continue
                        if sanitize_url(candidate) not in visited and not self._has_sensitive_action(candidate):
                            queue.append((candidate, depth + 1, False, None))
            except Exception as exc:
                self._record("navigation_error", url, {"error_type": type(exc).__name__, "message": str(exc)[:300]})
                if ai_proposal_id:
                    actual_url = page.url or None
                    self._record(
                        "ai_action_verified",
                        actual_url or url,
                        {
                            "proposal_id": ai_proposal_id,
                            "action": "navigate",
                            "verified": False,
                            "expected_url": sanitize_url(url),
                            "actual_url": sanitize_url(actual_url) if actual_url else None,
                            "error_type": type(exc).__name__,
                        },
                    )

    def _run_agent_step(
        self,
        page: Any,
        observation: PageObservation,
        visited: set[str],
        queue: deque[tuple[str, int, bool, str | None]],
        depth: int,
    ) -> bool:
        """Run bounded observe/plan/policy/act/verify steps on the current page."""
        repeated_actions: set[tuple[str, str | None, int | None]] = set()
        while self._agent_policy.iterations < self._agent_policy.max_iterations and not self._stop.is_set():
            self._wait_until_resumed()
            self._check_bounds()
            if self._stop.is_set():
                return True

            current_url = page.url or observation.url
            try:
                self.guardian.validate_url(current_url)
            except ScopeViolation as exc:
                self._record("ai_observation_rejected", current_url, {"reason": str(exc)[:200]})
                return True

            page_data = page.evaluate(_PAGE_INSPECTOR)
            scroll = page.evaluate(
                "() => ({y: Math.round(window.scrollY), height: document.documentElement.scrollHeight, "
                "viewport: window.innerHeight})"
            )
            allowed_links: dict[str, str] = {}
            anchor_indices: dict[str, int] = {}
            for index, link in enumerate(page_data.get("links", [])[:500]):
                candidate = str(link.get("url", ""))
                try:
                    self.guardian.validate_url(candidate)
                except ScopeViolation:
                    continue
                if (
                    str(link.get("target", "")).lower() in {"", "_self"}
                    and not bool(link.get("download"))
                    and not bool(link.get("has_onclick"))
                ):
                    target_id = f"link-{index}"
                    allowed_links[target_id] = candidate
                    anchor_indices[target_id] = index

            forms = page_data.get("forms", [])[:100]
            snapshot = {
                "current_url": sanitize_url(current_url),
                "title_present": bool(page_data.get("title")),
                "interactive_elements": [
                    {"target_id": key, "kind": "same-scope link", "url": sanitize_url(value)}
                    for key, value in list(allowed_links.items())[:30]
                ],
                "form_summary": {
                    "count": len(forms),
                    "methods": sorted({str(form.get("method", "get")) for form in forms}),
                },
                "scroll_position": scroll,
                "recent_actions": [item.event for item in self._activity[-10:]],
                "authorized_hosts": self.authorization.allowed_domains,
                "allowed_url_prefixes": self.authorization.allowed_url_prefixes,
                "request_count": self._request_count,
                "pages_observed": len(self._pages),
            }
            self._record(
                "ai_observation",
                current_url,
                {
                    "title_present": snapshot["title_present"],
                    "in_scope_link_count": len(allowed_links),
                    "form_count": len(forms),
                    "scroll_y": scroll.get("y", 0),
                    "scroll_height": scroll.get("height", 0),
                    "request_count": self._request_count,
                },
            )
            try:
                proposal = self.ai_planner.propose(snapshot)
            except ProviderError as exc:
                self._record("ai_provider_error", current_url, {"reason": str(exc)[:180]})
                self.ai_planner = None
                return False
            except Exception as exc:
                self._record(
                    "ai_provider_error",
                    current_url,
                    {"reason": f"{type(exc).__name__}: {str(exc)[:140]}", "error_type": type(exc).__name__},
                )
                self.ai_planner = None
                return False

            proposal_id = uuid.uuid4().hex[:12]
            decision = self._agent_policy.decide(proposal, allowed_links, visited)
            effective_requires_approval = decision.requires_approval
            self._record(
                "ai_proposal",
                current_url,
                {
                    "proposal_id": proposal_id,
                    "objective": proposal.objective,
                    "action": proposal.action,
                    "target_id": proposal.target_id,
                    "reason": proposal.reason[:240],
                    "expected_result": proposal.expected_result,
                    "policy_allowed": decision.allowed,
                    "policy_reason": decision.reason,
                    "requires_approval": effective_requires_approval,
                },
            )
            self._record(
                "ai_policy_decision",
                current_url,
                {
                    "proposal_id": proposal_id,
                    "action": proposal.action,
                    "target_id": proposal.target_id,
                    "allowed": decision.allowed,
                    "requires_approval": effective_requires_approval,
                    "reason": decision.reason,
                    "destination": sanitize_url(decision.destination) if decision.destination else None,
                },
            )
            if not decision.allowed:
                self._record("ai_action_rejected", current_url, {"proposal_id": proposal_id, "reason": decision.reason})
                return False

            signature = (
                proposal.action,
                proposal.target_id,
                int(scroll.get("y", 0)) if proposal.action == "scroll" else None,
            )
            if signature in repeated_actions:
                self._record(
                    "ai_action_rejected",
                    current_url,
                    {"proposal_id": proposal_id, "reason": "repeated action made no new observation"},
                )
                return True
            repeated_actions.add(signature)

            if proposal.action in {"navigate", "click"} and depth >= self.limits.max_depth:
                self._record(
                    "ai_action_rejected",
                    current_url,
                    {"proposal_id": proposal_id, "reason": "navigation depth limit reached"},
                )
                return True

            if effective_requires_approval:
                if self.approval_gate is None:
                    self._record(
                        "approval_unavailable",
                        current_url,
                        {"proposal_id": proposal_id, "reason": "no approval interface is connected"},
                    )
                    return True
                approval_proposal = proposal.model_copy(update={"requires_approval": True})
                if not self.approval_gate(approval_proposal):
                    self._record(
                        "ai_action_rejected",
                        current_url,
                        {"proposal_id": proposal_id, "reason": "human approval was not granted"},
                    )
                    return True
                self._record(
                    "ai_action_approved",
                    current_url,
                    {"proposal_id": proposal_id, "action": proposal.action},
                )

            if proposal.action == "stop":
                self._record("ai_action_executed", current_url, {"proposal_id": proposal_id, "action": "stop"})
                self._record("ai_action_verified", current_url, {"proposal_id": proposal_id, "verified": True})
                self.stop()
                return True

            if proposal.action == "scroll":
                before = int(scroll.get("y", 0))
                page.mouse.wheel(0, 640)
                after = page.evaluate("() => Math.round(window.scrollY)")
                verified = int(after) > before
                self._record(
                    "ai_action_executed",
                    current_url,
                    {"proposal_id": proposal_id, "action": "scroll", "scroll_y": int(after)},
                )
                self._record(
                    "ai_action_verified",
                    current_url,
                    {"proposal_id": proposal_id, "action": "scroll", "verified": verified, "scroll_y": int(after)},
                )
                if not verified:
                    return True
                continue

            if proposal.action == "screenshot":
                screenshot_name = None
                captured = False
                if self.capture_screenshots:
                    path = self.output_dir / "screenshots" / f"{self.assessment_id}-agent-{proposal_id}.png"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(
                        path=str(path),
                        full_page=False,
                        animations="disabled",
                        timeout=self.limits.navigation_timeout_ms,
                    )
                    screenshot_name = path.name
                    captured = path.is_file() and path.stat().st_size > 0
                self._record(
                    "ai_action_executed",
                    current_url,
                    {"proposal_id": proposal_id, "action": "screenshot", "screenshot": screenshot_name},
                )
                self._record(
                    "ai_action_verified",
                    current_url,
                    {"proposal_id": proposal_id, "action": "screenshot", "verified": captured},
                )
                continue

            if proposal.action == "inspect":
                observed = page.evaluate(_PAGE_INSPECTOR)
                self._record(
                    "ai_action_executed",
                    current_url,
                    {"proposal_id": proposal_id, "action": "inspect"},
                )
                self._record(
                    "ai_action_verified",
                    current_url,
                    {
                        "proposal_id": proposal_id,
                        "action": "inspect",
                        "verified": sanitize_url(page.url) == sanitize_url(current_url),
                        "link_count": len(observed.get("links", [])),
                        "form_count": len(observed.get("forms", [])),
                    },
                )
                continue

            if proposal.action == "inspect_forms":
                observed_forms = page.evaluate("() => document.forms.length")
                self._record(
                    "ai_action_executed",
                    current_url,
                    {"proposal_id": proposal_id, "action": "inspect_forms"},
                )
                self._record(
                    "ai_action_verified",
                    current_url,
                    {
                        "proposal_id": proposal_id,
                        "action": "inspect_forms",
                        "verified": int(observed_forms) == len(forms),
                        "form_count": int(observed_forms),
                    },
                )
                continue

            if proposal.action == "inspect_network":
                endpoint_count = len(self._api_endpoints)
                self._record(
                    "ai_action_executed",
                    current_url,
                    {"proposal_id": proposal_id, "action": "inspect_network", "endpoint_count": endpoint_count},
                )
                self._record(
                    "ai_action_verified",
                    current_url,
                    {"proposal_id": proposal_id, "action": "inspect_network", "verified": True},
                )
                continue

            if proposal.action in {"navigate", "click"} and decision.destination:
                target_id = proposal.target_id or ""
                if proposal.action == "navigate":
                    queue.append((decision.destination, depth + 1, False, proposal_id))
                    self._record(
                        "ai_action_queued",
                        current_url,
                        {
                            "proposal_id": proposal_id,
                            "action": "navigate",
                            "target_id": target_id,
                            "destination": sanitize_url(decision.destination),
                        },
                    )
                    return True

                index = anchor_indices.get(target_id)
                if index is None:
                    self._record("ai_action_rejected", current_url, {"proposal_id": proposal_id, "reason": "link index is unavailable"})
                    return True
                anchor = page.locator("a[href]").nth(index)
                href = anchor.get_attribute("href")
                current_destination = urljoin(page.url, href or "")
                try:
                    self.guardian.validate_url(current_destination)
                except ScopeViolation:
                    self._record("ai_action_rejected", current_url, {"proposal_id": proposal_id, "reason": "link changed outside authorized scope"})
                    return True
                if sanitize_url(current_destination) != sanitize_url(decision.destination):
                    self._record("ai_action_rejected", current_url, {"proposal_id": proposal_id, "reason": "link changed after observation"})
                    return True
                target = anchor.get_attribute("target")
                download = anchor.get_attribute("download")
                onclick = anchor.get_attribute("onclick")
                if target not in {None, "", "_self"} or download is not None or onclick is not None:
                    self._record("ai_action_rejected", current_url, {"proposal_id": proposal_id, "reason": "link behavior changed after observation"})
                    return True
                self._record(
                    "ai_action_started",
                    current_url,
                    {"proposal_id": proposal_id, "action": "click", "target_id": target_id},
                )
                try:
                    anchor.click(timeout=self.limits.navigation_timeout_ms)
                except Exception as exc:
                    actual_url = page.url or current_url
                    self._record(
                        "ai_action_verified",
                        actual_url,
                        {
                            "proposal_id": proposal_id,
                            "action": "click",
                            "verified": False,
                            "expected_url": sanitize_url(decision.destination),
                            "actual_url": sanitize_url(actual_url),
                            "error_type": type(exc).__name__,
                        },
                    )
                    return True
                actual_url = page.url
                self.guardian.validate_url(actual_url)
                verified = sanitize_url(actual_url) == sanitize_url(decision.destination)
                self._record(
                    "ai_action_executed",
                    actual_url,
                    {"proposal_id": proposal_id, "action": "click", "target_id": target_id},
                )
                self._record(
                    "ai_action_verified",
                    actual_url,
                    {
                        "proposal_id": proposal_id,
                        "action": "click",
                        "verified": verified,
                        "expected_url": sanitize_url(decision.destination),
                        "actual_url": sanitize_url(actual_url),
                    },
                )
                if verified:
                    queue.append((actual_url, depth + 1, True, None))
                return True

        self._record("agent_stopped", observation.url, {"reason": "agent iteration limit reached"})
        return True

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
                details["status_code"] = response.status
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
        if datetime.now(timezone.utc) >= self.authorization.expires_at:
            if not self._stop.is_set():
                self._stop.set()
                self._record("authorization_expired", details={"reason": "authorization record expired during the browser run"})
            return
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
        if self.event_sink:
            try:
                self.event_sink(item)
            except Exception:
                # Event persistence must not weaken browser cleanup or scope enforcement.
                pass
        if self.live_logs:
            print(item.model_dump_json(), file=sys.stdout, flush=True)


_PAGE_INSPECTOR = """
() => {
  const trim = (value, max = 160) => (value || '').trim().replace(/\\s+/g, ' ').slice(0, max);
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500).map(a => ({
    url: a.href,
    text: trim(a.innerText || a.getAttribute('aria-label') || a.title),
    target: trim(a.getAttribute('target') || '', 40),
    download: a.hasAttribute('download'),
    has_onclick: a.hasAttribute('onclick')
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
