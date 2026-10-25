"""Loopback-only authenticated dashboard API for local assessments."""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .agent import OpenAICompatiblePlanner
from .auth import Session, SessionCodec, hash_password, verify_password
from .browser import SUPPORTED_BROWSER_CHANNELS
from .models import AuthorizationRecord, ScanLimits
from .report import render_html_report
from .scope import ScopeGuardian, ScopeViolation
from .store import Store, utc_now
from .target_validation import TargetInputError, head_probe, normalize_http_url
from .worker import ScanManager


IMPLEMENTED_CHECKS = [
    {"id": "passive_headers", "name": "HTTP security headers", "category": "Passive web security", "description": "Observe selected response headers on visited HTTPS documents.", "risk": "Low", "intensity": "Passive", "implemented": True},
    {"id": "passive_cookie_attributes", "name": "Cookie attributes", "category": "Passive web security", "description": "Inspect cookie attributes without storing cookie values.", "risk": "Low", "intensity": "Passive", "implemented": True},
    {"id": "passive_transport", "name": "HTTPS and transport observations", "category": "Passive web security", "description": "Record observed HTTP/HTTPS navigation and relevant transport headers.", "risk": "Low", "intensity": "Passive", "implemented": True},
    {"id": "passive_forms", "name": "Form security observations", "category": "Browser and application analysis", "description": "Discover forms and note password transport or an absent obvious CSRF field; forms are never submitted.", "risk": "Low", "intensity": "Passive", "implemented": True},
    {"id": "browser_discovery", "name": "Website and endpoint discovery", "category": "Browser and application analysis", "description": "Crawl same-scope pages and record browser-visible fetch/XHR endpoints.", "risk": "Low", "intensity": "Passive", "implemented": True},
]
UNSUPPORTED_CHECKS = [
    {"id": "passive_cors", "name": "CORS configuration", "category": "Passive web security", "description": "Not yet analyzed by the finding engine.", "risk": "Low", "intensity": "Passive", "implemented": False},
    {"id": "passive_disclosure", "name": "Information disclosure indicators", "category": "Passive web security", "description": "No broad disclosure rules are implemented yet.", "risk": "Low", "intensity": "Passive", "implemented": False},
    {"id": "passive_mixed_content", "name": "Mixed content", "category": "Passive web security", "description": "Mixed-content response analysis is not implemented yet.", "risk": "Low", "intensity": "Passive", "implemented": False},
    {"id": "passive_dependencies", "name": "Client-side dependency observations", "category": "Passive web security", "description": "Dependency fingerprint and known-vulnerability matching are not implemented.", "risk": "Low", "intensity": "Passive", "implemented": False},
    {"id": "browser_auth", "name": "Authentication and session flow", "category": "Browser and application analysis", "description": "Authenticated flows are not tested; approved test-account support is not implemented.", "risk": "Medium", "intensity": "Passive", "implemented": False},
    {"id": "browser_access_control", "name": "Browser-visible access control", "category": "Browser and application analysis", "description": "No access-control boundary testing is implemented.", "risk": "High", "intensity": "Active", "implemented": False},
    *[{"id": key, "name": title, "category": "Controlled active assessment", "description": "Disabled: active checks are not implemented. Use a separately approved staging workflow when available.", "risk": "High", "intensity": "Active", "implemented": False} for key, title in [("active_xss", "XSS testing"), ("active_sqli", "SQL injection testing"), ("active_idor", "IDOR/BOLA testing"), ("active_auth", "Authentication security testing"), ("active_boundary", "Authorization boundary testing"), ("active_csrf", "CSRF testing"), ("active_upload", "File upload validation testing")]],
]
CHECKS = IMPLEMENTED_CHECKS + UNSUPPORTED_CHECKS
CHECK_BY_ID = {check["id"]: check for check in CHECKS}
STATUS_VALUES = {"potential", "verified", "inconclusive", "false_positive", "resolved"}


def _ai_is_available() -> bool:
    try:
        return OpenAICompatiblePlanner.from_environment() is not None
    except ValueError:
        return False


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SetupPayload(StrictModel):
    bootstrap_token: str = Field(min_length=16, max_length=256)
    organization_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=256)


class LoginPayload(StrictModel):
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=1, max_length=256)


class TargetPayload(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    base_url: str = Field(min_length=8, max_length=2048)
    authorized_by: str = Field(min_length=2, max_length=200)
    authorization_reference: str = Field(min_length=2, max_length=500)
    expires_at: datetime
    documented_authorization: bool
    allow_loopback: bool = False
    allow_private_networks: bool = False


class ValidatePayload(StrictModel):
    url: str = Field(min_length=1, max_length=2048)
    target_id: str | None = None


class ScanPayload(StrictModel):
    target_id: str
    target_url: str = Field(min_length=1, max_length=2048)
    selected_checks: list[str] = Field(min_length=1, max_length=30)
    headless: bool = False
    capture_screenshots: bool = True
    ai_analysis: bool = False
    limits: ScanLimits = Field(default_factory=ScanLimits)


class FindingStatusPayload(StrictModel):
    status: Literal["potential", "verified", "inconclusive", "false_positive", "resolved"]


class ApprovalPayload(StrictModel):
    approved: bool


def create_app(
    data_dir: str | Path | None = None,
    *,
    bootstrap_token: str | None = None,
    start_worker: bool = True,
) -> FastAPI:
    root = Path(data_dir or os.environ.get("SENTINEL_DATA_DIR", "artifacts/sentinel"))
    root.mkdir(parents=True, exist_ok=True)
    store = Store(root / "sentinel.sqlite3")
    secret = os.environ.get("SENTINEL_SESSION_SECRET")
    secret_path = root / ".session-secret"
    if not secret:
        try:
            secret = secret_path.read_text(encoding="utf-8").strip()
        except OSError:
            secret = secrets.token_urlsafe(48)
            try:
                secret_path.write_text(secret, encoding="utf-8")
            except OSError:
                pass
        if len(secret) < 32:
            secret = secrets.token_urlsafe(48)
        os.environ["SENTINEL_SESSION_SECRET"] = secret
    codec = SessionCodec(secret)
    bootstrap = bootstrap_token or os.environ.get("SENTINEL_BOOTSTRAP_TOKEN") or secrets.token_urlsafe(24)
    manager = ScanManager(store, root / "scans")
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if start_worker:
            manager.start()
        try:
            yield
        finally:
            if start_worker:
                manager.shutdown()

    app = FastAPI(title="Sentinel AI", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.codec = codec
    app.state.bootstrap_token = bootstrap
    app.state.manager = manager
    app.state.root = root

    def require_loopback(request: Request) -> None:
        host = request.client.host if request.client else ""
        if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            raise HTTPException(403, "This local dashboard only accepts loopback connections.")

    def session_for(request: Request) -> Session:
        require_loopback(request)
        session = codec.decode(request.cookies.get("sentinel_session"))
        if not session or not store.user_by_id(session.user_id, session.organization_id):
            raise HTTPException(401, "Sign in to continue.")
        return session

    def csrf(request: Request, x_csrf_token: str | None = Header(default=None)) -> None:
        session = codec.decode(request.cookies.get("sentinel_session"))
        if not session or not x_csrf_token or not hmac.compare_digest(session.csrf, x_csrf_token):
            raise HTTPException(403, "CSRF validation failed.")

    def require_owner(session: Session = Depends(session_for)) -> Session:
        if session.role != "owner":
            raise HTTPException(403, "Only the organization owner can change authorization records.")
        return session

    def target_or_404(target_id: str, session: Session) -> dict[str, Any]:
        target = store.get_target(target_id, session.organization_id)
        if not target:
            raise HTTPException(404, "Authorized target not found.")
        return target

    @app.get("/api/health")
    def health(request: Request) -> dict[str, Any]:
        require_loopback(request)
        return {"ok": True, "service": "sentinel-ai", "local_only": True}

    @app.get("/api/auth/state")
    def auth_state(request: Request) -> dict[str, Any]:
        require_loopback(request)
        return {"setup_required": not store.has_users()}

    @app.post("/api/auth/setup")
    def setup(payload: SetupPayload, response: Response, request: Request) -> dict[str, Any]:
        require_loopback(request)
        if store.has_users():
            raise HTTPException(409, "Initial owner has already been created.")
        if not hmac.compare_digest(payload.bootstrap_token, app.state.bootstrap_token):
            raise HTTPException(403, "Bootstrap token is incorrect. Use the token printed by the server.")
        try:
            user = store.bootstrap_owner(payload.email, hash_password(payload.password), payload.organization_name)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        store.add_audit(user["organization_id"], user["user_id"], "auth.owner_bootstrapped", {})
        token, csrf_token = codec.issue({"id": user["user_id"], "organization_id": user["organization_id"], "email": user["email"], "role": user["role"]})
        response.set_cookie("sentinel_session", token, httponly=True, samesite="strict", secure=False, max_age=8 * 3600, path="/")
        response.set_cookie("sentinel_csrf", csrf_token, httponly=False, samesite="strict", secure=False, max_age=8 * 3600, path="/")
        return {"user": {"email": user["email"], "role": user["role"]}, "csrf_token": csrf_token}

    @app.post("/api/auth/login")
    def login(payload: LoginPayload, response: Response, request: Request) -> dict[str, Any]:
        require_loopback(request)
        user = store.user_by_email(payload.email)
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(401, "Email or password is incorrect.")
        token, csrf_token = codec.issue(user)
        response.set_cookie("sentinel_session", token, httponly=True, samesite="strict", secure=False, max_age=8 * 3600, path="/")
        response.set_cookie("sentinel_csrf", csrf_token, httponly=False, samesite="strict", secure=False, max_age=8 * 3600, path="/")
        store.add_audit(user["organization_id"], user["id"], "auth.login", {})
        return {"user": {"email": user["email"], "role": user["role"]}, "csrf_token": csrf_token}

    @app.post("/api/auth/logout")
    def logout(response: Response, request: Request, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, bool]:
        store.add_audit(session.organization_id, session.user_id, "auth.logout", {})
        response.delete_cookie("sentinel_session", path="/")
        response.delete_cookie("sentinel_csrf", path="/")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(session: Session = Depends(session_for)) -> dict[str, Any]:
        return {"email": session.email, "role": session.role, "organization_id": session.organization_id}

    @app.get("/api/dashboard")
    def dashboard(session: Session = Depends(session_for)) -> dict[str, Any]:
        return {"metrics": store.metrics(session.organization_id), "worker": manager.status(), "ai_available": _ai_is_available(), "checks": CHECKS}

    @app.get("/api/checks")
    def checks(_session: Session = Depends(session_for)) -> dict[str, Any]:
        return {"checks": CHECKS, "implemented_ids": [c["id"] for c in IMPLEMENTED_CHECKS]}

    @app.get("/api/worker")
    def worker(session: Session = Depends(session_for)) -> dict[str, Any]:
        return manager.status()

    @app.get("/api/targets")
    def targets(session: Session = Depends(session_for)) -> list[dict[str, Any]]:
        return store.list_targets(session.organization_id)

    @app.post("/api/targets")
    def create_target(payload: TargetPayload, _csrf: None = Depends(csrf), session: Session = Depends(require_owner)) -> dict[str, Any]:
        if not payload.documented_authorization:
            raise HTTPException(400, "Confirm that written client authorization covers this assessment scope.")
        try:
            base_url, parsed = normalize_http_url(payload.base_url)
            expires = payload.expires_at
            if expires.tzinfo is None or expires.utcoffset() is None:
                raise TargetInputError("Authorization expiry must include a timezone.")
            origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            prefix_path = parsed.path.rstrip("/") or "/"
            prefix = origin + (prefix_path if prefix_path == "/" else prefix_path + "/")
            authorization = AuthorizationRecord(
                authorized_by=payload.authorized_by,
                authorization_reference=payload.authorization_reference,
                expires_at=expires,
                allowed_domains=[parsed.hostname or ""],
                allowed_url_prefixes=[prefix],
                allow_loopback=payload.allow_loopback,
                allow_private_networks=payload.allow_private_networks,
            )
        except (TargetInputError, ValidationError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        # Target registration itself performs no DNS lookup or network probe. Address and
        # reachability checks happen after this explicit authorization record is stored.
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            address = None
        if address is not None:
            if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise HTTPException(422, "Link-local, reserved, multicast and unspecified addresses are blocked.")
            if address.is_loopback and not payload.allow_loopback:
                raise HTTPException(422, "Loopback targets require the explicit loopback authorization option.")
            if address.is_private and not address.is_loopback and not payload.allow_private_networks:
                raise HTTPException(422, "Private network targets require the explicit private network authorization option.")
        target = store.create_target({
            "organization_id": session.organization_id, "name": payload.name.strip(), "base_url": base_url,
            "authorization": authorization.model_dump(mode="json"),
            "authorization_reference": payload.authorization_reference.strip(), "authorized_by": payload.authorized_by.strip(),
            "expires_at": expires.astimezone(timezone.utc).isoformat(), "created_by": session.user_id,
        })
        store.add_audit(session.organization_id, session.user_id, "target.authorization_created", {"target_id": target["id"], "reference": payload.authorization_reference[:120]})
        return {key: value for key, value in target.items() if key != "authorization"}

    @app.post("/api/targets/validate")
    def validate_target(payload: ValidatePayload, session: Session = Depends(session_for)) -> dict[str, Any]:
        try:
            normalized, _ = normalize_http_url(payload.url)
        except TargetInputError as exc:
            return {"state": "invalid", "normalized_url": None, "error": str(exc)}
        if not payload.target_id:
            return {"state": "authorization_required", "normalized_url": normalized, "error": "Register a target and record client authorization before probing or scanning it."}
        target = target_or_404(payload.target_id, session)
        try:
            authorization = AuthorizationRecord.model_validate(target["authorization"])
            guardian = ScopeGuardian(authorization)
            guardian.validate_url(normalized)
        except ScopeViolation as exc:
            if "DNS resolution failed" in str(exc) or "no IP addresses resolved" in str(exc):
                return {"state": "unreachable", "normalized_url": normalized, "target_id": target["id"], "error": str(exc)}
            return {"state": "unauthorized", "normalized_url": normalized, "target_id": target["id"], "error": str(exc)}
        except (ValidationError, ValueError) as exc:
            return {"state": "unauthorized", "normalized_url": normalized, "target_id": target["id"], "error": str(exc)}
        probe = head_probe(normalized, authorization)
        return {"state": "reachable" if probe.reachable and probe.state == "reachable" else probe.state, "normalized_url": normalized, "target_id": target["id"], **probe.__dict__}

    @app.post("/api/scans")
    def create_scan(payload: ScanPayload, request: Request, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        if not manager.status().get("connected"):
            raise HTTPException(503, "Local assessment worker is disconnected.")
        target = target_or_404(payload.target_id, session)
        unsupported = [check for check in payload.selected_checks if check not in CHECK_BY_ID or not CHECK_BY_ID[check]["implemented"]]
        if unsupported:
            raise HTTPException(422, {"message": "One or more selected checks are not implemented.", "checks": unsupported})
        try:
            normalized, _ = normalize_http_url(payload.target_url)
            authorization = AuthorizationRecord.model_validate(target["authorization"])
            ScopeGuardian(authorization).validate_url(normalized)
        except (TargetInputError, ScopeViolation, ValidationError, ValueError) as exc:
            raise HTTPException(422, f"Target validation failed: {exc}") from exc
        probe = head_probe(normalized, authorization)
        if not probe.reachable or probe.state != "reachable":
            raise HTTPException(422, {"message": "Target did not pass authorization and reachability validation.", "probe": probe.__dict__})
        browser_channel = os.environ.get("SENTINEL_BROWSER_CHANNEL", "chromium").strip().lower()
        if browser_channel not in SUPPORTED_BROWSER_CHANNELS:
            raise HTTPException(503, "SENTINEL_BROWSER_CHANNEL must name a supported Playwright Chromium channel.")
        config = {
            "target_url": normalized, "selected_checks": payload.selected_checks, "headless": payload.headless,
            "capture_screenshots": payload.capture_screenshots, "ai_analysis": payload.ai_analysis,
            "browser_channel": browser_channel,
            "limits": payload.limits.model_dump(mode="json"), "report_formats": ["html", "json", "pdf"],
        }
        scan = store.create_scan({"organization_id": session.organization_id, "target_id": target["id"], "config": config, "created_by": session.user_id})
        store.add_audit(session.organization_id, session.user_id, "scan.created", {"scan_id": scan["id"], "target_id": target["id"], "checks": payload.selected_checks})
        store.append_event(session.organization_id, scan["id"], {"event": "job_queued", "timestamp": utc_now(), "url": normalized, "details": {"worker_id": "local"}})
        manager.notify_new_job()
        return _public_scan(scan)

    @app.get("/api/scans")
    def scans(session: Session = Depends(session_for)) -> list[dict[str, Any]]:
        return [_public_scan(scan) for scan in store.list_scans(session.organization_id)]

    @app.get("/api/scans/{scan_id}")
    def scan_detail(scan_id: str, session: Session = Depends(session_for)) -> dict[str, Any]:
        scan = store.get_scan(scan_id, session.organization_id)
        if not scan:
            raise HTTPException(404, "Assessment not found.")
        events = store.events_after(scan_id, session.organization_id, limit=1000)
        approvals = store.pending_approvals(scan_id, session.organization_id)
        current_url = next((event["url"] for event in reversed(events) if event.get("event") == "page_observed" and event.get("url")), scan["config"]["target_url"])
        return {**_public_scan(scan), "current_url": current_url, "events": events, "approvals": approvals, "worker": manager.status(), "ai_available": _ai_is_available()}

    @app.post("/api/scans/{scan_id}/pause")
    def pause(scan_id: str, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        if not manager.pause(scan_id, session.organization_id):
            raise HTTPException(409, "Assessment is not currently running or cannot be paused.")
        return {"ok": True, "status": "paused"}

    @app.post("/api/scans/{scan_id}/resume")
    def resume(scan_id: str, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        if not manager.resume(scan_id, session.organization_id):
            raise HTTPException(409, "Assessment is not currently paused or cannot be resumed.")
        return {"ok": True, "status": "running"}

    @app.post("/api/scans/{scan_id}/stop")
    def stop(scan_id: str, emergency: bool = False, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        if not manager.stop(scan_id, session.organization_id, emergency=emergency):
            raise HTTPException(409, "Assessment is not active.")
        return {"ok": True, "status": "cancelled", "emergency": emergency}

    @app.get("/api/scans/{scan_id}/events")
    async def stream_events(scan_id: str, request: Request, session: Session = Depends(session_for), after: int = 0) -> StreamingResponse:
        if not store.get_scan(scan_id, session.organization_id):
            raise HTTPException(404, "Assessment not found.")
        async def generate():
            cursor = max(after, 0)
            idle = 0
            while idle < 300:
                if await request.is_disconnected():
                    break
                events = store.events_after(scan_id, session.organization_id, cursor, 200)
                if events:
                    idle = 0
                    for event in events:
                        cursor = event["id"]
                        yield f"id: {cursor}\nevent: activity\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
                else:
                    idle += 1
                    scan = store.get_scan(scan_id, session.organization_id)
                    if scan and scan["status"] in {"completed", "failed", "cancelled"}:
                        yield "event: done\ndata: {}\n\n"
                        break
                    yield ": heartbeat\n\n"
                    await __import__("asyncio").sleep(1)
        return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/findings")
    def findings(scan_id: str | None = None, status: str | None = None, session: Session = Depends(session_for)) -> list[dict[str, Any]]:
        if status and status not in STATUS_VALUES:
            raise HTTPException(422, "Unknown finding status.")
        if scan_id and not store.get_scan(scan_id, session.organization_id):
            raise HTTPException(404, "Assessment not found.")
        return store.list_findings(session.organization_id, scan_id, status)

    @app.patch("/api/findings/{finding_id}")
    def update_finding(finding_id: str, payload: FindingStatusPayload, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        if not store.update_finding_status(finding_id, session.organization_id, payload.status):
            raise HTTPException(404, "Finding not found.")
        store.add_audit(session.organization_id, session.user_id, "finding.status_changed", {"finding_id": finding_id, "status": payload.status})
        return {"ok": True, "status": payload.status}

    @app.get("/api/scans/{scan_id}/approvals")
    def approvals(scan_id: str, session: Session = Depends(session_for)) -> list[dict[str, Any]]:
        if not store.get_scan(scan_id, session.organization_id):
            raise HTTPException(404, "Assessment not found.")
        return store.pending_approvals(scan_id, session.organization_id)

    @app.post("/api/approvals/{approval_id}")
    def resolve_approval(approval_id: str, payload: ApprovalPayload, _csrf: None = Depends(csrf), session: Session = Depends(session_for)) -> dict[str, Any]:
        approval = store.get_approval(approval_id, session.organization_id)
        if not approval:
            raise HTTPException(404, "Approval request not found.")
        if not store.resolve_approval(approval_id, session.organization_id, session.user_id, payload.approved):
            raise HTTPException(409, "Approval request has already been resolved.")
        manager.resolve_approval(approval_id)
        store.add_audit(session.organization_id, session.user_id, "agent.action_approval_resolved", {"approval_id": approval_id, "approved": payload.approved})
        return {"ok": True, "approved": payload.approved}

    @app.get("/api/audit")
    def audit(session: Session = Depends(session_for)) -> list[dict[str, Any]]:
        return store.list_audit(session.organization_id)

    @app.get("/api/scans/{scan_id}/report.{format}")
    def report(scan_id: str, format: Literal["html", "json", "pdf"], session: Session = Depends(session_for)) -> Response:
        scan = store.get_scan(scan_id, session.organization_id)
        if not scan:
            raise HTTPException(404, "Assessment not found.")
        if scan["status"] != "completed" or not scan["result"]:
            raise HTTPException(409, "A report is available after the assessment completes.")
        report_data = scan["result"]
        latest_statuses = {
            finding["id"].split(":", 1)[1]: finding["status"]
            for finding in store.list_findings(session.organization_id, scan_id)
            if ":" in finding["id"]
        }
        report_data = {**report_data, "findings": [
            {**finding, "status": latest_statuses.get(finding["id"], finding.get("status", "potential"))}
            for finding in report_data.get("findings", [])
        ]}
        if format == "json":
            content = json.dumps(report_data, indent=2, ensure_ascii=False)
            return Response(content, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="sentinel-{scan_id}.json"'})
        from .models import AssessmentResult
        result = AssessmentResult.model_validate(report_data)
        if format == "html":
            return HTMLResponse(render_html_report(result), headers={"Content-Disposition": f'attachment; filename="sentinel-{scan_id}.html"'})
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content(render_html_report(result), wait_until="load")
                pdf = page.pdf(format="A4", print_background=True, prefer_css_page_size=True)
                browser.close()
        except Exception as exc:
            raise HTTPException(503, f"PDF export unavailable: {type(exc).__name__}. HTML and JSON reports remain available.") from exc
        return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="sentinel-{scan_id}.pdf"'})

    @app.get("/api/scans/{scan_id}/screenshots/{filename}")
    def screenshot(scan_id: str, filename: str, session: Session = Depends(session_for)) -> FileResponse:
        scan = store.get_scan(scan_id, session.organization_id)
        if not scan or Path(filename).name != filename or not filename.lower().endswith(".png"):
            raise HTTPException(404, "Screenshot not found.")
        directory = (root / "scans" / scan_id / "screenshots").resolve()
        path = (directory / filename).resolve()
        if directory not in path.parents or not path.is_file():
            raise HTTPException(404, "Screenshot not found.")
        return FileResponse(path, media_type="image/png")

    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        require_loopback(request)
        return HTMLResponse((static_dir / "index.html").read_text(encoding="utf-8"))

    return app


def _public_scan(scan: dict[str, Any]) -> dict[str, Any]:
    return {key: scan.get(key) for key in (
        "id", "organization_id", "target_id", "target_name", "base_url", "authorization_reference", "status",
        "error", "pages_count", "requests_count", "created_at", "started_at", "completed_at", "config",
    )}


app = create_app()
