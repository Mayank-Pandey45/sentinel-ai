"""Single-process local worker that executes persisted assessment jobs."""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .agent import ActionProposal, OpenAICompatiblePlanner
from .browser import BrowserController
from .models import ActivityEvent, AuthorizationRecord, ScanLimits
from .store import Store, utc_now


class ScanManager:
    """A deliberately single-worker executor for loopback/local deployments."""

    def __init__(self, store: Store, output_root: str | Path, *, poll_seconds: float = 0.25):
        self.store = store
        self.output_root = Path(output_root)
        self.poll_seconds = poll_seconds
        self._shutdown = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._controllers: dict[str, BrowserController] = {}
        self._approval_events: dict[str, threading.Event] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._shutdown.clear()
        self.store.recover_interrupted_scans()
        self._thread = threading.Thread(target=self._run, name="sentinel-local-worker", daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        self._shutdown.set()
        self._wake.set()
        with self._lock:
            controllers = list(self._controllers.values())
        for controller in controllers:
            controller.stop()
        if self._thread:
            self._thread.join(timeout=5)
        self.store.heartbeat("local", "stopped", "local", ["passive-browser-assessment"])

    def notify_new_job(self) -> None:
        self._wake.set()

    def status(self) -> dict[str, Any]:
        worker = self.store.worker("local")
        browser_channel = os.environ.get("SENTINEL_BROWSER_CHANNEL", "chromium").strip().lower()
        if not worker:
            return {
                "connected": False,
                "worker_id": "local",
                "mode": "local",
                "browser_channel": browser_channel,
                "last_heartbeat": None,
            }
        try:
            heartbeat = datetime.fromisoformat(worker["last_heartbeat"])
            if heartbeat.tzinfo is None:
                heartbeat = heartbeat.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - heartbeat).total_seconds()
        except (TypeError, ValueError):
            age = 999999
        return {
            **worker,
            "connected": worker["status"] == "connected" and age < 10,
            "heartbeat_age_seconds": round(age, 1),
            "browser_channel": browser_channel,
        }

    def pause(self, scan_id: str, organization_id: str) -> bool:
        scan = self.store.get_scan(scan_id, organization_id)
        if not scan or scan["status"] != "running":
            return False
        with self._lock:
            controller = self._controllers.get(scan_id)
        if not controller:
            return False
        controller.pause()
        self.store.update_scan(scan_id, status="paused")
        self.store.add_audit(organization_id, None, "scan.paused", {"scan_id": scan_id})
        return True

    def resume(self, scan_id: str, organization_id: str) -> bool:
        scan = self.store.get_scan(scan_id, organization_id)
        if not scan or scan["status"] != "paused":
            return False
        with self._lock:
            controller = self._controllers.get(scan_id)
        if not controller:
            return False
        controller.resume()
        self.store.update_scan(scan_id, status="running")
        self.store.add_audit(organization_id, None, "scan.resumed", {"scan_id": scan_id})
        return True

    def stop(self, scan_id: str, organization_id: str, *, emergency: bool = False) -> bool:
        scan = self.store.get_scan(scan_id, organization_id)
        if not scan or scan["status"] not in {"queued", "validating", "running", "paused", "waiting_approval"}:
            return False
        with self._lock:
            controller = self._controllers.get(scan_id)
        self.store.update_scan(scan_id, status="cancelled", cancel_requested=True, completed_at=utc_now())
        self.store.add_audit(organization_id, None, "scan.emergency_stop" if emergency else "scan.stop_requested", {"scan_id": scan_id})
        if controller:
            controller.emergency_stop() if emergency else controller.stop()
        with self._lock:
            for event in self._approval_events.values():
                event.set()
        return True

    def resolve_approval(self, approval_id: str) -> None:
        with self._lock:
            event = self._approval_events.get(approval_id)
        if event:
            event.set()

    def _run(self) -> None:
        while not self._shutdown.is_set():
            self.store.heartbeat("local", "connected", "local", ["passive-browser-assessment", "html-report", "json-export"])
            scan = self.store.next_queued_scan()
            if scan:
                self._execute(scan)
                continue
            self._wake.wait(self.poll_seconds)
            self._wake.clear()
        self.store.heartbeat("local", "stopped", "local", ["passive-browser-assessment"])

    def _execute(self, scan: dict[str, Any]) -> None:
        scan_id = scan["id"]
        organization_id = scan["organization_id"]
        self.store.update_scan(scan_id, status="validating", started_at=utc_now(), error=None)
        self.store.append_event(organization_id, scan_id, {
            "event": "job_validating", "timestamp": utc_now(), "url": None, "details": {"worker_id": "local"},
        })
        queued_state = self.store.get_scan_internal(scan_id)
        if queued_state and queued_state["cancel_requested"]:
            self.store.update_scan(scan_id, status="cancelled", completed_at=utc_now())
            self.store.append_event(organization_id, scan_id, {
                "event": "job_cancelled", "timestamp": utc_now(), "url": None,
                "details": {"reason": "Cancelled before browser launch"},
            })
            return
        try:
            target = self.store.get_target(scan["target_id"], organization_id)
            if not target:
                raise RuntimeError("Authorized target record is no longer available")
            authorization = AuthorizationRecord.model_validate(target["authorization"])
            config = scan["config"]
            output_dir = self.output_root / scan_id
            provider_error = None
            try:
                planner = OpenAICompatiblePlanner.from_environment() if config.get("ai_analysis") else None
            except ValueError as exc:
                planner = None
                provider_error = f"Provider configuration rejected ({type(exc).__name__}); passive scanning will continue."
            if config.get("ai_analysis") and planner is None:
                self.store.append_event(organization_id, scan_id, {
                    "event": "ai_unavailable", "timestamp": utc_now(), "url": None,
                    "details": {"reason": provider_error or "Configure SENTINEL_AI_API_KEY and SENTINEL_AI_MODEL (SENTINEL_AI_BASE_URL is optional). Passive scanning will continue."},
                })
            controller = BrowserController(
                authorization,
                config["target_url"],
                output_dir,
                ScanLimits.model_validate(config["limits"]),
                headless=bool(config.get("headless", False)),
                live_logs=False,
                capture_screenshots=bool(config.get("capture_screenshots", True)),
                selected_checks=config.get("selected_checks", []),
                browser_channel=config.get("browser_channel", os.environ.get("SENTINEL_BROWSER_CHANNEL", "chromium")),
                ai_planner=planner,
                approval_gate=lambda proposal: self._approval_gate(scan_id, organization_id, proposal),
                event_sink=lambda event: self._persist_event(organization_id, scan_id, event),
            )
            with self._lock:
                self._controllers[scan_id] = controller
            current = self.store.get_scan_internal(scan_id)
            if current and current["cancel_requested"]:
                controller.stop()
                self.store.update_scan(scan_id, status="cancelled", completed_at=utc_now())
                self.store.append_event(organization_id, scan_id, {
                    "event": "job_cancelled", "timestamp": utc_now(), "url": None,
                    "details": {"reason": "Cancelled before browser launch"},
                })
                return
            else:
                self.store.update_scan(scan_id, status="running")
                self.store.append_event(organization_id, scan_id, {
                    "event": "job_running", "timestamp": utc_now(), "url": config["target_url"],
                    "details": {
                        "worker_id": "local",
                        "browser_mode": "headless" if config.get("headless") else "visible",
                        "browser_channel": config.get("browser_channel", os.environ.get("SENTINEL_BROWSER_CHANNEL", "chromium")),
                        "chromium_sandbox": True,
                    },
                })
            result = controller.run()
            serialized = result.model_dump(mode="json")
            self.store.save_result(scan_id, organization_id, serialized)
            for finding in serialized.get("findings", []):
                self.store.append_event(organization_id, scan_id, {
                    "event": "finding_identified", "timestamp": finding.get("detected_at", utc_now()),
                    "url": (finding.get("affected_endpoints") or [None])[0],
                    "details": {"finding_id": finding.get("id"), "title": finding.get("title"),
                                "severity": finding.get("severity"), "confidence": finding.get("confidence")},
                })
            current = self.store.get_scan_internal(scan_id)
            cancelled = bool(current and current["cancel_requested"])
            status = "cancelled" if cancelled else "completed"
            self.store.update_scan(scan_id, status=status, completed_at=utc_now())
            self.store.add_audit(organization_id, scan["created_by"], f"scan.{status}", {"scan_id": scan_id})
            self.store.append_event(organization_id, scan_id, {
                "event": f"job_{status}", "timestamp": utc_now(), "url": None,
                "details": {"pages": len(result.pages), "requests": sum(1 for item in result.activity if item.event == "request_allowed")},
            })
        except Exception as exc:
            current = self.store.get_scan_internal(scan_id)
            cancelled = bool(current and current["cancel_requested"])
            status = "cancelled" if cancelled else "failed"
            safe_error = f"{type(exc).__name__}: {str(exc)[:450]}"
            self.store.update_scan(scan_id, status=status, error=safe_error, completed_at=utc_now())
            self.store.add_audit(organization_id, scan["created_by"], f"scan.{status}", {"scan_id": scan_id, "error": type(exc).__name__})
            self.store.append_event(organization_id, scan_id, {
                "event": f"job_{status}", "timestamp": utc_now(), "url": None, "details": {"error": safe_error},
            })
        finally:
            with self._lock:
                self._controllers.pop(scan_id, None)
            self.store.heartbeat("local", "connected", "local", ["passive-browser-assessment", "html-report", "json-export"])

    def _persist_event(self, organization_id: str, scan_id: str, event: ActivityEvent) -> None:
        data = event.model_dump(mode="json")
        self.store.append_event(organization_id, scan_id, data)
        if event.event == "paused":
            self.store.update_scan(scan_id, status="paused")
        elif event.event == "resumed":
            self.store.update_scan(scan_id, status="running")
        elif event.event == "page_observed":
            self.store.update_scan(scan_id, pages_count=int(event.details.get("page_count", 0)))
        elif event.event == "request_allowed":
            scan = self.store.get_scan_internal(scan_id)
            if scan:
                self.store.update_scan(scan_id, requests_count=scan["requests_count"] + 1)

    def _approval_gate(self, scan_id: str, organization_id: str, proposal: ActionProposal) -> bool:
        approval_id = self.store.create_approval(organization_id, scan_id, proposal.model_dump(mode="json"))
        event = threading.Event()
        with self._lock:
            self._approval_events[approval_id] = event
        self.store.update_scan(scan_id, status="waiting_approval")
        self.store.append_event(organization_id, scan_id, {
            "event": "approval_requested", "timestamp": utc_now(), "url": None,
            "details": {"approval_id": approval_id, "objective": proposal.objective, "action": proposal.action,
                        "reason": proposal.reason, "expected_result": proposal.expected_result},
        })
        deadline = time.monotonic() + 300
        try:
            while time.monotonic() < deadline:
                if event.wait(0.25):
                    break
                current = self.store.get_scan_internal(scan_id)
                if self._shutdown.is_set() or not current or current["cancel_requested"]:
                    return False
            approval = self.store.get_approval(approval_id, organization_id)
            if not approval or approval["status"] != "approved":
                if approval and approval["status"] == "pending":
                    with self.store.connection() as db:
                        db.execute("UPDATE approvals SET status='expired', resolved_at=? WHERE id=? AND status='pending'", (utc_now(), approval_id))
                return False
            return True
        finally:
            self.store.update_scan(scan_id, status="running")
            with self._lock:
                self._approval_events.pop(approval_id, None)
