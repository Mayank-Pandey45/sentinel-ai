"""SQLite persistence for the local dashboard and assessment worker."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class Store:
    """Small SQLite store. Every lookup that belongs to a user is organization-scoped."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    email TEXT NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('owner', 'analyst', 'viewer')),
                    created_at TEXT NOT NULL,
                    UNIQUE (organization_id, email)
                );
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    name TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    authorization_json TEXT NOT NULL,
                    authorization_reference TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    target_id TEXT NOT NULL REFERENCES targets(id),
                    status TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    pages_count INTEGER NOT NULL DEFAULT 0,
                    requests_count INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS scans_org_created ON scans(organization_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS scans_queue ON scans(status, created_at);
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    affected_endpoints_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    cwe TEXT,
                    owasp_reference TEXT,
                    business_impact TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    retest_guidance TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS findings_org_severity ON findings(organization_id, severity, status);
                CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    event TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    url TEXT,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_scan_id ON scan_events(scan_id, id);
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    proposal_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolved_by TEXT REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL REFERENCES organizations(id),
                    user_id TEXT REFERENCES users(id),
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_org_time ON audit_logs(organization_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS workers (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    last_heartbeat TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL
                );
                """
            )

    def bootstrap_owner(self, email: str, password_hash: str, organization_name: str) -> dict[str, str]:
        with self.connection() as db:
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise ValueError("initial owner has already been created")
            organization_id, user_id, now = new_id(), new_id(), utc_now()
            db.execute(
                "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
                (organization_id, organization_name, now),
            )
            db.execute(
                "INSERT INTO users(id, organization_id, email, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, 'owner', ?)",
                (user_id, organization_id, email.strip().lower(), password_hash, now),
            )
            return {"user_id": user_id, "organization_id": organization_id, "email": email.strip().lower(), "role": "owner"}

    def has_users(self) -> bool:
        with self.connection() as db:
            return db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def user_by_email(self, email: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT id, organization_id, email, password_hash, role FROM users WHERE email = ? COLLATE NOCASE",
                (email.strip(),),
            ).fetchone()
            return dict(row) if row else None

    def user_by_id(self, user_id: str, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT id, organization_id, email, role FROM users WHERE id = ? AND organization_id = ?",
                (user_id, organization_id),
            ).fetchone()
            return dict(row) if row else None

    def create_target(self, values: dict[str, Any]) -> dict[str, Any]:
        target_id = new_id()
        with self.connection() as db:
            db.execute(
                "INSERT INTO targets(id, organization_id, name, base_url, authorization_json, "
                "authorization_reference, authorized_by, expires_at, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id, values["organization_id"], values["name"], values["base_url"],
                    _json(values["authorization"]), values["authorization_reference"], values["authorized_by"],
                    values["expires_at"], values["created_by"], utc_now(),
                ),
            )
        return self.get_target(target_id, values["organization_id"]) or {}

    def get_target(self, target_id: str, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM targets WHERE id = ? AND organization_id = ?",
                (target_id, organization_id),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["authorization"] = json.loads(result.pop("authorization_json"))
        return result

    def list_targets(self, organization_id: str) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT id, organization_id, name, base_url, authorization_reference, authorized_by, expires_at, created_at "
                "FROM targets WHERE organization_id = ? ORDER BY created_at DESC",
                (organization_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_scan(self, values: dict[str, Any]) -> dict[str, Any]:
        scan_id = new_id()
        now = utc_now()
        with self.connection() as db:
            db.execute(
                "INSERT INTO scans(id, organization_id, target_id, status, config_json, created_by, created_at) "
                "VALUES (?, ?, ?, 'queued', ?, ?, ?)",
                (scan_id, values["organization_id"], values["target_id"], _json(values["config"]), values["created_by"], now),
            )
        return self.get_scan(scan_id, values["organization_id"]) or {}

    def get_scan(self, scan_id: str, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT s.*, t.name AS target_name, t.base_url, t.authorization_reference "
                "FROM scans s JOIN targets t ON t.id = s.target_id "
                "WHERE s.id = ? AND s.organization_id = ? AND t.organization_id = ?",
                (scan_id, organization_id, organization_id),
            ).fetchone()
        return self._scan_dict(row) if row else None

    def get_scan_internal(self, scan_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_dict(row) if row else None

    @staticmethod
    def _scan_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["config"] = json.loads(result.pop("config_json"))
        encoded_result = result.pop("result_json")
        result["result"] = json.loads(encoded_result) if encoded_result else None
        result["cancel_requested"] = bool(result["cancel_requested"])
        return result

    def list_scans(self, organization_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT s.*, t.name AS target_name, t.base_url, t.authorization_reference "
                "FROM scans s JOIN targets t ON t.id = s.target_id "
                "WHERE s.organization_id = ? AND t.organization_id = ? "
                "ORDER BY s.created_at DESC LIMIT ?",
                (organization_id, organization_id, min(max(limit, 1), 500)),
            ).fetchall()
        return [self._scan_dict(row) for row in rows]

    def next_queued_scan(self) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM scans WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
        return self._scan_dict(row) if row else None

    def update_scan(self, scan_id: str, **values: Any) -> None:
        permitted = {"status", "error", "started_at", "completed_at", "cancel_requested", "pages_count", "requests_count"}
        updates = {key: value for key, value in values.items() if key in permitted}
        if not updates:
            return
        if "cancel_requested" in updates:
            updates["cancel_requested"] = int(bool(updates["cancel_requested"]))
        statement = ", ".join(f"{key} = ?" for key in updates)
        with self.connection() as db:
            db.execute(f"UPDATE scans SET {statement} WHERE id = ?", (*updates.values(), scan_id))

    def recover_interrupted_scans(self) -> None:
        with self.connection() as db:
            db.execute(
                "UPDATE scans SET status = 'failed', error = 'Worker restarted while this scan was active', "
                "completed_at = ? WHERE status IN ('validating', 'running', 'paused', 'waiting_approval')",
                (utc_now(),),
            )

    def save_result(self, scan_id: str, organization_id: str, result: dict[str, Any]) -> None:
        pages = result.get("pages", [])
        activity = result.get("activity", [])
        findings = result.get("findings", [])
        with self.connection() as db:
            db.execute(
                "UPDATE scans SET result_json = ?, pages_count = ?, requests_count = ? WHERE id = ? AND organization_id = ?",
                (_json(result), len(pages), sum(1 for event in activity if event.get("event") == "request_allowed"), scan_id, organization_id),
            )
            for finding in findings:
                db.execute(
                    "INSERT OR REPLACE INTO findings(id, organization_id, scan_id, title, category, severity, confidence, status, "
                    "affected_endpoints_json, evidence_json, cwe, owasp_reference, business_impact, recommendation, retest_guidance, scanner, detected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"{scan_id}:{finding['id']}", organization_id, scan_id, finding["title"], finding["category"], finding["severity"],
                        finding["confidence"], finding.get("status", "potential"), _json(finding.get("affected_endpoints", [])),
                        _json(finding.get("evidence", [])), finding.get("cwe"), finding.get("owasp_reference"),
                        finding["business_impact"], finding["recommendation"], finding["retest_guidance"],
                        finding.get("scanner", "sentinel-passive"), finding.get("detected_at") or utc_now(),
                    ),
                )

    def append_event(self, organization_id: str, scan_id: str, event: dict[str, Any]) -> int:
        with self.connection() as db:
            cursor = db.execute(
                "INSERT INTO scan_events(organization_id, scan_id, event, timestamp, url, details_json) VALUES (?, ?, ?, ?, ?, ?)",
                (organization_id, scan_id, event.get("event", "activity"), event.get("timestamp", utc_now()), event.get("url"), _json(event.get("details", {}))),
            )
            return int(cursor.lastrowid)

    def events_after(self, scan_id: str, organization_id: str, after_id: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT id, event, timestamp, url, details_json FROM scan_events "
                "WHERE scan_id = ? AND organization_id = ? AND id > ? ORDER BY id LIMIT ?",
                (scan_id, organization_id, after_id, min(limit, 1000)),
            ).fetchall()
        return [
            {"id": row["id"], "event": row["event"], "timestamp": row["timestamp"], "url": row["url"], "details": json.loads(row["details_json"])}
            for row in rows
        ]

    def list_findings(self, organization_id: str, scan_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        where = ["organization_id = ?"]
        params: list[Any] = [organization_id]
        if scan_id:
            where.append("scan_id = ?")
            params.append(scan_id)
        if status:
            where.append("status = ?")
            params.append(status)
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM findings WHERE " + " AND ".join(where) + " ORDER BY detected_at DESC",
                params,
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["affected_endpoints"] = json.loads(item.pop("affected_endpoints_json"))
            item["evidence"] = json.loads(item.pop("evidence_json"))
            results.append(item)
        return results

    def update_finding_status(self, finding_id: str, organization_id: str, status: str) -> bool:
        with self.connection() as db:
            cursor = db.execute(
                "UPDATE findings SET status = ? WHERE id = ? AND organization_id = ?",
                (status, finding_id, organization_id),
            )
            return cursor.rowcount == 1

    def metrics(self, organization_id: str) -> dict[str, Any]:
        with self.connection() as db:
            scan_counts = {row["status"]: row["count"] for row in db.execute(
                "SELECT status, COUNT(*) AS count FROM scans WHERE organization_id = ? GROUP BY status",
                (organization_id,),
            )}
            finding_counts = {row["severity"]: row["count"] for row in db.execute(
                "SELECT severity, COUNT(*) AS count FROM findings WHERE organization_id = ? "
                "AND status NOT IN ('false_positive', 'resolved') GROUP BY severity",
                (organization_id,),
            )}
            total = db.execute("SELECT COUNT(*) FROM scans WHERE organization_id = ?", (organization_id,)).fetchone()[0]
            completed = scan_counts.get("completed", 0)
            recent = db.execute(
                "SELECT s.id, s.status, s.created_at, s.completed_at, s.pages_count, s.requests_count, "
                "t.name AS target_name, t.base_url, COUNT(f.id) AS findings_count "
                "FROM scans s JOIN targets t ON t.id = s.target_id LEFT JOIN findings f ON f.scan_id = s.id "
                "WHERE s.organization_id = ? GROUP BY s.id ORDER BY s.created_at DESC LIMIT 8",
                (organization_id,),
            ).fetchall()
        reports = [dict(item) for item in recent if item["status"] == "completed"]
        return {
            "total_scans": total,
            "completed_scans": completed,
            "running_scans": scan_counts.get("running", 0) + scan_counts.get("validating", 0),
            "queued_scans": scan_counts.get("queued", 0),
            "critical_findings": finding_counts.get("critical", 0),
            "high_findings": finding_counts.get("high", 0),
            "medium_findings": finding_counts.get("medium", 0),
            "low_findings": finding_counts.get("low", 0),
            "informational_findings": finding_counts.get("informational", 0),
            "recent_assessments": [dict(row) for row in recent],
            "recent_reports": reports,
        }

    def add_audit(self, organization_id: str, user_id: str | None, action: str, details: dict[str, Any] | None = None) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT INTO audit_logs(organization_id, user_id, action, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (organization_id, user_id, action, _json(details or {}), utc_now()),
            )

    def list_audit(self, organization_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT a.id, a.action, a.details_json, a.created_at, u.email "
                "FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id "
                "WHERE a.organization_id = ? ORDER BY a.id DESC LIMIT ?",
                (organization_id, min(max(limit, 1), 500)),
            ).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def heartbeat(self, worker_id: str, status: str, mode: str, capabilities: list[str]) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT INTO workers(id, status, mode, last_heartbeat, capabilities_json) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, mode=excluded.mode, "
                "last_heartbeat=excluded.last_heartbeat, capabilities_json=excluded.capabilities_json",
                (worker_id, status, mode, utc_now(), _json(capabilities)),
            )

    def worker(self, worker_id: str = "local") -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM workers WHERE id = ?", (worker_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["capabilities"] = json.loads(result.pop("capabilities_json"))
        return result

    def create_approval(self, organization_id: str, scan_id: str, proposal: dict[str, Any]) -> str:
        approval_id = new_id()
        with self.connection() as db:
            db.execute(
                "INSERT INTO approvals(id, organization_id, scan_id, proposal_json, status, created_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (approval_id, organization_id, scan_id, _json(proposal), utc_now()),
            )
        return approval_id

    def get_approval(self, approval_id: str, organization_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM approvals WHERE id = ? AND organization_id = ?",
                (approval_id, organization_id),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["proposal"] = json.loads(result.pop("proposal_json"))
        return result

    def resolve_approval(self, approval_id: str, organization_id: str, user_id: str, approved: bool) -> bool:
        with self.connection() as db:
            cursor = db.execute(
                "UPDATE approvals SET status = ?, resolved_at = ?, resolved_by = ? "
                "WHERE id = ? AND organization_id = ? AND status = 'pending'",
                ("approved" if approved else "rejected", utc_now(), user_id, approval_id, organization_id),
            )
            return cursor.rowcount == 1

    def pending_approvals(self, scan_id: str, organization_id: str) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM approvals WHERE scan_id = ? AND organization_id = ? AND status = 'pending' ORDER BY created_at",
                (scan_id, organization_id),
            ).fetchall()
        return [{**dict(row), "proposal": json.loads(row["proposal_json"])} for row in rows]
