from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app
from sentinel_ai.store import new_id, utc_now


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.app = create_app(Path(self.temp.name), bootstrap_token="test-bootstrap-token-123456", start_worker=False)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def bootstrap(self):
        response = self.client.post("/api/auth/setup", json={
            "bootstrap_token": "test-bootstrap-token-123456", "organization_name": "Test Workspace",
            "email": "owner@example.test", "password": "a-long-test-password-4821",
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.csrf = response.json()["csrf_token"]
        return response.json()

    def headers(self):
        return {"X-CSRF-Token": self.csrf}

    def make_target(self, *, url="http://127.0.0.1:8000/", allow_loopback=True):
        expires = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        response = self.client.post("/api/targets", headers=self.headers(), json={
            "name": "Local fixture", "base_url": url, "authorized_by": "Local test owner",
            "authorization_reference": "TEST-FIXTURE-01", "expires_at": expires,
            "documented_authorization": True, "allow_loopback": allow_loopback,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_dashboard_requires_authentication_and_setup_token_is_one_time(self):
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)
        wrong = self.client.post("/api/auth/setup", json={
            "bootstrap_token": "wrong-bootstrap-token-0000", "organization_name": "Test Workspace",
            "email": "owner@example.test", "password": "a-long-test-password-4821",
        })
        self.assertEqual(wrong.status_code, 403)
        self.bootstrap()
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_validation_requires_existing_authorization_and_rejects_bad_urls(self):
        self.bootstrap()
        no_auth = self.client.post("/api/targets/validate", json={"url": "https://example.com/"})
        self.assertEqual(no_auth.json()["state"], "authorization_required")
        for value in ("file:///etc/passwd", "https://user:pass@example.com/", "https://example.com/?token=x"):
            response = self.client.post("/api/targets/validate", json={"url": value})
            self.assertEqual(response.json()["state"], "invalid")

    def test_target_creation_requires_csrf_and_documented_authorization(self):
        self.bootstrap()
        expires = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        payload = {"name":"Fixture", "base_url":"http://127.0.0.1:8000/", "authorized_by":"Owner", "authorization_reference":"T-1", "expires_at":expires, "documented_authorization":True, "allow_loopback":True}
        self.assertEqual(self.client.post("/api/targets", json=payload).status_code, 403)
        payload["documented_authorization"] = False
        denied = self.client.post("/api/targets", headers=self.headers(), json=payload)
        self.assertEqual(denied.status_code, 400)
        payload["documented_authorization"] = True
        created = self.client.post("/api/targets", headers=self.headers(), json=payload)
        self.assertEqual(created.status_code, 200, created.text)
        self.assertNotIn("authorization", created.json())

    def test_worker_disconnected_and_unsupported_check_block_scan_creation(self):
        self.bootstrap()
        valid_shape = {"target_id":"unknown", "target_url":"https://example.com/", "selected_checks":["passive_headers"]}
        self.assertEqual(self.client.post("/api/scans", headers=self.headers(), json=valid_shape).status_code, 503)
        self.app.state.store.heartbeat("local", "connected", "local", ["passive-browser-assessment"])
        target = self.make_target()
        payload = {"target_id":target["id"], "target_url":target["base_url"], "selected_checks":["active_sqli"]}
        denied = self.client.post("/api/scans", headers=self.headers(), json=payload)
        self.assertEqual(denied.status_code, 422)

    def test_expired_authorization_is_not_valid(self):
        self.bootstrap()
        target = self.make_target()
        user = self.app.state.store.user_by_email("owner@example.test")
        stored = self.app.state.store.get_target(target["id"], user["organization_id"])
        auth = stored["authorization"]
        auth["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with self.app.state.store.connection() as db:
            db.execute("UPDATE targets SET authorization_json=? WHERE id=?", (json.dumps(auth), target["id"]))
        response = self.client.post("/api/targets/validate", json={"url":target["base_url"],"target_id":target["id"]})
        self.assertEqual(response.json()["state"], "unauthorized")

    def test_cross_organization_scan_lookup_is_denied(self):
        owner = self.bootstrap()["user"]
        target = self.make_target()
        store = self.app.state.store
        owner_record = store.user_by_email(owner["email"])
        org1 = owner_record["organization_id"]
        scan = store.create_scan({"organization_id":org1,"target_id":target["id"],"created_by":owner_record["id"],"config":{"target_url":target["base_url"]}})
        org2, user2 = new_id(), new_id()
        with store.connection() as db:
            db.execute("INSERT INTO organizations(id,name,created_at) VALUES(?,?,?)",(org2,"Other org",utc_now()))
            db.execute("INSERT INTO users(id,organization_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",(user2,org2,"other@example.test","not-used","owner",utc_now()))
        token,_ = self.app.state.codec.issue({"id":user2,"organization_id":org2,"email":"other@example.test","role":"owner"})
        other = TestClient(self.app)
        self.addCleanup(other.close)
        other.cookies.set("sentinel_session",token)
        self.assertEqual(other.get(f"/api/scans/{scan['id']}").status_code,404)
        self.assertEqual(other.get("/api/targets").json(),[])


if __name__ == "__main__":
    unittest.main()
