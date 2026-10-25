"""Password hashing and signed, organization-scoped dashboard sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


_PASSWORD_ROUNDS = 420_000
_SESSION_SECONDS = 8 * 60 * 60


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password must contain 12 to 256 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PASSWORD_ROUNDS, dklen=32)
    return f"pbkdf2_sha256${_PASSWORD_ROUNDS}${_b64(salt)}${_b64(derived)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_text, expected_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = _unb64(salt_text)
        expected = _unb64(expected_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class Session:
    user_id: str
    organization_id: str
    email: str
    role: str
    expires_at: int
    csrf: str


class SessionCodec:
    def __init__(self, secret: str | bytes, session_seconds: int = _SESSION_SECONDS):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if len(secret) < 32:
            raise ValueError("session secret must be at least 32 bytes")
        self.secret = secret
        self.session_seconds = session_seconds

    def issue(self, user: dict[str, str]) -> tuple[str, str]:
        csrf = secrets.token_urlsafe(24)
        payload = {
            "sub": user["id"],
            "org": user["organization_id"],
            "email": user["email"],
            "role": user["role"],
            "exp": int(time.time()) + self.session_seconds,
            "csrf": csrf,
        }
        body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signature = _b64(hmac.new(self.secret, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{signature}", csrf

    def decode(self, token: str | None) -> Session | None:
        if not token or len(token) > 4096:
            return None
        try:
            body, signature = token.split(".", 1)
            expected = hmac.new(self.secret, body.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(signature)):
                return None
            payload = json.loads(_unb64(body))
            if int(payload["exp"]) <= int(time.time()):
                return None
            return Session(
                user_id=str(payload["sub"]),
                organization_id=str(payload["org"]),
                email=str(payload["email"]),
                role=str(payload["role"]),
                expires_at=int(payload["exp"]),
                csrf=str(payload["csrf"]),
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
