"""Typed data models for authorizations, observations, and assessment output."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AuthorizationRecord(BaseModel):
    """Explicit permission record for one assessment scope."""

    model_config = ConfigDict(extra="forbid")

    authorized_by: str = Field(min_length=2, max_length=200)
    authorization_reference: str = Field(min_length=2, max_length=500)
    expires_at: datetime
    allowed_domains: list[str] = Field(min_length=1, max_length=100)
    include_subdomains: bool = False
    allowed_url_prefixes: list[str] = Field(default_factory=list, max_length=100)
    allow_private_networks: bool = False
    allow_loopback: bool = False

    @field_validator("authorized_by", "authorization_reference")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            host = value.strip().rstrip(".").lower()
            if not host or "*" in host or "/" in host or "@" in host:
                raise ValueError("allowed_domains must contain exact hostnames or IP addresses")
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("invalid internationalized hostname") from exc
            normalized.append(host)
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_domains contains duplicates")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value

    @field_validator("allowed_url_prefixes")
    @classmethod
    def validate_prefixes(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                parsed = urlsplit(value)
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("URL prefixes must be valid absolute HTTP(S) URLs") from exc
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("URL prefixes must be absolute HTTP(S) URLs")
        return values

    @model_validator(mode="after")
    def validate_not_expired(self) -> "AuthorizationRecord":
        if self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("authorization record has expired")
        for prefix in self.allowed_url_prefixes:
            host = urlsplit(prefix).hostname or ""
            host = host.rstrip(".").lower().encode("idna").decode("ascii")
            allowed = host in self.allowed_domains or (
                self.include_subdomains
                and any(host.endswith("." + domain) for domain in self.allowed_domains)
            )
            if not allowed:
                raise ValueError("URL prefixes must use a host from allowed_domains")
        return self


class ScanLimits(BaseModel):
    """Small, explicit resource bounds for the local browser run."""

    model_config = ConfigDict(extra="forbid")

    max_pages: int = Field(default=10, ge=1, le=100)
    max_depth: int = Field(default=2, ge=0, le=10)
    max_requests: int = Field(default=500, ge=1, le=5000)
    max_duration_seconds: int = Field(default=300, ge=5, le=3600)
    request_delay_seconds: float = Field(default=0.1, ge=0, le=10)
    navigation_delay_seconds: float = Field(default=0.5, ge=0, le=10)
    navigation_timeout_ms: int = Field(default=20_000, ge=1000, le=120_000)


class ActivityEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event: str
    url: str | None = None
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class CookieObservation(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    appears_session_related: bool = False


class PageObservation(BaseModel):
    url: str
    title: str = ""
    status_code: int | None = None
    security_headers: dict[str, str | None] = Field(default_factory=dict)
    cookies: list[CookieObservation] = Field(default_factory=list)
    forms: list[dict[str, str | int | bool | None]] = Field(default_factory=list)
    links: list[dict[str, str]] = Field(default_factory=list)
    controls: list[dict[str, str]] = Field(default_factory=list)
    screenshot: str | None = None


class Finding(BaseModel):
    id: str
    scan_id: str | None = None
    title: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    status: Literal["potential", "verified", "inconclusive", "false_positive", "resolved"] = "potential"
    confidence: Literal["low", "medium", "high"]
    category: str
    affected_endpoints: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    cwe: str | None = None
    owasp_reference: str | None = None
    business_impact: str
    recommendation: str
    retest_guidance: str
    scanner: str = "sentinel-passive"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssessmentResult(BaseModel):
    assessment_id: str
    started_at: datetime
    completed_at: datetime | None = None
    target_url: str
    authorization_reference: str
    authorized_by: str
    authorized_domains: list[str] = Field(default_factory=list)
    allowed_url_prefixes: list[str] = Field(default_factory=list)
    browser_metadata: dict[str, str | int | bool | None] = Field(default_factory=dict)
    selected_checks: list[str] = Field(default_factory=list)
    worker_id: str = "local"
    pages: list[PageObservation] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    activity: list[ActivityEvent] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
