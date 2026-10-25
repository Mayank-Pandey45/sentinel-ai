"""Fail-closed target scope checks used before every browser request."""

from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from collections.abc import Callable, Sequence
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

from .models import AuthorizationRecord


class ScopeViolation(ValueError):
    """A URL or resolved network destination is outside the authorization."""


Resolver = Callable[[str], Sequence[str]]


def resolve_host(host: str) -> list[str]:
    try:
        return list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))
    except OSError as exc:
        raise ScopeViolation(f"DNS resolution failed for {host!r}") from exc


class ScopeGuardian:
    """Validates host, scheme, path, DNS answers, and public-address policy."""

    def __init__(self, authorization: AuthorizationRecord, resolver: Resolver = resolve_host):
        self.authorization = authorization
        self.resolver = resolver

    def validate_url(self, url: str) -> SplitResult:
        """Return parsed URL if every scope and destination check succeeds."""
        if not isinstance(url, str) or len(url) > 8192:
            raise ScopeViolation("URL is missing or too long")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            _ = parsed.port  # Reject malformed ports early.
        except ValueError as exc:
            raise ScopeViolation("URL is malformed") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            raise ScopeViolation("only absolute HTTP(S) URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeViolation("URLs containing credentials are not allowed")
        if "\\" in parsed.netloc or "%" in host:
            raise ScopeViolation("ambiguous hostname syntax is not allowed")

        host = self._normalize_host(host)
        if not self._host_is_allowed(host):
            raise ScopeViolation(f"host {host!r} is not in the explicit authorization allowlist")
        if self.authorization.allowed_url_prefixes and not any(
            self._matches_url_prefix(parsed, prefix)
            for prefix in self.authorization.allowed_url_prefixes
        ):
            raise ScopeViolation("URL path is outside the explicit authorization prefixes")

        addresses = self._resolve(host)
        if not addresses:
            raise ScopeViolation(f"no IP addresses resolved for {host!r}")
        for address in addresses:
            self._validate_ip(address, host)
        return parsed

    def _resolve(self, host: str) -> list[str]:
        try:
            return [str(item) for item in self.resolver(host)]
        except ScopeViolation:
            raise
        except Exception as exc:
            raise ScopeViolation(f"DNS resolution failed for {host!r}") from exc

    @staticmethod
    def _normalize_host(host: str) -> str:
        host = host.rstrip(".").lower()
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeViolation("invalid hostname encoding") from exc

    def _host_is_allowed(self, host: str) -> bool:
        if host in self.authorization.allowed_domains:
            return True
        return self.authorization.include_subdomains and any(
            host.endswith("." + domain) for domain in self.authorization.allowed_domains
        )

    @staticmethod
    def _matches_url_prefix(parsed: SplitResult, prefix: str) -> bool:
        allowed = urlsplit(prefix)
        same_origin = (
            parsed.scheme.lower() == allowed.scheme.lower()
            and (parsed.hostname or "").lower().rstrip(".") == (allowed.hostname or "").lower().rstrip(".")
            and ScopeGuardian._effective_port(parsed) == ScopeGuardian._effective_port(allowed)
        )
        if not same_origin:
            return False
        base = ScopeGuardian._normalized_path(allowed.path)
        current = ScopeGuardian._normalized_path(parsed.path)
        if base is None or current is None:
            return False
        base = base.rstrip("/") or "/"
        return current == base or base == "/" or current.startswith(base + "/")

    @staticmethod
    def _effective_port(parsed: SplitResult) -> int | None:
        try:
            return parsed.port or {"http": 80, "https": 443}.get(parsed.scheme.lower())
        except ValueError:
            return None

    @staticmethod
    def _normalized_path(path: str) -> str | None:
        current = path or "/"
        for _ in range(8):
            decoded = unquote(current)
            if decoded == current:
                break
            current = decoded
        else:
            return None
        if "\\" in current or not current.startswith("/"):
            return None
        return posixpath.normpath(current)

    def _validate_ip(self, raw_address: str, host: str) -> None:
        try:
            address = ipaddress.ip_address(raw_address.split("%", 1)[0])
        except ValueError as exc:
            raise ScopeViolation(f"DNS returned an invalid address for {host!r}") from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            self._validate_ip(str(address.ipv4_mapped), host)
            return
        if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise ScopeViolation(f"host {host!r} resolves to a prohibited network address")
        if address.is_loopback:
            if self.authorization.allow_loopback:
                return
            raise ScopeViolation(f"host {host!r} resolves to loopback, blocked by default")
        if address.is_private:
            if self.authorization.allow_private_networks:
                return
            raise ScopeViolation(f"host {host!r} resolves to a private address, blocked by default")
        if not address.is_global:
            raise ScopeViolation(f"host {host!r} resolves to a non-public address")


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$")
_LONG_HEX = re.compile(r"^(?=.*[a-fA-F])(?=.*\d)[a-fA-F0-9]{20,}$")
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def sanitize_url(url: str) -> str:
    """Remove credentials, query, and likely identifier/token path segments."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host + (f":{port}" if port is not None else "")
        parts = []
        for segment in (parsed.path or "/").split("/"):
            if _UUID.match(segment) or _LONG_HEX.match(segment) or _LONG_TOKEN.match(segment):
                parts.append("{redacted}")
            else:
                parts.append(segment)
        return urlunsplit((parsed.scheme, netloc, "/".join(parts), "", ""))
    except Exception:
        return "[unparseable URL]"
