"""Strict target normalization and bounded, redirect-aware reachability probing."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from .models import AuthorizationRecord
from .scope import ScopeGuardian, ScopeViolation, resolve_host


class TargetInputError(ValueError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    reachable: bool
    state: str
    status_code: int | None
    redirect_chain: list[str]
    final_url: str | None
    content_type: str | None = None
    error: str | None = None


def normalize_http_url(raw_url: str) -> tuple[str, SplitResult]:
    if not isinstance(raw_url, str) or not raw_url.strip() or len(raw_url) > 2048:
        raise TargetInputError("Enter a URL no longer than 2,048 characters.")
    raw_url = raw_url.strip()
    # A bare hostname or hostname/path is normalized to HTTPS for a common browser form.
    if "://" not in raw_url and not raw_url.startswith("//"):
        raw_url = "https://" + raw_url
    try:
        parsed = urlsplit(raw_url)
        _ = parsed.port
    except ValueError as exc:
        raise TargetInputError("The URL or port is malformed.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetInputError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise TargetInputError("Enter a complete URL with a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetInputError("URLs containing embedded usernames or passwords are not accepted.")
    if parsed.query or parsed.fragment:
        raise TargetInputError("Use a base page URL without a query string or fragment so secrets are not stored.")
    if "\\" in parsed.netloc or "%" in parsed.hostname:
        raise TargetInputError("Ambiguous hostname syntax is not accepted.")
    try:
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetInputError("The hostname is not valid internationalized text.") from exc
    try:
        address = ipaddress.ip_address(host)
        host_for_url = f"[{host}]" if address.version == 6 else host
    except ValueError:
        host_for_url = host
    scheme = parsed.scheme.lower()
    port = parsed.port
    default_port = 80 if scheme == "http" else 443
    netloc = host_for_url + (f":{port}" if port is not None and port != default_port else "")
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, netloc, path, "", ""))
    return normalized, urlsplit(normalized)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def head_probe(url: str, authorization: AuthorizationRecord, *, timeout: float = 5, max_redirects: int = 5) -> ProbeResult:
    """Probe only an already authorized target; pin each connection to a checked DNS answer."""
    guardian = ScopeGuardian(authorization)
    current, _ = normalize_http_url(url)
    redirect_chain: list[str] = []
    for redirect_count in range(max_redirects + 1):
        connection: http.client.HTTPConnection | None = None
        try:
            parsed = guardian.validate_url(current)
            host = parsed.hostname or ""
            addresses = resolve_host(host)
            # validate_url checks every DNS answer; connect to one of those checked addresses directly.
            guardian._validate_ip(addresses[0], host)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            if parsed.scheme.lower() == "https":
                connection = _PinnedHTTPSConnection(host, port, addresses[0], timeout)
            else:
                connection = _PinnedHTTPConnection(host, port, addresses[0], timeout)
            path = parsed.path or "/"
            connection.request("HEAD", path, headers={"User-Agent": "SentinelAI-Target-Validator/1.0", "Connection": "close"})
            response = connection.getresponse()
            status = response.status
            content_type = response.getheader("Content-Type")
            location = response.getheader("Location")
            response.read(0)
            connection.close()
            connection = None
            if status in {301, 302, 303, 307, 308} and location:
                if redirect_count >= max_redirects:
                    return ProbeResult(True, "redirect_limit", status, redirect_chain, current, content_type, "Redirect limit reached.")
                redirected = urljoin(current, location)
                try:
                    redirected, _ = normalize_http_url(redirected)
                    guardian.validate_url(redirected)
                except (TargetInputError, ScopeViolation):
                    return ProbeResult(True, "redirect_out_of_scope", status, redirect_chain + ["[blocked outside authorization]"], None, content_type, "Redirect leaves the authorized URL scope.")
                redirect_chain.append(redirected)
                current = redirected
                continue
            return ProbeResult(True, "reachable", status, redirect_chain, current, content_type)
        except (OSError, http.client.HTTPException, ssl.SSLError, ScopeViolation, TargetInputError) as exc:
            return ProbeResult(False, "unreachable", None, redirect_chain, None, None, type(exc).__name__)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
    return ProbeResult(False, "unreachable", None, redirect_chain, None, error="Redirect limit reached.")
