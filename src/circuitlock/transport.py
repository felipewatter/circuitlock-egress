"""Pinned HTTP(S) client: no proxy, no hostname re-resolution at connect time."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import socket
import ssl
from urllib.parse import urljoin

from .address import Destination, resolve_destination, system_resolver
from .errors import CircuitLockError, PolicyError, ResolutionError, TransportError
from .policy import Policy

_REDIRECTS = {301, 302, 303, 307, 308}


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, dest: Destination, timeout: int):
        super().__init__(dest.hostname, dest.port, timeout=timeout)
        self._pinned_ip = dest.ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout,
                                             self.source_address)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, dest: Destination, timeout: int):
        super().__init__(dest.hostname, dest.port, timeout=timeout,
                         context=ssl.create_default_context())
        self._pinned_ip = dest.ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout,
                                        self.source_address)
        try:
            # Keep the original name for SNI and cert hostname verification.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


@dataclass(frozen=True, slots=True)
class FetchResult:
    status: int
    content: bytes
    sha256: str
    final_host: str
    redirects: int
    content_type: str

    @property
    def size(self) -> int:
        return len(self.content)


def safe_fetch(url: str, policy: Policy | None = None, *, resolver=system_resolver,
               method: str = "GET") -> FetchResult:
    """Fetch using explicit per-hop DNS admission and an IP-pinned socket.

    Does not load proxies or follow redirects implicitly. No application-provided
    headers are accepted, avoiding authentication-header forwarding/smuggling.
    """
    policy = policy if policy is not None else Policy()
    if not isinstance(policy, Policy):
        raise PolicyError("Expected a validated Policy")
    if method not in ("GET", "HEAD"):
        raise PolicyError("Only GET and HEAD are permitted")
    visited: set[tuple[str, str, int, str]] = set()
    current = url
    first_scheme = None
    for redirects in range(policy.max_redirects + 1):
        dest = resolve_destination(current, policy, resolver)
        if first_scheme == "https" and dest.scheme != "https":
            raise PolicyError("TLS downgrade on redirect denied")
        if first_scheme is None:
            first_scheme = dest.scheme
        state = (dest.scheme, dest.hostname, dest.port, dest.target)
        if state in visited:
            raise TransportError("Redirect loop rejected")
        visited.add(state)
        connection = (_PinnedHTTPS(dest, policy.timeout_seconds) if dest.scheme == "https"
                      else _PinnedHTTP(dest, policy.timeout_seconds))
        try:
            header_host = dest.hostname
            if ":" in header_host:
                header_host = f"[{header_host}]"
            if dest.port != (443 if dest.scheme == "https" else 80):
                header_host += f":{dest.port}"
            # No user-controlled arbitrary headers, auth, or data/metadata methods.
            connection.request(method, dest.target,
                               headers={"Host": header_host, "Accept": "*/*",
                                        "Accept-Encoding": "identity", "Connection": "close",
                                        "User-Agent": "CircuitLock/0.1.0"})
            response = connection.getresponse()
            if response.status in _REDIRECTS:
                redirect = response.getheader("Location")
                if not redirect or redirects >= policy.max_redirects:
                    raise TransportError("Disallowed or excessive redirects")
                if len(redirect) > 8192:
                    raise TransportError("Redirect target exceeds limit")
                current = urljoin(current, redirect)
                # No body is downloaded for redirect responses; all URL checks rerun.
                continue
            size_header = response.getheader("Content-Length")
            if size_header is not None:
                try:
                    if int(size_header) > policy.max_response_bytes:
                        raise TransportError("Response size exceeds policy")
                except ValueError as e:
                    raise TransportError("Invalid response length") from e
            content = response.read(policy.max_response_bytes + 1)
            if len(content) > policy.max_response_bytes:
                raise TransportError("Response exceeds byte cap")
            # A malicious server may put credentials/control text in header values.
            # Return only a syntactically simple media type, never raw headers.
            import re
            candidate = response.getheader("Content-Type", "").split(";", 1)[0].strip()
            ctype = candidate.lower() if re.fullmatch(r"[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+", candidate) and len(candidate) <= 100 else ""
            return FetchResult(response.status, content, hashlib.sha256(content).hexdigest(),
                               dest.hostname, redirects, ctype)
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise TransportError("HTTP(S) transport failed; response not admitted") from e
        finally:
            connection.close()
    raise TransportError("Too many redirects")
