"""Defensive URL validation, DNS result verification, and address pinning."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlsplit, SplitResult

from .errors import PolicyError, ResolutionError
from .policy import Policy, hostname

_HOST_CLASSES = ("localhost", "metadata", "metadata.google.internal")
_DISALLOWED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


@dataclass(frozen=True, slots=True)
class Destination:
    scheme: str
    hostname: str
    port: int
    target: str
    ip: str
    is_ip_literal: bool


def _normalize_url(raw: str, policy: Policy) -> tuple[str, str, int, str, bool]:
    if not isinstance(raw, str) or len(raw) < 1 or len(raw) > 8192:
        raise PolicyError("Invalid URL length")
    if any(ord(c) < 33 or ord(c) > 126 for c in raw) or "\\" in raw:
        raise PolicyError("URL contains ambiguous or unsafe characters")
    try:
        url: SplitResult = urlsplit(raw)
        if url.username is not None or url.password is not None or url.fragment:
            raise PolicyError("Credentials and fragments are forbidden")
        scheme = url.scheme.lower()
        if scheme not in policy.allowed_schemes or not url.netloc:
            raise PolicyError("Scheme not allowed or authority missing")
        name = url.hostname
        if not name or "%" in name or "@" in url.netloc:
            raise PolicyError("Invalid hostname")
        port = (url.port if url.port is not None else (443 if scheme == "https" else 80))
        if port not in policy.allowed_ports:
            raise PolicyError("Port not permitted by policy")
        # Forbid Unicode hostnames to avoid IDNA, homograph and parser disagreements.
        if not name.isascii():
            raise PolicyError("Only canonical ASCII hostnames are accepted")
        address = None
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            pass
        if address is not None:
            name = address.compressed
        else:
            name = hostname(name)
            if name in _HOST_CLASSES or any(name.endswith(s) for s in _DISALLOWED_SUFFIXES):
                raise PolicyError("Locally scoped hostname denied")
        if policy.allowed_hosts and name not in policy.allowed_hosts:
            raise PolicyError("Hostname not in egress allowlist")
        target = (url.path or "/") + (("?" + url.query) if url.query else "")
        if len(target) > 8192:
            raise PolicyError("Request target exceeds limit")
        return scheme, name, port, target, address is not None
    except (ValueError, TypeError) as e:
        raise PolicyError("Malformed URL") from e


def _parse_address(text: str, policy: Policy) -> str:
    try:
        address = ipaddress.ip_address(text)
    except (ValueError, TypeError) as e:
        raise ResolutionError("DNS returned a malformed address") from e
    # These families can tunnel IPv4 and need a separate tunnel-aware policy.
    if (isinstance(address, ipaddress.IPv6Address) and
        (address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None)):
        raise ResolutionError("Embedded IPv4 transition address denied")
    if address.is_global:
        return address.compressed
    if any(address in network for network in policy.networks):
        return address.compressed
    raise ResolutionError("Nonpublic address denied by policy")


def system_resolver(host: str, port: int) -> list[str]:
    """Return all A/AAAA addresses as numeric IPs; no URL supplied to resolver."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return [item[4][0] for item in answers]


def resolve_destination(raw: str, policy: Policy | None = None, resolver=system_resolver) -> Destination:
    policy = policy if policy is not None else Policy()
    scheme, name, port, target, literal = _normalize_url(raw, policy)
    try:
        answers = [name] if literal else resolver(name, port)
    except (OSError, ValueError) as e:
        raise ResolutionError("DNS resolution failed") from e
    if not isinstance(answers, (tuple, list)) or not 1 <= len(answers) <= policy.max_dns_answers:
        raise ResolutionError("Empty or oversized DNS answer set")
    # Require *every* answer to satisfy policy; mixed public/private is rejected.
    validated = [_parse_address(answer, policy) for answer in answers]
    unique = sorted(set(validated), key=lambda ip: (ipaddress.ip_address(ip).version, ip))
    return Destination(scheme, name, port, target, unique[0], literal)
