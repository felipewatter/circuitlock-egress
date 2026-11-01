"""Immutable, deterministic, opt-in egress policy with strict parsing."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network, IPv4Network, IPv6Network
import json
import re
from pathlib import Path

from .errors import PolicyError

_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def hostname(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyError("Invalid hostname")
    value = value.lower().removesuffix(".")
    if not _HOST.fullmatch(value) or "." not in value:
        raise PolicyError("Hostname must be an absolute ASCII DNS name")
    return value


def _no_duplicates(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise PolicyError("Duplicate JSON policy key")
        result[key] = val
    return result


@dataclass(frozen=True, slots=True)
class Policy:
    """Deny private destinations by default; opt-in overrides are explicit.

    allowed_cidrs allows designated nonpublic addresses (e.g., for local
    integration tests). Use firewall rules as a second, independent boundary.
    """
    allowed_hosts: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    max_redirects: int = 0
    max_response_bytes: int = 2 * 1024 * 1024
    timeout_seconds: int = 10
    max_dns_answers: int = 32

    def __post_init__(self):
        for key, n, low, high in (
            ("max_redirects", self.max_redirects, 0, 5),
            ("max_response_bytes", self.max_response_bytes, 1, 16 * 1024 * 1024),
            ("timeout_seconds", self.timeout_seconds, 1, 30),
            ("max_dns_answers", self.max_dns_answers, 1, 32),
        ):
            if type(n) is not int or n < low or n > high:
                raise PolicyError(f"Invalid {key}")
        if not self.allowed_schemes or any(x not in ("http", "https") for x in self.allowed_schemes):
            raise PolicyError("Only HTTP(S) schemes are supported")
        if any(type(p) is not int or p < 1 or p > 65535 for p in self.allowed_ports):
            raise PolicyError("Invalid allowed port")
        if not self.allowed_ports:
            raise PolicyError("At least one allowed port is required")
        if len(self.allowed_hosts) > 64 or len(self.allowed_cidrs) > 32:
            raise PolicyError("Too many policy entries")
        for host in self.allowed_hosts:
            if hostname(host) != host:
                raise PolicyError("Canonical lowercase hostnames required")
        for address in self.allowed_cidrs:
            try:
                network = ip_network(address, strict=True)
            except ValueError as e:
                raise PolicyError("Invalid CIDR in policy") from e
            if str(network) != address:
                raise PolicyError("Canonical CIDR required")
        if len(set(self.allowed_hosts)) != len(self.allowed_hosts):
            raise PolicyError("Duplicate allowed hostname")
        if len(set(self.allowed_cidrs)) != len(self.allowed_cidrs):
            raise PolicyError("Duplicate CIDR")
        if len(set(self.allowed_ports)) != len(self.allowed_ports):
            raise PolicyError("Duplicate port")

    @property
    def networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        return tuple(ip_network(x) for x in self.allowed_cidrs)

    @classmethod
    def from_json(cls, text: str) -> Policy:
        if not isinstance(text, str) or len(text.encode("utf-8")) > 32 * 1024:
            raise PolicyError("Policy exceeds size limit")
        try:
            data = json.loads(text, object_pairs_hook=_no_duplicates)
        except (ValueError, TypeError) as e:
            raise PolicyError("Policy must be valid JSON") from e
        if not isinstance(data, dict):
            raise PolicyError("Policy must be a JSON object")
        names = set(cls.__dataclass_fields__)
        if set(data) - names:
            raise PolicyError("Unknown policy field")
        arrays = {"allowed_hosts", "allowed_cidrs", "allowed_schemes", "allowed_ports"}
        for key in arrays & data.keys():
            if not isinstance(data[key], list):
                raise PolicyError("Policy lists must be arrays")
            data[key] = tuple(data[key])
        try:
            return cls(**data)
        except (TypeError, ValueError) as e:
            raise PolicyError("Invalid policy structure") from e

    @classmethod
    def from_file(cls, filename: str | Path) -> Policy:
        import os
        import stat
        target = Path(filename)
        try:
            before = target.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > 32 * 1024:
                raise PolicyError("Policy must be a regular file under 32 KiB")
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as source:
                opened = os.fstat(source.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise PolicyError("Policy file changed")
                body = source.read(32 * 1024 + 1)
            if len(body) > 32 * 1024:
                raise PolicyError("Policy exceeds size limit")
            return cls.from_json(body.decode("utf-8", errors="strict"))
        except (OSError, UnicodeError) as e:
            raise PolicyError("Cannot read policy safely") from e
