"""Safe exception classes: never embed untrusted URLs or response bodies."""
class CircuitLockError(Exception):
    """Base exception for a rejected or incomplete outbound request."""


class PolicyError(CircuitLockError):
    """Invalid policy or rejected destination."""


class ResolutionError(CircuitLockError):
    """Destination DNS response rejected or failed."""


class TransportError(CircuitLockError):
    """Network I/O error, redirect error, or response limit breach."""
