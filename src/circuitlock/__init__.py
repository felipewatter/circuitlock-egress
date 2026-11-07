"""CircuitLock: bounded, DNS-pinned outbound HTTP(S) egress (stdlib only)."""
from .address import Destination, resolve_destination
from .errors import CircuitLockError, PolicyError, ResolutionError, TransportError
from .policy import Policy
from .transport import FetchResult, safe_fetch

__all__ = ["CircuitLockError", "PolicyError", "ResolutionError", "TransportError",
           "Policy", "Destination", "resolve_destination", "FetchResult", "safe_fetch"]
__version__ = "0.1.1"
