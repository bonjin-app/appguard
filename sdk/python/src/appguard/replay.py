"""Volatile single-process replay storage; never evict live claims."""

from threading import Lock
from typing import Protocol


class ReplayStoreUnavailable(Exception):
    """Backend failure or capacity exhaustion, not a replay result."""


class ReplayStore(Protocol):
    def claim(self, scope: tuple[str, str, str], *, expires: int, now: int) -> bool:
        """Atomically claim a new scope until expiry, or fail closed."""
        ...


class InMemoryReplayStore:
    def __init__(self, capacity: int = 10000):
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        self._capacity = capacity
        self._claims: dict[tuple[str, str, str], int] = {}
        self._lock = Lock()

    def claim(self, scope: tuple[str, str, str], *, expires: int, now: int) -> bool:
        if (type(expires) is not int or type(now) is not int or not 0 <= now < expires <= 999999999999999
                or type(scope) is not tuple or len(scope) != 3
                or any(type(part) is not str or not 1 <= len(part) <= 128 for part in scope)):
            raise ReplayStoreUnavailable("invalid replay claim")
        with self._lock:
            expired = [key for key, deadline in self._claims.items() if deadline <= now]
            for key in expired:
                del self._claims[key]
            if scope in self._claims:
                return False
            if len(self._claims) >= self._capacity:
                raise ReplayStoreUnavailable("replay capacity exhausted")
            self._claims[scope] = expires
            return True
