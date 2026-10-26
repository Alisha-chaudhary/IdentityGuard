import threading
import time
from collections import defaultdict
from typing import Dict, List


class RateLimitExceeded(Exception):
    """Raised when a client exceeds the configured request rate."""


class FixedWindowRateLimiter:
    """Small in-memory rate limiter for a single-process deployment.

    Keeps a sliding log of request timestamps per key and rejects requests
    once the window count is exhausted. It is intentionally *not*
    distributed-safe: behind more than one app instance, back this with a
    shared store such as Redis (for example fastapi-limiter) instead of
    relying on per-process memory.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._stamps: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Return True if the request is allowed, False if rate limited."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            stamps = self._stamps[key]
            stamps[:] = [stamp for stamp in stamps if stamp > cutoff]
            if len(stamps) >= self.max_requests:
                return False
            stamps.append(now)
            return True

    def remaining(self, key: str) -> int:
        """Requests left in the current window for the key."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            stamps = [stamp for stamp in self._stamps.get(key, []) if stamp > cutoff]
            self._stamps[key] = stamps
            return max(0, self.max_requests - len(stamps))

    def reset(self) -> None:
        """Clear all counters. Mostly useful in tests."""
        with self._lock:
            self._stamps.clear()
