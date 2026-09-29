"""Rate limiting and a hard request budget.

Two protections against accidentally overwhelming a client's production system:
  - a token-bucket limiter that caps sustained requests-per-second, and
  - a global counter that stops the run once max_total_requests is reached.

Both come from the engagement file. The budget is a fail-closed circuit breaker: when
it trips, network tools stop working and the agent is told to wrap up.
"""

from __future__ import annotations

import threading
import time


class RequestBudgetExceeded(Exception):
    """Raised when the engagement's total request budget is exhausted."""


class RateLimiter:
    def __init__(self, rate_per_second: float, max_total: int):
        self._rate = max(rate_per_second, 0.01)
        self._capacity = max(rate_per_second, 1.0)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._max_total = max_total
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(self._max_total - self._used, 0)

    def acquire(self) -> None:
        """Block until a request slot is available, or raise if the budget is spent."""
        with self._lock:
            if self._used >= self._max_total:
                raise RequestBudgetExceeded(
                    f"request budget exhausted ({self._max_total}); stop and report"
                )
            while True:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    self._used += 1
                    return
                sleep_for = (1 - self._tokens) / self._rate
                time.sleep(sleep_for)
