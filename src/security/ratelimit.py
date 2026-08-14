"""Token-bucket rate limiting for tool invocations.

Two independent budgets protect the system:

* a **per-minute token bucket** keyed on ``(principal, tool)`` -- bounds burst
  rate against a looping or injected agent;
* a **per-run hard ceiling** on total tool calls, enforced by the broker and by
  policy rule ``DENY-002``.

Rate limiting is a safety control here rather than a cost control: the failure
mode we care about is an agent stuck in a tool loop, or one steered by injected
content into hammering a resource.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class RateLimitExceeded(RuntimeError):
    """Raised when a principal exceeds its allowance for a tool."""

    def __init__(self, principal: str, tool: str, retry_after: float) -> None:
        self.principal = principal
        self.tool = tool
        self.retry_after = retry_after
        super().__init__(
            f"rate limit exceeded for principal '{principal}' on tool '{tool}'; "
            f"retry in {retry_after:.1f}s"
        )


@dataclass
class _Bucket:
    capacity: float
    tokens: float
    refill_per_second: float
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self, amount: float = 1.0) -> tuple[bool, float]:
        """Attempt to take ``amount`` tokens.

        Returns ``(allowed, retry_after_seconds)``.
        """
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.last_refill = now

        if self.tokens >= amount:
            self.tokens -= amount
            return True, 0.0

        deficit = amount - self.tokens
        return False, deficit / self.refill_per_second if self.refill_per_second else float("inf")


class RateLimiter:
    """Thread-safe token-bucket limiter keyed on ``(principal, tool)``."""

    def __init__(self, calls_per_minute: int = 30, burst: int | None = None) -> None:
        if calls_per_minute <= 0:
            raise ValueError("calls_per_minute must be positive")
        self.calls_per_minute = calls_per_minute
        self.burst = float(burst if burst is not None else calls_per_minute)
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, principal: str, tool: str) -> None:
        """Consume one token or raise :class:`RateLimitExceeded`."""
        key = (principal, tool)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(
                    capacity=self.burst,
                    tokens=self.burst,
                    refill_per_second=self.calls_per_minute / 60.0,
                )
                self._buckets[key] = bucket
            allowed, retry_after = bucket.consume()

        if not allowed:
            raise RateLimitExceeded(principal, tool, retry_after)

    def reset(self) -> None:
        """Drop all buckets (test hook)."""
        with self._lock:
            self._buckets.clear()
