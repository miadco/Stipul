"""Circuit breaker for MCP Proxy runtime failures."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from time import time as _default_clock
from typing import Any, Callable


@dataclass
class CircuitBreaker:
    """Track repeated failures and enforce degraded-mode policy decisions."""

    clock: Callable[[], float] = _default_clock
    allow_read_fail_open: bool = False
    on_state_change: Callable[[str], None] | None = None
    _state: str = field(default="closed", init=False)
    _opened_at: float | None = field(default=None, init=False)
    _failure_times: deque[float] = field(default_factory=deque, init=False)

    @property
    def state(self) -> str:
        return self._state

    def _emit(self, reason: str) -> None:
        if self.on_state_change is not None:
            self.on_state_change(reason)

    def _open(self, now: float) -> None:
        if self._state != "open":
            self._state = "open"
            self._opened_at = now
            self._emit("circuit_breaker_open")

    def _close(self) -> None:
        if self._state != "closed":
            self._state = "closed"
            self._opened_at = None
            self._failure_times.clear()
            self._emit("circuit_breaker_closed")

    def _prune_failures(self, now: float) -> None:
        while self._failure_times and now - self._failure_times[0] > 10.0:
            self._failure_times.popleft()

    def _record_failure(self, now: float) -> None:
        self._prune_failures(now)
        self._failure_times.append(now)
        if len(self._failure_times) >= 3:
            self._open(now)

    def _degraded_result(self, risk_class: str) -> dict[str, str]:
        normalized = risk_class.replace("_", "-")
        if normalized == "read" and self.allow_read_fail_open:
            return {"decision": "allow", "reason": "proxy_degraded"}
        return {"decision": "deny", "reason": "proxy_degraded"}

    def call(self, fn: Callable[[], Any], risk_class: str) -> Any:
        """Call ``fn`` with circuit-breaker protection."""
        now = self.clock()

        if self._state == "open":
            if self._opened_at is not None and now - self._opened_at >= 30.0:
                try:
                    result = fn()
                except Exception:
                    self._opened_at = now
                    return self._degraded_result(risk_class)
                self._close()
                return result
            return self._degraded_result(risk_class)

        try:
            result = fn()
        except Exception:
            self._record_failure(now)
            return self._degraded_result(risk_class)

        self._failure_times.clear()
        return result
