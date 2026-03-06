from __future__ import annotations

from stipul.writ.proxy.circuit_breaker import CircuitBreaker


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_policy_error_on_write_fails_closed():
    clock = FakeClock()
    breaker = CircuitBreaker(clock=clock)

    result = breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "write")

    assert result == {"decision": "deny", "reason": "proxy_degraded"}


def test_policy_error_on_read_can_fail_open_when_enabled():
    clock = FakeClock()
    breaker = CircuitBreaker(clock=clock, allow_read_fail_open=True)

    result = breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "read")

    assert result == {"decision": "allow", "reason": "proxy_degraded"}


def test_three_failures_in_ten_seconds_opens_circuit_and_emits_event():
    clock = FakeClock()
    events: list[str] = []
    breaker = CircuitBreaker(clock=clock, on_state_change=events.append)

    for _ in range(3):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "write")
        clock.advance(3)

    assert breaker.state == "open"
    assert "circuit_breaker_open" in events


def test_recovery_after_thirty_seconds_closes_circuit_and_emits_event():
    clock = FakeClock()
    events: list[str] = []
    breaker = CircuitBreaker(clock=clock, on_state_change=events.append)

    for _ in range(3):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("boom")), "write")
        clock.advance(3)

    clock.advance(31)
    result = breaker.call(lambda: "ok", "write")

    assert result == "ok"
    assert breaker.state == "closed"
    assert "circuit_breaker_closed" in events
