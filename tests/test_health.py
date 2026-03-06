from __future__ import annotations

from stipul.health.endpoint import HealthEndpoint


class FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_health_payload_shape(contract):
    clock = FakeClock(now=200.0)
    endpoint = HealthEndpoint(contract_id=contract.contract_id, clock=clock, start_time=100.0)
    endpoint.update_last_event_timestamp("2026-01-01T00:00:00Z")

    payload = endpoint.payload()

    assert payload["status"] == "healthy"
    assert payload["contract_id"] == contract.contract_id
    assert payload["chain_length"] == 1
    assert payload["last_event_timestamp"] == "2026-01-01T00:00:00Z"
    assert payload["uptime_seconds"] == 100
