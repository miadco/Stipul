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
    assert payload["kill_switch_active"] is False
    assert payload["last_event_timestamp"] == "2026-01-01T00:00:00Z"
    assert payload["operator_reason"] is None
    assert payload["operator_updated_at"] is None
    assert payload["operator_updated_by"] is None
    assert payload["uptime_seconds"] == 100


def test_health_payload_includes_operator_status(contract):
    endpoint = HealthEndpoint(contract_id=contract.contract_id)
    endpoint.update_operator_status(
        kill_switch_active=True,
        updated_at="2026-03-07T17:00:00Z",
        updated_by="operator@example.com",
        reason="operator_kill_switch_enabled",
    )

    payload = endpoint.payload()

    assert payload["kill_switch_active"] is True
    assert payload["operator_reason"] == "operator_kill_switch_enabled"
    assert payload["operator_updated_at"] == "2026-03-07T17:00:00Z"
    assert payload["operator_updated_by"] == "operator@example.com"
