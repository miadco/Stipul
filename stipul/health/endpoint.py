"""Health reporting for the MCP Proxy process."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Callable


@dataclass
class HealthEndpoint:
    """Return current proxy health details in a stable Week 2 shape."""

    contract_id: str
    clock: Callable[[], float] = time.time
    start_time: float = field(default_factory=time.time)
    last_event_timestamp: str | None = None
    degraded: bool = False
    circuit_open: bool = False
    kill_switch_active: bool = False
    operator_updated_at: str | None = None
    operator_updated_by: str | None = None
    operator_reason: str | None = None

    def update_last_event_timestamp(self, timestamp: str) -> None:
        self.last_event_timestamp = timestamp

    def set_degraded(self, value: bool) -> None:
        self.degraded = value

    def set_circuit_open(self, value: bool) -> None:
        self.circuit_open = value

    def update_operator_status(
        self,
        *,
        kill_switch_active: bool,
        updated_at: str | None,
        updated_by: str | None = None,
        reason: str | None,
    ) -> None:
        self.kill_switch_active = kill_switch_active
        self.operator_updated_at = updated_at
        self.operator_updated_by = updated_by
        self.operator_reason = reason

    def payload(self) -> dict[str, object]:
        status = "healthy"
        if self.circuit_open:
            status = "circuit_open"
        elif self.degraded:
            status = "degraded"

        uptime = int(max(0, self.clock() - self.start_time))
        return {
            "status": status,
            "contract_id": self.contract_id,
            # chain_length is hardcoded to 1 until the Inheritance Resolver ships in Week 4.
            # Any change to this value must reflect actual verified chain depth from the loader.
            # Never increment without a real resolver behind it.
            "chain_length": 1,
            "kill_switch_active": self.kill_switch_active,
            "last_event_timestamp": self.last_event_timestamp,
            "operator_reason": self.operator_reason,
            "operator_updated_at": self.operator_updated_at,
            "operator_updated_by": self.operator_updated_by,
            "uptime_seconds": uptime,
        }
