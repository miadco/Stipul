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

    def update_last_event_timestamp(self, timestamp: str) -> None:
        self.last_event_timestamp = timestamp

    def set_degraded(self, value: bool) -> None:
        self.degraded = value

    def set_circuit_open(self, value: bool) -> None:
        self.circuit_open = value

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
            "last_event_timestamp": self.last_event_timestamp,
            "uptime_seconds": uptime,
        }
