"""Session lifecycle state for proxy close-out flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class SessionState:
    """Mutable accumulator for proxy session runtime data."""

    session_id: str
    contract_id: str
    session_start: datetime
    events_path: Path
    decisions_path: Path
    summary_path: Path
    budget_consumed: dict[str, float] = field(default_factory=dict)
    tool_calls_used: int = 0
    net_calls_used: int = 0
    closed: bool = False

    def __post_init__(self) -> None:
        if self.session_start.tzinfo is None:
            raise ValueError("session_start must be UTC-aware")
