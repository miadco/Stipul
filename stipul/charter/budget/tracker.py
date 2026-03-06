"""Budget tracking and exhaustion checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from stipul.charter.contract.schema import Contract

_LOGGER = logging.getLogger(__name__)


@dataclass
class BudgetCheckResult:
    allowed: bool
    reason: str | None
    dimension: str | None
    first_exhaustion: bool


@dataclass
class BudgetTracker:
    max_tool_calls: int | None
    max_net_calls: int | None
    tool_calls_used: int = 0
    net_calls_used: int = 0
    tokens_used: int = 0
    dollars_used: float = 0.0
    exhausted: bool = False
    exhausted_dimension: str | None = None
    exhausted_at: str | None = None

    @classmethod
    def from_contract(cls, contract: Contract) -> BudgetTracker:
        tracker = cls(
            max_tool_calls=contract.max_tool_calls,
            max_net_calls=contract.max_net_calls,
        )
        if tracker.max_tool_calls is None and tracker.max_net_calls is None:
            _LOGGER.warning("Contract specifies no budget limits. Budget enforcement disabled.")
        return tracker

    @staticmethod
    def _utcnow_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def check_and_decrement(self, call_type: Literal["tool", "net"]) -> BudgetCheckResult:
        if self.exhausted:
            return BudgetCheckResult(
                allowed=False,
                reason="budget_exhausted",
                dimension=self.exhausted_dimension,
                first_exhaustion=False,
            )

        if call_type == "tool":
            limit = self.max_tool_calls
            used = self.tool_calls_used
            dimension = "tool_calls"
        elif call_type == "net":
            limit = self.max_net_calls
            used = self.net_calls_used
            dimension = "net_calls"
        else:
            raise ValueError("call_type must be 'tool' or 'net'")

        if limit is None:
            if call_type == "tool":
                self.tool_calls_used += 1
            else:
                self.net_calls_used += 1
            return BudgetCheckResult(
                allowed=True,
                reason=None,
                dimension=None,
                first_exhaustion=False,
            )

        if used >= limit:
            self.exhausted = True
            self.exhausted_dimension = dimension
            self.exhausted_at = self._utcnow_iso()
            return BudgetCheckResult(
                allowed=False,
                reason="budget_exhausted",
                dimension=dimension,
                first_exhaustion=True,
            )

        if call_type == "tool":
            self.tool_calls_used += 1
        else:
            self.net_calls_used += 1

        return BudgetCheckResult(
            allowed=True,
            reason=None,
            dimension=None,
            first_exhaustion=False,
        )

    def record_usage(self, tokens: int | None = None, dollars: float | None = None) -> None:
        if tokens is not None:
            self.tokens_used += int(tokens)
        if dollars is not None:
            self.dollars_used += float(dollars)
