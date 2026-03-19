"""Budget burn-rate anomaly detection.

`DecayDetector.check(tracker, current_time=None)` defaults to wall-clock UTC to preserve
runtime integration behavior in the proxy.

For deterministic analysis and tests, pass an explicit `current_time` to `check(...)` or
use `check_burn_rate(current_spend, current_time)` directly.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from stipul.charter.budget.tracker import BudgetTracker
from stipul.charter.contract.schema import Contract

logger = logging.getLogger("stipul.charter.budget.decay")


@dataclass(frozen=True)
class DecayAlert:
    """Immutable record of a detected budget burn-rate anomaly."""

    triggered_dimension: str
    spend_fraction: float
    time_fraction: float
    burn_rate: float
    projected_exhaustion_seconds: float
    current_spend: dict[str, float]
    budget_limit: dict[str, float]

    @property
    def dimension(self) -> str:
        """Backward-compatible alias used by existing budget tests/callers."""
        return self.triggered_dimension


# Backward compatibility: existing code imports DecayAnomaly.
DecayAnomaly = DecayAlert


class DecayDetector:
    """Detect high burn-rate budget anomalies relative to contract TTL."""

    def __init__(
        self,
        budget_limit: dict[str, int | float] | None = None,
        ttl: int | None = None,
        session_start: datetime | None = None,
        *,
        contract_ttl_seconds: float | None = None,
    ) -> None:
        if session_start is None:
            raise ValueError("session_start must be UTC-aware")
        if session_start.tzinfo is None:
            raise ValueError("session_start must be UTC-aware")

        if ttl is None and contract_ttl_seconds is not None:
            ttl = int(contract_ttl_seconds)
        if ttl is not None and ttl <= 0:
            raise ValueError("ttl must be a positive integer")

        self.session_start = session_start.astimezone(timezone.utc)
        self.ttl = ttl
        # Keep old attribute name for backward compatibility.
        self.contract_ttl_seconds = float(ttl) if ttl is not None else None
        self.budget_limit: dict[str, float] = {
            key: float(value)
            for key, value in (budget_limit or {}).items()
        }
        self.anomaly_threshold_budget: float = 0.80
        self.anomaly_threshold_time: float = 0.20
        self.anomalies_detected: int = 0
        self.tool_calls_anomaly_emitted: bool = False
        self.net_calls_anomaly_emitted: bool = False

        if self.ttl is None:
            logger.warning("No TTL set on contract, budget decay detection disabled.")
            # Backward-compatible warning string expected by Day 4 tests.
            logger.warning("No TTL set, budget decay detection disabled.")

    @classmethod
    def from_contract(cls, contract: Contract, session_start: datetime) -> DecayDetector:
        ttl: int | None = None
        created_at = getattr(contract, "created_at", None)
        expires_at = getattr(contract, "expires_at", None)
        if isinstance(created_at, datetime) and isinstance(expires_at, datetime):
            ttl_seconds = (expires_at - created_at).total_seconds()
            if ttl_seconds > 0:
                ttl = int(ttl_seconds)

        budget_limit: dict[str, int | float] = {}
        max_tool_calls = getattr(contract, "max_tool_calls", None)
        max_net_calls = getattr(contract, "max_net_calls", None)
        if max_tool_calls is not None:
            budget_limit["tool_calls"] = max_tool_calls
        if max_net_calls is not None:
            budget_limit["net_calls"] = max_net_calls
        return cls(
            budget_limit=budget_limit,
            ttl=ttl,
            session_start=session_start,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    def _check_burn_rate_with_limit(
        self,
        *,
        budget_limit: dict[str, float],
        current_spend: dict[str, int | float],
        current_time: datetime,
        allow_zero_time_fraction: bool,
        select_highest_burn_rate: bool,
    ) -> DecayAlert | None:
        if self.ttl is None:
            return None
        if current_time.tzinfo is None:
            raise ValueError("current_time must be UTC-aware")

        current_time_utc = current_time.astimezone(timezone.utc)
        time_fraction = (current_time_utc - self.session_start).total_seconds() / float(self.ttl)
        if time_fraction <= 0:
            if not allow_zero_time_fraction:
                return None
            time_fraction = 0.0
        if time_fraction >= 1.0:
            return None

        spend_float = {key: float(value) for key, value in current_spend.items()}
        budget_float = dict(budget_limit)
        candidates: list[DecayAlert] = []
        for dimension in budget_float:
            if dimension not in spend_float:
                continue

            limit = budget_float[dimension]
            if limit == 0:
                continue

            spend_fraction = spend_float[dimension] / limit
            if (
                spend_fraction > self.anomaly_threshold_budget
                and time_fraction < self.anomaly_threshold_time
            ):
                if time_fraction > 0:
                    burn_rate = spend_fraction / time_fraction
                else:
                    burn_rate = 0.0
                projected_exhaustion_seconds = (
                    (float(self.ttl) * (1.0 - spend_fraction)) / burn_rate
                    if burn_rate > 0
                    else float("inf")
                )
                candidates.append(
                    DecayAlert(
                        triggered_dimension=dimension,
                        spend_fraction=spend_fraction,
                        time_fraction=time_fraction,
                        burn_rate=burn_rate,
                        projected_exhaustion_seconds=projected_exhaustion_seconds,
                        current_spend=spend_float,
                        budget_limit=budget_float,
                    )
                )

        if not candidates:
            return None
        if select_highest_burn_rate:
            return max(candidates, key=lambda candidate: candidate.burn_rate)
        return candidates[0]

    def check_burn_rate(
        self,
        current_spend: dict[str, int | float],
        current_time: datetime,
    ) -> DecayAlert | None:
        return self._check_burn_rate_with_limit(
            budget_limit=self.budget_limit,
            current_spend=current_spend,
            current_time=current_time,
            allow_zero_time_fraction=False,
            select_highest_burn_rate=True,
        )

    def check(
        self,
        tracker: BudgetTracker,
        *,
        current_time: datetime | None = None,
    ) -> DecayAnomaly | None:
        """Runtime compatibility adapter over tracker state.

        When `current_time` is omitted this samples current wall-clock UTC.
        Deterministic callers should pass `current_time` (or use `check_burn_rate(...)`).
        """
        if tracker.exhausted:
            return None

        budget_limit = dict(self.budget_limit)
        if not budget_limit:
            if tracker.max_tool_calls is not None:
                budget_limit["tool_calls"] = float(tracker.max_tool_calls)
            if tracker.max_net_calls is not None:
                budget_limit["net_calls"] = float(tracker.max_net_calls)

        legacy_mode = not bool(self.budget_limit)
        alert = self._check_burn_rate_with_limit(
            budget_limit=budget_limit,
            current_spend={
                "tool_calls": tracker.tool_calls_used,
                "net_calls": tracker.net_calls_used,
            },
            current_time=current_time if current_time is not None else self._utcnow(),
            # Backward compatibility for Day 4 tests where elapsed==0.
            allow_zero_time_fraction=legacy_mode,
            # Backward compatibility for Day 4 tests expecting tool-first selection.
            select_highest_burn_rate=not legacy_mode,
        )
        if alert is None:
            return None

        if alert.triggered_dimension == "tool_calls":
            if self.tool_calls_anomaly_emitted:
                return None
            self.tool_calls_anomaly_emitted = True
        elif alert.triggered_dimension == "net_calls":
            if self.net_calls_anomaly_emitted:
                return None
            self.net_calls_anomaly_emitted = True

        self.anomalies_detected += 1
        return alert

    def to_event_payload(self, alert: DecayAlert) -> dict[str, Any]:
        base = asdict(alert)
        if alert.projected_exhaustion_seconds == float("inf"):
            exhaustion_str = "unknown (burn rate is zero)"
        else:
            exhaustion_str = f"{alert.projected_exhaustion_seconds:.0f}s"

        message = (
            "Budget anomaly detected for "
            f"{alert.triggered_dimension}; projected exhaustion: {exhaustion_str}."
        )
        return {
            **base,
            "event_subtype": "budget_anomaly",
            "message": message,
        }
