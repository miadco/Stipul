"""Break-glass override support for emergency tool access."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, cast
from uuid import uuid4

from agentshield.contract.schema import Contract
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.models import CanonicalEvent
from agentshield.permits import (
    _ensure_aware,
    _format_zulu,
    _normalize_hex64,
    _normalize_items,
    _normalize_positive_int,
    _normalize_uuid,
    _parse_zulu,
)

LOGGER = logging.getLogger("agentshield.breakglass")


@dataclass(frozen=True)
class BreakGlassEvent:
    breakglass_id: str
    triggered_by: str
    triggered_at: str
    reason: str
    scope: Literal["all_tools", "specific_tools"]
    specific_tools: tuple[str, ...]
    ttl: int
    expires_at: str
    session_id: str
    contract_id: str
    contract_hash: str


class BreakGlassManager:
    """Create and evaluate break-glass emergency overrides."""

    def __init__(self, contract: Contract, max_ttl_cap: int = 3600) -> None:
        self.contract = contract
        self.contract_hash = compute_contract_hash(contract)
        self.max_ttl_cap = _normalize_positive_int("max_ttl_cap", max_ttl_cap)

    def trigger(
        self,
        triggered_by_hex64: str,
        reason: str,
        scope: Literal["all_tools", "specific_tools"],
        specific_tools: list[str] | tuple[str, ...] | set[str] | frozenset[str],
        ttl: int,
        session_id: str,
        *,
        triggered_at: datetime | None = None,
    ) -> BreakGlassEvent:
        triggered_by = _normalize_hex64("triggered_by_hex64", triggered_by_hex64)
        normalized_reason = self._normalize_reason(reason)
        normalized_scope = self._normalize_scope(scope)
        normalized_tools = _normalize_items("specific_tools", specific_tools)
        normalized_ttl = _normalize_positive_int("ttl", ttl)
        normalized_session_id = _normalize_uuid("session_id", session_id)
        triggered_at_dt = _ensure_aware("triggered_at", triggered_at)

        if normalized_ttl > self.max_ttl_cap:
            raise ValueError("ttl must not exceed max_ttl_cap")

        if normalized_scope == "all_tools" and normalized_tools:
            raise ValueError("specific_tools must be empty when scope is all_tools")
        if normalized_scope == "specific_tools" and not normalized_tools:
            raise ValueError("specific_tools must not be empty when scope is specific_tools")

        for tool in normalized_tools:
            if tool in self.contract.never_allow_tools:
                raise ValueError(f"tool '{tool}' is in never_allow_tools")
            if tool not in self.contract.allowed_tools and tool not in self.contract.tool_risk_classes:
                raise ValueError(f"tool '{tool}' is unknown to the contract")

        expires_at = triggered_at_dt.timestamp() + normalized_ttl
        event = BreakGlassEvent(
            breakglass_id=str(uuid4()),
            triggered_by=triggered_by,
            triggered_at=_format_zulu(triggered_at_dt),
            reason=normalized_reason,
            scope=normalized_scope,
            specific_tools=normalized_tools,
            ttl=normalized_ttl,
            expires_at=_format_zulu(datetime.fromtimestamp(expires_at, tz=timezone.utc)),
            session_id=normalized_session_id,
            contract_id=self.contract.contract_id,
            contract_hash=self.contract_hash,
        )
        LOGGER.warning(
            "Break-glass triggered by %s scope=%s ttl=%s session_id=%s",
            event.triggered_by,
            event.scope,
            event.ttl,
            event.session_id,
        )
        return event

    def is_active(self, event: BreakGlassEvent, current_time: datetime) -> bool:
        current_time_dt = _ensure_aware("current_time", current_time)
        return current_time_dt < _parse_zulu("expires_at", event.expires_at)

    def check_tool_against_breakglass(
        self,
        event: BreakGlassEvent,
        tool_name: str,
        current_time: datetime,
    ) -> bool:
        if not isinstance(tool_name, str) or not tool_name:
            return False
        if tool_name in self.contract.never_allow_tools:
            return False
        if not self.is_active(event, current_time):
            return False
        if event.scope == "all_tools":
            return True
        return tool_name in event.specific_tools

    def build_breakglass_summary(
        self,
        event: BreakGlassEvent,
        events: list[CanonicalEvent],
    ) -> dict[str, Any]:
        window_start = _parse_zulu("triggered_at", event.triggered_at)
        window_end = _parse_zulu("expires_at", event.expires_at)
        tools_used: dict[str, int] = {}
        total = 0

        for item in events:
            event_time = _parse_zulu("timestamp", item.timestamp)
            if not (window_start <= event_time < window_end):
                continue
            if item.event_type != "tool_call":
                continue
            if item.decision != "allow":
                continue
            if item.reason != "breakglass_active":
                continue
            if event.scope == "specific_tools" and item.tool_name not in event.specific_tools:
                continue
            tools_used[item.tool_name] = tools_used.get(item.tool_name, 0) + 1
            total += 1

        return {
            "breakglass_id": event.breakglass_id,
            "flagged_for_review": True,
            "tools_used": tools_used,
            "total_matching_allows": total,
            "window_start": event.triggered_at,
            "window_end": event.expires_at,
        }

    @staticmethod
    def _normalize_reason(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("reason must be a string")
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("reason must be at least 10 characters")
        return normalized

    @staticmethod
    def _normalize_scope(value: str) -> Literal["all_tools", "specific_tools"]:
        if value not in {"all_tools", "specific_tools"}:
            raise ValueError("scope must be 'all_tools' or 'specific_tools'")
        return cast(Literal["all_tools", "specific_tools"], value)


__all__ = ["BreakGlassEvent", "BreakGlassManager"]
