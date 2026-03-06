from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from stipul.writ.breakglass import BreakGlassManager
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.models import CanonicalEvent

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_TRIGGERED_BY = "a" * 64


def _dt(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _event(
    contract,
    *,
    tool_name: str,
    timestamp: str,
    reason: str,
    decision: str = "allow",
    event_type: str = "tool_call",
) -> CanonicalEvent:
    return CanonicalEvent(
        sequence_id=1,
        timestamp=timestamp,
        session_id=_SESSION_ID,
        event_type=event_type,
        tool_name=tool_name,
        risk_class="write",
        decision=decision,
        reason=reason,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        agent_identity="b" * 64,
        input_hash="c" * 64,
        key_id="deadbeef",
        algorithm="ed25519",
        key_created_at="2026-01-01T00:00:00Z",
        prev_hash="0" * 64,
        signature=base64.b64encode(b"signature").decode("ascii"),
    )


def test_trigger_valid_logs_warning(caplog, contract):
    manager = BreakGlassManager(contract)

    with caplog.at_level("WARNING", logger="stipul.writ.breakglass"):
        event = manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency write access now",
            scope="specific_tools",
            specific_tools=["filesystem.write"],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )

    assert event.contract_hash == compute_contract_hash(contract)
    assert any("Break-glass triggered" in message for message in caplog.messages)


def test_trigger_rejects_invalid_reason_scope_ttl_and_tool_list(contract):
    manager = BreakGlassManager(contract)

    with pytest.raises(ValueError, match="at least 10 characters"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="too short",
            scope="specific_tools",
            specific_tools=["filesystem.write"],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )

    with pytest.raises(ValueError, match="scope"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency write access now",
            scope="wrong",  # type: ignore[arg-type]
            specific_tools=["filesystem.write"],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )

    with pytest.raises(ValueError, match="max_ttl_cap"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency write access now",
            scope="specific_tools",
            specific_tools=["filesystem.write"],
            ttl=3601,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )

    with pytest.raises(ValueError, match="specific_tools must be empty"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency access to everything",
            scope="all_tools",
            specific_tools=["filesystem.write"],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )

    with pytest.raises(ValueError, match="specific_tools must not be empty"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency write access now",
            scope="specific_tools",
            specific_tools=[],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )


def test_trigger_rejects_never_allow_tool(contract):
    manager = BreakGlassManager(contract)

    with pytest.raises(ValueError, match="never_allow_tools"):
        manager.trigger(
            triggered_by_hex64=_TRIGGERED_BY,
            reason="Need emergency shell execution now",
            scope="specific_tools",
            specific_tools=["shell.exec"],
            ttl=60,
            session_id=_SESSION_ID,
            triggered_at=_dt(2026, 1, 1),
        )


def test_is_active_and_check_tool_against_breakglass(contract):
    manager = BreakGlassManager(contract)
    event = manager.trigger(
        triggered_by_hex64=_TRIGGERED_BY,
        reason="Need emergency access to everything",
        scope="all_tools",
        specific_tools=[],
        ttl=60,
        session_id=_SESSION_ID,
        triggered_at=_dt(2026, 1, 1),
    )

    assert manager.is_active(event, _dt(2026, 1, 1, 0, 0, 30))
    assert not manager.is_active(event, _dt(2026, 1, 1, 0, 1, 0))
    assert manager.check_tool_against_breakglass(event, "web.search", _dt(2026, 1, 1, 0, 0, 30))
    assert not manager.check_tool_against_breakglass(
        event,
        "shell.exec",
        _dt(2026, 1, 1, 0, 0, 30),
    )
    assert not manager.check_tool_against_breakglass(
        event,
        "web.search",
        _dt(2026, 1, 1, 0, 1, 0),
    )


def test_specific_tools_scope_only_matches_listed_tools(contract):
    manager = BreakGlassManager(contract)
    event = manager.trigger(
        triggered_by_hex64=_TRIGGERED_BY,
        reason="Need emergency write access now",
        scope="specific_tools",
        specific_tools=["filesystem.write"],
        ttl=60,
        session_id=_SESSION_ID,
        triggered_at=_dt(2026, 1, 1),
    )

    assert manager.check_tool_against_breakglass(
        event,
        "filesystem.write",
        _dt(2026, 1, 1, 0, 0, 1),
    )
    assert not manager.check_tool_against_breakglass(
        event,
        "web.search",
        _dt(2026, 1, 1, 0, 0, 1),
    )


def test_build_breakglass_summary_counts_only_matching_allows(contract):
    manager = BreakGlassManager(contract)
    event = manager.trigger(
        triggered_by_hex64=_TRIGGERED_BY,
        reason="Need emergency write access now",
        scope="specific_tools",
        specific_tools=["filesystem.write"],
        ttl=120,
        session_id=_SESSION_ID,
        triggered_at=_dt(2026, 1, 1),
    )

    summary = manager.build_breakglass_summary(
        event,
        [
            _event(
                contract,
                tool_name="filesystem.write",
                timestamp="2026-01-01T00:00:10Z",
                reason="breakglass_active",
            ),
            _event(
                contract,
                tool_name="web.search",
                timestamp="2026-01-01T00:00:20Z",
                reason="breakglass_active",
            ),
            _event(
                contract,
                tool_name="filesystem.write",
                timestamp="2026-01-01T00:00:30Z",
                reason="risk_class",
            ),
            _event(
                contract,
                tool_name="filesystem.write",
                timestamp="2026-01-01T00:03:01Z",
                reason="breakglass_active",
            ),
        ],
    )

    assert summary["breakglass_id"] == event.breakglass_id
    assert summary["flagged_for_review"] is True
    assert summary["total_matching_allows"] == 1
    assert summary["tools_used"] == {"filesystem.write": 1}
