from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest

from agentshield.budget.tracker import BudgetTracker
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.decisions import DecisionVerification
from agentshield.events.decisions import verify_decisions as verify_decisions_projection
from agentshield.events.logger import EventLogger
from agentshield.events.store import EventStore
from agentshield.proxy.server import ProxyServer
from agentshield.proxy.session import SessionState
from agentshield.signing.keys import generate_keypair

SESSION_START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
SESSION_END = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)


class _ChainOk:
    status = "INTACT"
    first_failure_sequence_id = None


class _ChainBroken:
    status = "BROKEN"
    first_failure_sequence_id = 7


CHAIN_OK = _ChainOk()
CHAIN_BROKEN = _ChainBroken()


@dataclass
class _ProxyCloseStub:
    contract: Any
    event_logger: Any
    budget_tracker: BudgetTracker
    _agent_identity_hash: str


@pytest.fixture
def session_state(tmp_path: Path, contract) -> SessionState:
    return SessionState(
        session_id="11111111-1111-1111-1111-111111111111",
        contract_id=contract.contract_id,
        session_start=SESSION_START,
        events_path=tmp_path / "events.jsonl",
        decisions_path=tmp_path / "decisions.jsonl",
        summary_path=tmp_path / "summary.json",
    )


@pytest.fixture
def proxy_stub(contract) -> _ProxyCloseStub:
    tracker = BudgetTracker.from_contract(contract)
    tracker.tool_calls_used = 15
    tracker.net_calls_used = 3
    logger = SimpleNamespace(log_event=MagicMock(return_value=None))
    return _ProxyCloseStub(
        contract=contract,
        event_logger=logger,
        budget_tracker=tracker,
        _agent_identity_hash="b" * 64,
    )


def test_session_state_rejects_naive_start(tmp_path: Path, contract) -> None:
    with pytest.raises(ValueError, match="session_start must be UTC-aware"):
        SessionState(
            session_id="11111111-1111-1111-1111-111111111111",
            contract_id=contract.contract_id,
            session_start=datetime(2026, 1, 1, 0, 0, 0),
            events_path=tmp_path / "events.jsonl",
            decisions_path=tmp_path / "decisions.jsonl",
            summary_path=tmp_path / "summary.json",
        )


def test_session_state_defaults(tmp_path: Path, contract) -> None:
    state = SessionState(
        session_id="11111111-1111-1111-1111-111111111111",
        contract_id=contract.contract_id,
        session_start=SESSION_START,
        events_path=tmp_path / "events.jsonl",
        decisions_path=tmp_path / "decisions.jsonl",
        summary_path=tmp_path / "summary.json",
    )
    assert state.closed is False
    assert state.budget_consumed == {}
    assert state.tool_calls_used == 0
    assert state.net_calls_used == 0


def test_session_close_raises_if_already_closed(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
) -> None:
    session_state.closed = True
    with pytest.raises(RuntimeError, match="already closed"):
        ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)


def test_session_close_raises_on_naive_session_end(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
) -> None:
    with pytest.raises(ValueError, match="session_end must be UTC-aware"):
        ProxyServer.session_close(proxy_stub, session_state, datetime(2026, 1, 1, 0, 5, 0), CHAIN_OK)


def test_session_close_writes_all_outputs(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
    make_test_events: Callable[[list[dict[str, Any]]], Path],
) -> None:
    events_path = make_test_events(
        [
            {"event_type": "tool_call", "decision": "allow"},
            {"event_type": "tool_call", "decision": "deny", "reason": "denied_by_contract"},
            {"event_type": "tool_call", "decision": "require_approval"},
            {"event_type": "tool_call", "decision": "allow"},
            {"event_type": "tool_call", "decision": "allow"},
        ]
    )
    session_state.events_path = events_path

    summary = ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)

    assert session_state.summary_path.exists()
    assert session_state.decisions_path.exists()
    assert session_state.closed is True
    summary_payload = json.loads(session_state.summary_path.read_text(encoding="utf-8"))
    assert summary_payload["session_id"] == session_state.session_id
    assert summary_payload["chain_integrity"] == "intact"
    lines = [line for line in session_state.decisions_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 5
    assert summary.total_calls == 5


def test_session_close_emits_summary_event_to_log_event(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
    make_test_events: Callable[[list[dict[str, Any]]], Path],
) -> None:
    events_path = make_test_events([{"event_type": "tool_call", "decision": "allow"} for _ in range(3)])
    session_state.events_path = events_path

    ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_BROKEN)

    assert proxy_stub.event_logger.log_event.called
    payload = proxy_stub.event_logger.log_event.call_args[0][0]
    assert payload["event_type"] == "write_op"
    assert payload["decision"] == "allow"
    assert payload["reason"] == "session_close"
    assert payload["tool_name"] == "session_summary"
    assert payload["risk_class"] == "read"
    assert "metadata" in payload
    assert payload["agent_identity"] == "b" * 64
    assert "sequence_id" not in payload
    assert "timestamp" not in payload
    assert "signature" not in payload


def test_session_close_uses_live_budget_tracker_state(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
    make_test_events: Callable[[list[dict[str, Any]]], Path],
) -> None:
    session_state.events_path = make_test_events([{"event_type": "tool_call"}])
    session_state.budget_consumed = {"tool_calls": 999.0, "net_calls": 888.0}
    proxy_stub.budget_tracker.tool_calls_used = 4
    proxy_stub.budget_tracker.net_calls_used = 2

    summary = ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)
    assert summary.budget_consumed == {"tool_calls": 4.0, "net_calls": 2.0}
    assert session_state.budget_consumed == {"tool_calls": 4.0, "net_calls": 2.0}


def test_session_close_warns_if_decisions_post_write_invalid(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    session_state.events_path = make_test_events([{"event_type": "tool_call", "decision": "allow"}])

    def _fake_verify(_: Path, __: Path) -> DecisionVerification:
        return DecisionVerification(
            is_valid=False,
            expected_count=1,
            actual_count=1,
            mismatches=[],
        )

    monkeypatch.setattr("agentshield.events.decisions.verify_decisions", _fake_verify)
    with caplog.at_level(logging.WARNING):
        ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)

    assert "failed post-write verification" in caplog.text


def test_summary_event_round_trip_through_real_event_logger(
    tmp_path: Path,
    contract,
) -> None:
    events_path = tmp_path / "events.jsonl"
    state = SessionState(
        session_id="11111111-1111-1111-1111-111111111111",
        contract_id=contract.contract_id,
        session_start=SESSION_START,
        events_path=events_path,
        decisions_path=tmp_path / "decisions.jsonl",
        summary_path=tmp_path / "summary.json",
    )
    keypair = generate_keypair(tmp_path / ".agentshield" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=state.session_id,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=tmp_path,
    )
    logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "filesystem.write",
            "risk_class": "write",
            "decision": "allow",
            "reason": "allowed_by_contract",
            "agent_identity": "b" * 64,
            "input_hash": "c" * 64,
        }
    )
    logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "web.search",
            "risk_class": "read",
            "decision": "allow",
            "reason": "allowed_by_contract",
            "agent_identity": "b" * 64,
            "input_hash": "d" * 64,
        }
    )
    tracker = BudgetTracker.from_contract(contract)
    tracker.tool_calls_used = 2
    tracker.net_calls_used = 0
    proxy = _ProxyCloseStub(
        contract=contract,
        event_logger=logger,
        budget_tracker=tracker,
        _agent_identity_hash="b" * 64,
    )

    ProxyServer.session_close(proxy, state, SESSION_END, CHAIN_OK)

    lines = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary_event = lines[-1]
    assert summary_event["tool_name"] == "session_summary"
    assert summary_event["event_type"] == "write_op"
    assert summary_event["decision"] == "allow"
    assert summary_event["reason"] == "session_close"
    assert summary_event["agent_identity"] == "b" * 64
    assert isinstance(summary_event["signature"], str) and summary_event["signature"]
    assert summary_event["contract_hash"] == compute_contract_hash(contract)
    assert summary_event["metadata"] == json.loads(state.summary_path.read_text(encoding="utf-8"))

    decisions_result = verify_decisions_projection(events_path, state.decisions_path)
    assert decisions_result.is_valid is True
    assert decisions_result.expected_count == 3
    assert decisions_result.actual_count == 3


def test_session_close_second_call_is_idempotent_and_does_not_write(
    proxy_stub: _ProxyCloseStub,
    session_state: SessionState,
    make_test_events: Callable[[list[dict[str, Any]]], Path],
) -> None:
    session_state.events_path = make_test_events(
        [
            {"event_type": "tool_call", "decision": "allow"},
            {"event_type": "tool_call", "decision": "deny", "reason": "denied_by_contract"},
        ]
    )
    ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)
    summary_hash = hashlib.sha256(session_state.summary_path.read_bytes()).hexdigest()
    decisions_hash = hashlib.sha256(session_state.decisions_path.read_bytes()).hexdigest()
    events_hash = hashlib.sha256(session_state.events_path.read_bytes()).hexdigest()

    with pytest.raises(RuntimeError, match="already closed"):
        ProxyServer.session_close(proxy_stub, session_state, SESSION_END, CHAIN_OK)

    assert hashlib.sha256(session_state.summary_path.read_bytes()).hexdigest() == summary_hash
    assert hashlib.sha256(session_state.decisions_path.read_bytes()).hexdigest() == decisions_hash
    assert hashlib.sha256(session_state.events_path.read_bytes()).hexdigest() == events_hash
    assert proxy_stub.event_logger.log_event.call_count == 1
