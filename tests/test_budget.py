from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from stipul.charter.budget.decay import DecayDetector
from stipul.charter.budget.state import load_budget_state, save_budget_state
from stipul.charter.budget.tracker import BudgetTracker
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.exceptions import BudgetExhaustedError
from stipul.writ.proxy.server import ProxyServer
from stipul.chronicle.signing.keys import generate_keypair

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _build_proxy(
    contract: Contract,
    events_path: Path,
    *,
    budget_tracker: BudgetTracker | None = None,
    decay_detector: DecayDetector | None = None,
    **kwargs,
) -> ProxyServer:
    keypair = generate_keypair(events_path.parent / ".stipul" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=events_path.parent,
    )
    return ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=_SESSION_ID,
        state_dir=events_path.parent,
        budget_tracker=budget_tracker,
        decay_detector=decay_detector,
        **kwargs,
    )


class _NoTTLContract:
    created_at = None
    expires_at = None
    max_tool_calls = 10
    max_net_calls = 10


def test_budget_tracker_from_contract_initializes_limits(contract: Contract) -> None:
    tracker = BudgetTracker.from_contract(contract)

    assert tracker.max_tool_calls == contract.max_tool_calls
    assert tracker.max_net_calls == contract.max_net_calls
    assert tracker.tool_calls_used == 0
    assert tracker.net_calls_used == 0


def test_budget_tracker_from_contract_handles_none_limits(contract: Contract) -> None:
    contract_with_none = replace(contract, max_net_calls=None)  # type: ignore[arg-type]
    tracker = BudgetTracker.from_contract(contract_with_none)

    assert tracker.max_tool_calls == contract.max_tool_calls
    assert tracker.max_net_calls is None
    result = tracker.check_and_decrement("net")
    assert result.allowed is True
    assert tracker.net_calls_used == 1


def test_budget_tracker_warns_when_all_limits_disabled(caplog, contract: Contract) -> None:
    contract_with_none = replace(  # type: ignore[arg-type]
        contract,
        max_tool_calls=None,
        max_net_calls=None,
    )
    with caplog.at_level(logging.WARNING):
        tracker = BudgetTracker.from_contract(contract_with_none)

    assert tracker.max_tool_calls is None
    assert tracker.max_net_calls is None
    assert "Contract specifies no budget limits. Budget enforcement disabled." in caplog.text


def test_budget_tracker_tool_call_updates_only_tool_dimension() -> None:
    tracker = BudgetTracker(max_tool_calls=10, max_net_calls=5)

    result = tracker.check_and_decrement("tool")

    assert result.allowed is True
    assert tracker.tool_calls_used == 1
    assert tracker.net_calls_used == 0


def test_budget_tracker_net_call_updates_only_net_dimension() -> None:
    tracker = BudgetTracker(max_tool_calls=10, max_net_calls=5)

    result = tracker.check_and_decrement("net")

    assert result.allowed is True
    assert tracker.tool_calls_used == 0
    assert tracker.net_calls_used == 1


def test_budget_tracker_first_and_subsequent_exhaustion_flags() -> None:
    tracker = BudgetTracker(max_tool_calls=1, max_net_calls=5, tool_calls_used=1)

    first = tracker.check_and_decrement("tool")
    second = tracker.check_and_decrement("tool")

    assert first.allowed is False
    assert first.reason == "budget_exhausted"
    assert first.dimension == "tool_calls"
    assert first.first_exhaustion is True
    assert second.allowed is False
    assert second.first_exhaustion is False


def test_budget_tracker_exhaustion_blocks_other_dimension() -> None:
    tracker = BudgetTracker(max_tool_calls=1, max_net_calls=99, tool_calls_used=1)

    first = tracker.check_and_decrement("tool")
    blocked = tracker.check_and_decrement("net")

    assert first.allowed is False
    assert blocked.allowed is False
    assert blocked.reason == "budget_exhausted"
    assert blocked.first_exhaustion is False


def test_budget_tracker_record_usage_is_observational_only() -> None:
    tracker = BudgetTracker(max_tool_calls=1, max_net_calls=1)

    tracker.record_usage(tokens=120, dollars=1.25)
    tracker.record_usage(tokens=3)
    tracker.record_usage(dollars=0.5)

    assert tracker.tokens_used == 123
    assert tracker.dollars_used == pytest.approx(1.75)
    assert tracker.exhausted is False


def test_save_budget_state_writes_expected_schema(tmp_path: Path) -> None:
    tracker = BudgetTracker(
        max_tool_calls=10,
        max_net_calls=5,
        tool_calls_used=2,
        net_calls_used=1,
        tokens_used=15,
        dollars_used=0.05,
    )

    save_budget_state(tmp_path, tracker, _SESSION_ID)

    state_path = tmp_path / "budget_state.json"
    assert state_path.exists()
    assert not (tmp_path / "budget_state.json.tmp").exists()
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["session_id"] == _SESSION_ID
    assert payload["tool_calls_used"] == 2
    assert payload["net_calls_used"] == 1
    assert payload["tokens_used"] == 15
    assert payload["dollars_used"] == pytest.approx(0.05)
    assert isinstance(payload["saved_at"], str)


def test_load_budget_state_absent_returns_none(tmp_path: Path) -> None:
    assert load_budget_state(tmp_path, _SESSION_ID) is None


def test_load_budget_state_session_mismatch_returns_none(tmp_path: Path) -> None:
    tracker = BudgetTracker(max_tool_calls=1, max_net_calls=1, tool_calls_used=1)
    save_budget_state(tmp_path, tracker, "99999999-9999-9999-9999-999999999999")

    assert load_budget_state(tmp_path, _SESSION_ID) is None


def test_load_budget_state_reconstructs_tracker(tmp_path: Path) -> None:
    tracker = BudgetTracker(
        max_tool_calls=10,
        max_net_calls=5,
        tool_calls_used=3,
        net_calls_used=2,
        tokens_used=45,
        dollars_used=0.33,
        exhausted=False,
    )
    save_budget_state(tmp_path, tracker, _SESSION_ID)

    loaded = load_budget_state(tmp_path, _SESSION_ID)

    assert loaded is not None
    assert loaded.max_tool_calls == 10
    assert loaded.max_net_calls == 5
    assert loaded.tool_calls_used == 3
    assert loaded.net_calls_used == 2
    assert loaded.tokens_used == 45
    assert loaded.dollars_used == pytest.approx(0.33)


def test_load_budget_state_raises_when_exhausted(tmp_path: Path) -> None:
    tracker = BudgetTracker(
        max_tool_calls=1,
        max_net_calls=1,
        tool_calls_used=1,
        exhausted=True,
        exhausted_dimension="tool_calls",
        exhausted_at="2026-01-01T00:00:00Z",
    )
    save_budget_state(tmp_path, tracker, _SESSION_ID)

    with pytest.raises(
        BudgetExhaustedError,
        match="Budget exhausted in prior session. Start a new session with a new contract.",
    ):
        load_budget_state(tmp_path, _SESSION_ID)


def test_decay_detector_disables_when_no_ttl(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        detector = DecayDetector.from_contract(_NoTTLContract(), datetime.now(timezone.utc))

    assert detector.contract_ttl_seconds is None
    assert "No TTL set, budget decay detection disabled." in caplog.text
    check_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert detector.check(BudgetTracker(max_tool_calls=10, max_net_calls=10), current_time=check_time) is None


def test_decay_detector_normal_rate_no_anomaly() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(max_tool_calls=100, max_net_calls=100, tool_calls_used=40)
    current_time = start + timedelta(seconds=500)

    assert detector.check(tracker, current_time=current_time) is None


def test_decay_detector_rapid_burn_triggers_anomaly() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(max_tool_calls=100, max_net_calls=100, tool_calls_used=85)
    current_time = start + timedelta(seconds=150)

    anomaly = detector.check(tracker, current_time=current_time)

    assert anomaly is not None
    assert anomaly.dimension == "tool_calls"
    assert anomaly.spend_fraction == pytest.approx(0.85)
    assert anomaly.time_fraction == pytest.approx(0.15)
    assert anomaly.burn_rate > 0
    assert anomaly.projected_exhaustion_seconds > 0


def test_decay_detector_returns_tool_anomaly_before_net() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(
        max_tool_calls=100,
        max_net_calls=100,
        tool_calls_used=85,
        net_calls_used=90,
    )
    current_time = start + timedelta(seconds=150)

    anomaly = detector.check(tracker, current_time=current_time)

    assert anomaly is not None
    assert anomaly.dimension == "tool_calls"


def test_decay_detector_emits_once_per_dimension() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(max_tool_calls=100, max_net_calls=100, tool_calls_used=85)
    current_time = start + timedelta(seconds=150)

    first = detector.check(tracker, current_time=current_time)
    second = detector.check(tracker, current_time=current_time)

    assert first is not None
    assert second is None
    assert detector.tool_calls_anomaly_emitted is True


def test_decay_detector_skips_when_tracker_exhausted() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(
        max_tool_calls=100,
        max_net_calls=100,
        tool_calls_used=85,
        exhausted=True,
        exhausted_dimension="tool_calls",
    )
    current_time = start + timedelta(seconds=150)

    assert detector.check(tracker, current_time=current_time) is None


def test_decay_detector_burn_rate_zero_guard() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=start)
    tracker = BudgetTracker(max_tool_calls=100, max_net_calls=100, tool_calls_used=85)

    anomaly = detector.check(tracker, current_time=start)

    assert anomaly is not None
    assert anomaly.burn_rate == 0.0
    assert anomaly.projected_exhaustion_seconds == float("inf")


def test_proxy_budget_check_runs_before_policy_eval(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    tracker = BudgetTracker(max_tool_calls=0, max_net_calls=5)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=datetime.now(timezone.utc))
    proxy = _build_proxy(contract, events_path, budget_tracker=tracker, decay_detector=detector)

    called = {"intercept": 0}

    def _boom(*_args, **_kwargs):
        called["intercept"] += 1
        raise AssertionError("policy layer should not run after budget denial")

    monkeypatch.setattr("stipul.writ.proxy.server.intercept", _boom)

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt"}},
        lambda _request: {"ok": True},
    )

    assert response == {
        "decision": "deny",
        "reason": "budget_exhausted",
        "tool_name": "filesystem.write",
    }
    assert called["intercept"] == 0
    events = _read_events(events_path)
    assert [event["event_type"] for event in events] == ["budget_exhausted", "tool_call"]
    assert events[1]["decision"] == "deny"
    assert events[1]["reason"] == "budget_exhausted"
    budget_state = json.loads((tmp_path / "budget_state.json").read_text(encoding="utf-8"))
    assert budget_state["exhausted"] is True


def test_proxy_first_denial_emits_budget_exhausted_once(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    tracker = BudgetTracker(max_tool_calls=0, max_net_calls=5)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=datetime.now(timezone.utc))
    proxy = _build_proxy(contract, events_path, budget_tracker=tracker, decay_detector=detector)

    request = {"tool_name": "filesystem.write", "inputs": {"path": "out.txt"}}
    proxy.handle_tool_call(request, lambda _request: {"ok": True})
    proxy.handle_tool_call(request, lambda _request: {"ok": True})

    events = _read_events(events_path)
    assert sum(1 for event in events if event["event_type"] == "budget_exhausted") == 1
    assert events[-1]["decision"] == "deny"
    assert events[-1]["reason"] == "budget_exhausted"


def test_proxy_budget_deny_never_mints_token(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    tracker = BudgetTracker(max_tool_calls=0, max_net_calls=5)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=datetime.now(timezone.utc))
    proxy = _build_proxy(contract, events_path, budget_tracker=tracker, decay_detector=detector)

    minted = {"count": 0}

    def _fake_mint(*_args, **_kwargs):
        minted["count"] += 1
        return "token"

    monkeypatch.setattr("stipul.writ.proxy.server.mint_token", _fake_mint)
    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt"}},
        lambda _request: {"ok": True},
    )

    assert response["reason"] == "budget_exhausted"
    assert minted["count"] == 0


def test_proxy_anomaly_emits_once_and_does_not_block_call(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    session_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracker = BudgetTracker(max_tool_calls=10, max_net_calls=10, tool_calls_used=8)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=session_start)
    monkeypatch.setattr(
        DecayDetector,
        "_utcnow",
        staticmethod(lambda: session_start + timedelta(seconds=100)),
    )
    proxy = _build_proxy(contract, events_path, budget_tracker=tracker, decay_detector=detector)

    forwarded = {"count": 0}

    def _forward(_request):
        forwarded["count"] += 1
        return {"ok": True}

    first = proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {}}, _forward)
    second = proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {}}, _forward)

    assert first == {"ok": True}
    assert second == {"ok": True}
    assert forwarded["count"] == 2

    events = _read_events(events_path)
    assert sum(1 for event in events if event["event_type"] == "budget_anomaly") == 1
    budget_state = json.loads((tmp_path / "budget_state.json").read_text(encoding="utf-8"))
    assert budget_state["tool_calls_used"] == 10


def test_proxy_saves_budget_state_after_budget_allow_even_if_policy_denies(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    tracker = BudgetTracker(max_tool_calls=10, max_net_calls=5)
    detector = DecayDetector(contract_ttl_seconds=1000.0, session_start=datetime.now(timezone.utc))
    proxy = _build_proxy(contract, events_path, budget_tracker=tracker, decay_detector=detector)

    response = proxy.handle_tool_call(
        {"tool_name": "unknown.tool", "inputs": {}},
        lambda _request: {"ok": True},
    )

    assert response["reason"] == "not_in_contract"
    state = json.loads((tmp_path / "budget_state.json").read_text(encoding="utf-8"))
    assert state["tool_calls_used"] == 1


def test_proxy_startup_refuses_exhausted_budget_state(
    tmp_path: Path, monkeypatch, base_dict
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(base_dict), encoding="utf-8")
    save_budget_state(
        tmp_path,
        BudgetTracker(
            max_tool_calls=1,
            max_net_calls=1,
            tool_calls_used=1,
            exhausted=True,
            exhausted_dimension="tool_calls",
            exhausted_at="2026-01-01T00:00:00Z",
        ),
        _SESSION_ID,
    )

    with pytest.raises(
        BudgetExhaustedError,
        match="Budget exhausted in prior session. Start a new session with a new contract.",
    ):
        ProxyServer.from_contract_path(
            contract_path=contract_path,
            session_id=_SESSION_ID,
            events_path=tmp_path / "events.jsonl",
        )
