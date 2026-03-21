from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from stipul.writ.breakglass import BreakGlassManager
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.charter.permits import PERMIT_SECRET_ENV, PermitManager
from stipul.writ.proxy.server import ProxyServer
from stipul.writ.proxy.session import SessionState
from stipul.chronicle.signing.keys import generate_keypair
from stipul.charter.token.validate import validate_token

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_PERMIT_SECRET = b"permit-secret"
_HEX_A = "a" * 64
_HEX_B = "b" * 64


def _read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _build_proxy(contract: Contract, events_path: Path, **kwargs) -> ProxyServer:
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
        **kwargs,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_permit_overrides_not_in_contract_without_bypassing_budget(tmp_path: Path, monkeypatch, base_dict):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv(PERMIT_SECRET_ENV, _PERMIT_SECRET.decode("utf-8"))
    payload = dict(base_dict)
    payload["tool_risk_classes"] = dict(base_dict["tool_risk_classes"])
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    contract = Contract.from_dict(payload)
    permit_manager = PermitManager(contract, _PERMIT_SECRET, _SESSION_ID)
    now = _now()
    request = permit_manager.create_request(
        requested_by_hex64=_HEX_A,
        permitted_tools=["debug.inspect"],
        permitted_destinations=[],
        reason="Need temporary debug access",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=now,
    )
    permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now,
        granted_ttl=300,
    )
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(
        contract,
        events_path,
        active_permits=[permit],
    )
    captured: dict[str, object] = {}

    def forward_call(request):
        captured["request"] = request
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {"target": "x"}},
        forward_call,
    )

    assert response == {"ok": True}
    auth = captured["request"]["headers"]["Authorization"]  # type: ignore[index]
    token = auth.split(" ", 1)[1]
    assert validate_token(token, "debug.inspect") == (True, "valid")
    assert proxy.budget_tracker is not None
    assert proxy.budget_tracker.tool_calls_used == 1
    events = _read_events(events_path)
    assert events[-1]["event_type"] == "tool_call"
    assert events[-1]["reason"] == "exception_permit_active"
    assert any(event["event_type"] == "elev_op" and event["reason"] == "exception_permit_active" for event in events)


def test_breakglass_overrides_permit_priority(tmp_path: Path, monkeypatch, base_dict):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv(PERMIT_SECRET_ENV, _PERMIT_SECRET.decode("utf-8"))
    payload = dict(base_dict)
    payload["tool_risk_classes"] = dict(base_dict["tool_risk_classes"])
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    contract = Contract.from_dict(payload)
    permit_manager = PermitManager(contract, _PERMIT_SECRET, _SESSION_ID)
    now = _now()
    request = permit_manager.create_request(
        requested_by_hex64=_HEX_A,
        permitted_tools=["debug.inspect"],
        permitted_destinations=[],
        reason="Need temporary debug access",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=now,
    )
    permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now,
        granted_ttl=300,
    )
    breakglass = BreakGlassManager(contract).trigger(
        triggered_by_hex64=_HEX_B,
        reason="Need emergency access to debug tooling",
        scope="specific_tools",
        specific_tools=["debug.inspect"],
        ttl=300,
        session_id=_SESSION_ID,
        triggered_at=now,
    )
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(
        contract,
        events_path,
        active_permits=[permit],
        active_breakglass=breakglass,
    )

    response = proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )

    assert response == {"ok": True}
    events = _read_events(events_path)
    assert events[-1]["reason"] == "breakglass_active"
    assert any(event["event_type"] == "elev_op" and event["reason"] == "breakglass_active" for event in events)


def test_active_permits_require_env_secret(tmp_path: Path, base_dict):
    contract = Contract.from_dict(base_dict)
    permit_manager = PermitManager(contract, _PERMIT_SECRET, _SESSION_ID)
    now = _now()
    request = permit_manager.create_request(
        requested_by_hex64=_HEX_A,
        permitted_tools=["filesystem.write"],
        permitted_destinations=[],
        reason="Need temporary write access",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=now,
    )
    permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now,
        granted_ttl=300,
    )

    try:
        _build_proxy(contract, tmp_path / "events.jsonl", active_permits=[permit])
    except ValueError as exc:
        assert PERMIT_SECRET_ENV in str(exc)
    else:
        raise AssertionError("expected ValueError when permit secret env var is missing")


def test_wrong_env_secret_rejects_permit_and_logs_reason(tmp_path: Path, monkeypatch, caplog, base_dict):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract = _contract_with_debug_tool(base_dict)
    permit_manager = PermitManager(contract, _PERMIT_SECRET, _SESSION_ID)
    now = _now()
    request = permit_manager.create_request(
        requested_by_hex64=_HEX_A,
        permitted_tools=["debug.inspect"],
        permitted_destinations=[],
        reason="Need temporary debug access",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=now,
    )
    permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now,
        granted_ttl=300,
    )
    monkeypatch.setenv(PERMIT_SECRET_ENV, "wrong-secret")
    proxy = _build_proxy(contract, tmp_path / "events.jsonl", active_permits=[permit])

    with caplog.at_level("WARNING"):
        response = proxy.handle_tool_call(
            {"tool_name": "debug.inspect", "inputs": {}},
            lambda _request: {"ok": True},
        )

    assert response == {
        "decision": "deny",
        "reason": "not_in_contract",
        "tool_name": "debug.inspect",
    }
    assert "invalid_signature" in caplog.text


def test_budget_exhaustion_overrides_breakglass(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    breakglass = BreakGlassManager(contract).trigger(
        triggered_by_hex64=_HEX_B,
        reason="Need emergency access to all tools",
        scope="all_tools",
        specific_tools=[],
        ttl=300,
        session_id=_SESSION_ID,
        triggered_at=_now(),
    )
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, active_breakglass=breakglass)
    assert proxy.budget_tracker is not None
    proxy.budget_tracker.tool_calls_used = contract.max_tool_calls
    called = {"count": 0}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {}},
        lambda _request: called.__setitem__("count", called["count"] + 1),
    )

    assert response == {
        "decision": "deny",
        "reason": "budget_exhausted",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0
    events = _read_events(events_path)
    assert events[-1]["reason"] == "budget_exhausted"
    assert all(event["reason"] != "breakglass_active" for event in events)


def test_session_close_emits_gap_events_before_summary_and_updates_summary_fields(
    tmp_path: Path,
    contract: Contract,
):
    now = _now()
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    proxy.event_logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "filesystem.write",
            "risk_class": "write",
            "decision": "allow",
            "reason": "exception_permit_active",
            "agent_identity": "b" * 64,
            "input_hash": "c" * 64,
        }
    )
    proxy.event_logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "web.search",
            "risk_class": "read",
            "decision": "allow",
            "reason": "breakglass_active",
            "agent_identity": "b" * 64,
            "input_hash": "d" * 64,
        }
    )
    wrapper_log_path = tmp_path / "wrapper_log.jsonl"
    wrapper_log_path.write_text(
        json.dumps(
            {
                "timestamp": now.isoformat().replace("+00:00", "Z"),
                "tool_name": "totally.unknown.tool",
                "input_hash": "e" * 64,
                "token_valid": True,
                "token_error": None,
                "execution_result": "success",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    state = SessionState(
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        session_start=(now - timedelta(seconds=10)).replace(microsecond=0),
        events_path=events_path,
        decisions_path=tmp_path / "decisions.jsonl",
        summary_path=tmp_path / "summary.json",
    )

    summary = proxy.session_close(
        state,
        (now + timedelta(seconds=10)).replace(microsecond=0),
        SimpleNamespace(status="INTACT", first_failure_sequence_id=None),
    )

    events = _read_events(events_path)
    gap_indices = [idx for idx, event in enumerate(events) if event["reason"] == "gap_detected"]
    summary_index = next(idx for idx, event in enumerate(events) if event["reason"] == "session_closed")
    assert gap_indices
    assert max(gap_indices) < summary_index
    assert events[summary_index]["event_type"] == "session_close"
    assert summary.coverage_assessment == "Low"
    assert summary.coverage_percentage == 0.0
    assert summary.gaps_detected == 3
    assert summary.permit_allows == 1
    assert summary.breakglass_allows == 1
    assert summary.flagged_for_review is True
    assert all("No unmanaged credential use detected" not in att for att in summary.attestations)


def _contract_with_debug_tool(base_dict: dict) -> Contract:
    payload = dict(base_dict)
    payload["tool_risk_classes"] = dict(base_dict["tool_risk_classes"])
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    return Contract.from_dict(payload)
