from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.writ.proxy.server import ProxyServer

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_APPROVER_ONE = "a" * 64
_APPROVER_TWO = "b" * 64


def _approval_contract(base_dict: dict) -> Contract:
    payload = copy.deepcopy(base_dict)
    payload["allowed_tools"] = sorted({*payload["allowed_tools"], "dangerous.op"})
    payload["tool_risk_classes"]["dangerous.op"] = "irreversible"
    payload["approval_quorum"] = 2
    return Contract.from_dict(payload)


def _build_proxy(contract: Contract, events_path: Path) -> ProxyServer:
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
    )


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _approval_state_path(state_dir: Path) -> Path:
    return state_dir / "approval_state.json"


def _read_approval_state(state_dir: Path) -> dict[str, object]:
    return json.loads(_approval_state_path(state_dir).read_text(encoding="utf-8"))


def test_quorum_not_reached_denies_and_reuses_same_pending_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_dict: dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("STIPUL_PERMIT_SECRET", "permit-secret")
    contract = _approval_contract(base_dict)
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    called = {"count": 0}

    def forward_call(_request: dict[str, object]) -> dict[str, object]:
        called["count"] += 1
        return {"ok": True}

    raw_request = {"tool_name": "dangerous.op", "inputs": {"path": "out.txt"}}

    try:
        response_one = proxy.handle_tool_call(raw_request, forward_call)
        response_two = proxy.handle_tool_call(raw_request, forward_call)
    finally:
        proxy.close()

    assert response_one == {
        "decision": "deny",
        "reason": "approval_required",
        "tool_name": "dangerous.op",
    }
    assert response_two == response_one
    assert called["count"] == 0

    state = _read_approval_state(tmp_path)
    requests = state["requests"]
    assert len(requests) == 1
    request = next(iter(requests.values()))
    assert request["status"] == "pending"
    assert request["required_approver_count"] == 2
    assert request["approvals"] == []

    events = _read_events(events_path)
    assert [event["reason"] for event in events] == [
        "approval_request_created",
        "approval_required",
        "approval_required",
    ]
    assert sum(1 for event in events if event["reason"] == "approval_request_created") == 1
    request_ids = [
        event["metadata"]["approval_context"]["request_id"]
        for event in events
    ]
    assert len(set(request_ids)) == 1


def test_same_approver_does_not_count_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_dict: dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("STIPUL_PERMIT_SECRET", "permit-secret")
    contract = _approval_contract(base_dict)
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    try:
        proxy.handle_tool_call({"tool_name": "dangerous.op", "inputs": {}}, lambda _request: {"ok": True})
        request_id = next(iter(_read_approval_state(tmp_path)["requests"]))

        first = proxy.approve_approval_request(request_id, _APPROVER_ONE)
        second = proxy.approve_approval_request(request_id, _APPROVER_ONE)
    finally:
        proxy.close()

    assert first["approval_count"] == 1
    assert second["approval_count"] == 1
    assert first["status"] == "pending"
    assert second["status"] == "pending"

    state = _read_approval_state(tmp_path)
    request = state["requests"][request_id]
    assert [approval["approved_by"] for approval in request["approvals"]] == [_APPROVER_ONE]

    events = _read_events(events_path)
    assert [event["reason"] for event in events] == [
        "approval_request_created",
        "approval_required",
        "approval_added",
    ]


def test_quorum_reached_allows_execution_through_existing_override_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_dict: dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("STIPUL_PERMIT_SECRET", "permit-secret")
    contract = _approval_contract(base_dict)
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    called = {"count": 0}
    captured: dict[str, object] = {}

    def forward_call(request: dict[str, object]) -> dict[str, object]:
        called["count"] += 1
        captured["request"] = request
        return {"ok": True}

    raw_request = {"tool_name": "dangerous.op", "inputs": {"path": "out.txt"}}

    try:
        denied = proxy.handle_tool_call(raw_request, forward_call)
        request_id = next(iter(_read_approval_state(tmp_path)["requests"]))
        first = proxy.approve_approval_request(request_id, _APPROVER_ONE)
        second = proxy.approve_approval_request(request_id, _APPROVER_TWO)
        allowed = proxy.handle_tool_call(raw_request, forward_call)
    finally:
        proxy.close()

    assert denied["reason"] == "approval_required"
    assert first["status"] == "pending"
    assert second["status"] == "approved"
    assert second["approval_count"] == 2
    assert second["derived_permit_id"]
    assert allowed == {"ok": True}
    assert called["count"] == 1
    assert captured["request"]["headers"]["Authorization"].startswith("Bearer ")

    events = _read_events(events_path)
    assert [event["reason"] for event in events[-2:]] == [
        "approval_quorum_active",
        "approval_quorum_active",
    ]
    assert [event["event_type"] for event in events[-2:]] == [
        "elev_op",
        "tool_call",
    ]
    assert events[-1]["decision"] == "allow"
    assert events[-1]["metadata"]["approval_context"]["request_id"] == request_id
    assert events[-1]["metadata"]["approval_context"]["approval_count"] == 2
    assert events[-1]["metadata"]["approval_context"]["approver_ids"] == [
        _APPROVER_ONE,
        _APPROVER_TWO,
    ]
    assert events[-1]["metadata"]["approval_context"]["derived_permit_id"] == second["derived_permit_id"]


def test_expired_request_cannot_be_approved_and_is_recreated_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_dict: dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("STIPUL_PERMIT_SECRET", "permit-secret")
    contract = _approval_contract(base_dict)
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    called = {"count": 0}

    def forward_call(_request: dict[str, object]) -> dict[str, object]:
        called["count"] += 1
        return {"ok": True}

    raw_request = {"tool_name": "dangerous.op", "inputs": {"path": "out.txt"}}

    try:
        first = proxy.handle_tool_call(raw_request, forward_call)
        state = _read_approval_state(tmp_path)
        request_id = next(iter(state["requests"]))
        state["requests"][request_id]["expires_at"] = "2020-01-01T00:00:00Z"
        _approval_state_path(tmp_path).write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="approval request expired"):
            proxy.approve_approval_request(request_id, _APPROVER_ONE)

        second = proxy.handle_tool_call(raw_request, forward_call)
    finally:
        proxy.close()

    assert first["reason"] == "approval_required"
    assert second == {
        "decision": "deny",
        "reason": "approval_required",
        "tool_name": "dangerous.op",
    }
    assert called["count"] == 0

    state_after = _read_approval_state(tmp_path)
    assert list(state_after["requests"]) == [request_id]
    assert state_after["requests"][request_id]["status"] == "pending"

    events = _read_events(events_path)
    assert [event["reason"] for event in events] == [
        "approval_request_created",
        "approval_required",
        "approval_request_expired",
        "approval_request_created",
        "approval_required",
    ]
    expired_event = events[2]
    assert expired_event["event_type"] == "elev_op"
    assert expired_event["metadata"]["approval_context"]["status"] == "expired"
