from __future__ import annotations

import json
from pathlib import Path

from agentshield.contract.schema import Contract
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.logger import EventLogger
from agentshield.events.store import EventStore
from agentshield.proxy.server import ProxyServer
from agentshield.signing.keys import generate_keypair
from agentshield.token.validate import validate_token

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _build_proxy(contract: Contract, events_path: Path, **kwargs) -> ProxyServer:
    keypair = generate_keypair(events_path.parent / ".agentshield" / "keys")
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
        **kwargs,
    )


def test_allowed_tool_call_forwards_and_logs_event(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    captured: dict[str, object] = {}

    def forward_call(request):
        captured["request"] = request
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
        forward_call,
    )

    assert response == {"ok": True}
    auth = captured["request"]["headers"]["Authorization"]
    assert auth.startswith("Bearer ")
    token = auth.split(" ", 1)[1]
    assert validate_token(token, "filesystem.write") == (True, "valid")

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["contract_id"] == contract.contract_id
    assert len(events[0]["contract_hash"]) == 64
    assert events[0]["decision"] == "allow"
    assert events[0]["prev_hash"] == compute_contract_hash(contract)
    assert isinstance(events[0]["signature"], str) and events[0]["signature"]


def test_denied_tool_call_returns_structured_error_and_never_forwards(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "totally.unknown.tool", "inputs": {"x": 1}},
        forward_call,
    )

    assert response == {
        "decision": "deny",
        "reason": "not_in_contract",
        "tool_name": "totally.unknown.tool",
    }
    assert called["count"] == 0

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "not_in_contract"


def test_egress_not_allowlisted_returns_structured_error_and_logs_net_call(
    tmp_path: Path, monkeypatch, contract
):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"egress_target": "evil.example.org", "payload": "x"},
        },
        forward_call,
    )

    assert response == {
        "decision": "deny",
        "reason": "not_in_egress_allowlist",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["event_type"] == "net_call"
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "not_in_egress_allowlist"


def test_require_approval_in_headless_mode_returns_approval_required(
    tmp_path: Path, monkeypatch, base_dict
):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("dangerous.op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["dangerous.op"] = "irreversible"
    contract = Contract.from_dict(base_dict)

    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, interactive=False)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call({"tool_name": "dangerous.op", "inputs": {}}, forward_call)

    assert response == {
        "decision": "deny",
        "reason": "approval_required",
        "tool_name": "dangerous.op",
    }
    assert called["count"] == 0

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "approval_required"


def test_passthrough_mode_forwards_without_minting_token(tmp_path: Path, contract):
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, passthrough=True)

    captured: dict[str, object] = {}

    def forward_call(request):
        captured["request"] = request
        return {"ok": True}

    response = proxy.handle_tool_call({"tool_name": "totally.unknown", "inputs": {}}, forward_call)

    assert response == {"ok": True}
    assert "headers" not in captured["request"] or "Authorization" not in captured["request"].get(
        "headers", {}
    )

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["decision"] == "allow"
    assert events[0]["reason"] == "passthrough"


def test_events_sequence_ids_are_monotonic_without_gaps(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def forward_call(_request):
        return {"ok": True}

    proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {"n": 1}}, forward_call)
    proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {"n": 2}}, forward_call)

    events = _read_events(events_path)
    assert [event["sequence_id"] for event in events] == [1, 2]
    assert all("prev_hash" in event and "signature" in event for event in events)


def test_policy_error_on_write_returns_proxy_degraded(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy failure")

    monkeypatch.setattr("agentshield.proxy.server.intercept", boom)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {}}, forward_call)

    assert response == {
        "decision": "deny",
        "reason": "proxy_degraded",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0


def test_three_policy_failures_emit_circuit_breaker_open_event(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy failure")

    monkeypatch.setattr("agentshield.proxy.server.intercept", boom)

    for _ in range(3):
        proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {}},
            lambda _request: {"ok": True},
        )

    events = _read_events(events_path)
    assert any(event["reason"] == "circuit_breaker_open" for event in events)
