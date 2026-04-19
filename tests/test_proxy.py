from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.charter.engine.policy import RuntimeState, evaluate
from stipul.chronicle.events.logger import EventLogger, compute_event_hash
from stipul.chronicle.events.store import EventStore
from stipul.writ.proxy.server import ProxyServer
from stipul.chronicle.signing.keys import generate_keypair
from stipul.charter.token.validate import validate_token
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


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
        **kwargs,
    )


def _tool_input_hash(inputs: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(inputs)).hexdigest()


def _assert_session_open(event: dict[str, object], contract: Contract) -> None:
    assert event["event_type"] == "session_open"
    assert event["reason"] == "session_started"
    assert event["sequence_id"] == 1
    assert event["prev_hash"] == compute_contract_hash(contract)
    assert event["tool_name"] is None
    assert event["decision"] is None
    assert event["risk_class"] is None
    assert event["tool_input"] is None
    assert event["rule_triggered"] is None
    assert event["metadata"] is None
    assert event["lifecycle_hash"] is None
    assert event["input_hash"] is None


def test_allowed_tool_call_forwards_and_logs_event(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
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
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["contract_id"] == contract.contract_id
    assert len(events[1]["contract_hash"]) == 64
    assert events[1]["decision"] == "allow"
    assert events[1]["rule_triggered"] == "risk_class"
    assert events[1]["prev_hash"] == compute_prev_hash(events[0])
    assert events[1]["event_hash"] == compute_event_hash(events[1])
    assert events[1]["tool_input"] == {"path": "out.txt", "content": "x"}
    assert isinstance(events[1]["signature"], str) and events[1]["signature"]
    attestation = proxy.event_logger.last_attestation
    assert attestation is not None
    assert attestation["kind"] == "chronicle_attestation"
    assert attestation["decision"] == "allow"
    assert attestation["tool_name"] == "filesystem.write"
    assert attestation["event_hash"] == compute_prev_hash(events[1])
    assert attestation["signature"] == events[1]["signature"]
    assert [path.name for path in tmp_path.glob("*.jsonl")] == ["events.jsonl"]


def test_allowed_tool_call_logs_authoritative_allow_before_forward_error(
    tmp_path: Path, monkeypatch, contract
):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def forward_call(_request):
        raise RuntimeError("tool execution failed")

    with pytest.raises(RuntimeError, match="tool execution failed"):
        proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            forward_call,
        )

    events = _read_events(events_path)
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "tool_call"
    assert events[1]["decision"] == "allow"
    assert events[1]["reason"] == "risk_class"
    assert events[1]["rule_triggered"] == "risk_class"
    assert events[1]["tool_name"] == "filesystem.write"


def test_denied_tool_call_returns_structured_error_and_never_forwards(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
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
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["decision"] == "deny"
    assert events[1]["reason"] == "not_in_contract"
    assert events[1]["rule_triggered"] == "not_allowed"


def test_egress_not_allowlisted_returns_structured_error_and_logs_net_call(
    tmp_path: Path, monkeypatch, contract
):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
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
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "net_call"
    assert events[1]["decision"] == "deny"
    assert events[1]["reason"] == "not_in_egress_allowlist"
    assert events[1]["tool_input"] is None


def test_scheme_prefixed_egress_target_is_normalized_and_allowed(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {
                "egress_target": "https://API.EXAMPLE.COM:443/path?q=1#frag",
                "payload": "x",
            },
        },
        forward_call,
    )

    assert response == {"ok": True}
    assert called["count"] == 1

    events = _read_events(events_path)
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "tool_call"
    assert events[1]["decision"] == "allow"
    assert events[1]["reason"] == "risk_class"


def test_exact_host_entry_denies_subdomain_end_to_end(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"egress_target": "sub.api.example.com", "payload": "x"},
        },
        lambda _request: {"ok": True},
    )

    assert response == {
        "decision": "deny",
        "reason": "not_in_egress_allowlist",
        "tool_name": "filesystem.write",
    }


def test_leading_dot_suffix_entry_allows_subdomain_end_to_end(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"egress_target": "logs.trusted.example", "payload": "x"},
        },
        forward_call,
    )

    assert response == {"ok": True}
    assert called["count"] == 1


def test_leading_dot_suffix_entry_denies_root_end_to_end(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"egress_target": "trusted.example", "payload": "x"},
        },
        lambda _request: {"ok": True},
    )

    assert response == {
        "decision": "deny",
        "reason": "not_in_egress_allowlist",
        "tool_name": "filesystem.write",
    }


def test_invalid_egress_target_denies_with_invalid_reason(
    tmp_path: Path, monkeypatch, contract
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"egress_target": "://garbage", "payload": "x"},
        },
        lambda _request: {"ok": True},
    )

    assert response == {
        "decision": "deny",
        "reason": "invalid_egress_target",
        "tool_name": "filesystem.write",
    }

    events = _read_events(events_path)
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "net_call"
    assert events[1]["decision"] == "deny"
    assert events[1]["reason"] == "invalid_egress_target"


def test_require_approval_in_headless_mode_returns_approval_required(
    tmp_path: Path, monkeypatch, base_dict
):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

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
    assert len(events) == 3
    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "elev_op"
    assert events[1]["decision"] == "allow"
    assert events[1]["reason"] == "approval_request_created"
    assert events[1]["risk_class"] == "irreversible"
    assert events[1]["metadata"]["approval_context"]["status"] == "pending"
    assert events[1]["metadata"]["approval_context"]["required_approver_count"] == 1
    assert events[2]["event_type"] == "tool_call"
    assert events[2]["decision"] == "deny"
    assert events[2]["reason"] == "approval_required"
    assert events[2]["rule_triggered"] == "risk_class"
    assert (
        events[2]["metadata"]["approval_context"]["request_id"]
        == events[1]["metadata"]["approval_context"]["request_id"]
    )


def test_handle_tool_call_propagates_rule_triggered_on_allow(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    current_time = datetime(2030, 1, 1, tzinfo=timezone.utc)

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"path": "out.txt", "content": "x"},
            "current_time": current_time.isoformat().replace("+00:00", "Z"),
        },
        lambda _request: {"ok": True},
    )

    expected = evaluate(
        contract,
        "filesystem.write",
        RuntimeState(
            tool_calls_made=0,
            net_calls_made=0,
            current_time=current_time,
            requesting_agent_id=contract.identity_agent_id,
            egress_target=None,
        ),
    )
    events = _read_events(events_path)

    assert response == {"ok": True}
    assert expected.rule_triggered == "risk_class"
    _assert_session_open(events[0], contract)
    assert events[1]["rule_triggered"] == expected.rule_triggered
    assert events[1]["reason"] == "risk_class"


def test_approval_path_splits_input_hash_and_lifecycle_hash(
    tmp_path: Path,
    monkeypatch,
    base_dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("dangerous.op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["dangerous.op"] = "irreversible"
    contract = Contract.from_dict(base_dict)

    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, interactive=False)
    inputs = {"path": "out.txt"}
    expected_input_hash = _tool_input_hash(inputs)

    response = proxy.handle_tool_call(
        {"tool_name": "dangerous.op", "inputs": inputs},
        lambda _request: {"ok": True},
    )
    events = _read_events(events_path)
    _assert_session_open(events[0], contract)
    approval_created, approval_denied = events[1:]

    assert response == {
        "decision": "deny",
        "reason": "approval_required",
        "tool_name": "dangerous.op",
    }
    assert approval_created["event_type"] == "elev_op"
    assert approval_created["input_hash"] == expected_input_hash
    assert approval_created["lifecycle_hash"] != approval_created["input_hash"]
    assert approval_created["metadata"]["approval_context"]["input_hash"] == expected_input_hash
    assert approval_denied["event_type"] == "tool_call"
    assert approval_denied["input_hash"] == expected_input_hash
    assert approval_denied["lifecycle_hash"] is None


def test_approval_path_elev_op_uses_underlying_tool_risk_class(
    tmp_path: Path,
    monkeypatch,
    base_dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("dangerous.op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["dangerous.op"] = "irreversible"
    contract = Contract.from_dict(base_dict)

    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, interactive=False)

    proxy.handle_tool_call(
        {"tool_name": "dangerous.op", "inputs": {"path": "out.txt"}},
        lambda _request: {"ok": True},
    )
    events = _read_events(events_path)

    _assert_session_open(events[0], contract)
    assert events[1]["event_type"] == "elev_op"
    assert events[1]["risk_class"] == "irreversible"


def test_persisted_event_hash_is_stable_across_jsonl_round_trip(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
        lambda _request: {"ok": True},
    )
    persisted = _read_events(events_path)[1]

    assert persisted["event_hash"] == compute_event_hash(persisted)


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
    assert len(events) == 2
    _assert_session_open(events[0], contract)
    assert events[1]["decision"] == "allow"
    assert events[1]["reason"] == "passthrough"


def test_set_kill_switch_logs_enable_and_disable_events(tmp_path: Path, contract):
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.set_kill_switch(
        True,
        updated_by="e" * 64,
        reason="operator_kill_switch_enabled",
    )
    proxy.set_kill_switch(
        False,
        updated_by="e" * 64,
        reason="operator_kill_switch_disabled",
    )

    events = _read_events(events_path)
    _assert_session_open(events[0], contract)
    assert [(event["event_type"], event["decision"], event["reason"]) for event in events[1:]] == [
        ("elev_op", "allow", "operator_kill_switch_enabled"),
        ("elev_op", "allow", "operator_kill_switch_disabled"),
    ]
    assert events[1]["tool_name"] == "__operator__"
    assert events[1]["metadata"]["kill_switch_active"] is True
    assert events[2]["metadata"]["kill_switch_active"] is False


def test_kill_switch_active_denies_before_passthrough_and_logs_event(tmp_path: Path, contract):
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path, passthrough=True)
    proxy.set_kill_switch(
        True,
        updated_by="e" * 64,
        reason="operator_kill_switch_enabled",
    )

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
        forward_call,
    )

    assert response == {
        "decision": "deny",
        "reason": "kill_switch_active",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0

    events = _read_events(events_path)
    _assert_session_open(events[0], contract)
    assert [(event["event_type"], event["decision"], event["reason"]) for event in events[1:]] == [
        ("elev_op", "allow", "operator_kill_switch_enabled"),
        ("tool_call", "deny", "kill_switch_active"),
    ]
    assert events[2]["metadata"]["kill_switch_active"] is True
    assert events[2]["metadata"]["operator_reason"] == "operator_kill_switch_enabled"


def test_events_sequence_ids_are_monotonic_without_gaps(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def forward_call(_request):
        return {"ok": True}

    proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {"n": 1}}, forward_call)
    proxy.handle_tool_call({"tool_name": "filesystem.write", "inputs": {"n": 2}}, forward_call)

    events = _read_events(events_path)
    _assert_session_open(events[0], contract)
    assert [event["sequence_id"] for event in events] == [1, 2, 3]
    assert all("prev_hash" in event and "signature" in event for event in events)


def test_policy_error_on_write_returns_proxy_degraded(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy failure")

    monkeypatch.setattr("stipul.writ.proxy.server.intercept", boom)

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
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy failure")

    monkeypatch.setattr("stipul.writ.proxy.server.intercept", boom)

    for _ in range(3):
        proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {}},
            lambda _request: {"ok": True},
        )

    events = _read_events(events_path)
    assert any(event["reason"] == "circuit_breaker_open" for event in events)
