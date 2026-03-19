from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path

from stipul.writ.breakglass import BreakGlassManager
from stipul.charter.contract.inheritance import ContractLayer, InheritanceResolver
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.writ.detection.bypass import BypassDetector
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.charter.permits import PERMIT_SECRET_ENV, PermitManager
from stipul.writ.proxy.server import ProxyServer
from stipul.chronicle.signing.keys import generate_keypair
from stipul.simulation.simulator import PolicySimulator
from stipul.charter.token.mint import mint_token
from stipul.writ.wrapper.mcp_wrapper import handle_tool_call

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_PERMIT_SECRET = b"permit-secret"
_HEX_A = "a" * 64
_HEX_B = "b" * 64


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


def _contract_with_debug_tool(base_dict: dict) -> Contract:
    payload = dict(base_dict)
    payload["tool_risk_classes"] = dict(base_dict["tool_risk_classes"])
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    return Contract.from_dict(payload)


def test_permit_lifecycle(base_dict, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv(PERMIT_SECRET_ENV, _PERMIT_SECRET.decode("utf-8"))
    contract = _contract_with_debug_tool(base_dict)
    now = _now()

    deny_proxy = _build_proxy(contract, tmp_path / "deny_events.jsonl")
    denied = deny_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert denied["reason"] == "not_in_contract"

    permit_manager = PermitManager(contract, _PERMIT_SECRET, _SESSION_ID)
    request = permit_manager.create_request(
        requested_by_hex64=_HEX_A,
        permitted_tools=["debug.inspect"],
        permitted_destinations=[],
        reason="Need temporary debug access",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=now,
    )
    active_permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now,
        granted_ttl=300,
    )
    allow_proxy = _build_proxy(
        contract,
        tmp_path / "allow_events.jsonl",
        active_permits=[active_permit],
    )
    allowed = allow_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert allowed == {"ok": True}

    expired_permit = permit_manager.approve_request(
        request,
        approved_by_hex64=_HEX_B,
        approved_at=now - timedelta(seconds=10),
        granted_ttl=1,
    )
    expired_proxy = _build_proxy(
        contract,
        tmp_path / "expired_events.jsonl",
        active_permits=[expired_permit],
    )
    expired = expired_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert expired["reason"] == "not_in_contract"


def test_breakglass_lifecycle(base_dict, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract = _contract_with_debug_tool(base_dict)
    now = _now()

    deny_proxy = _build_proxy(contract, tmp_path / "bg_deny_events.jsonl")
    denied = deny_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert denied["reason"] == "not_in_contract"

    breakglass_manager = BreakGlassManager(contract)
    active_breakglass = breakglass_manager.trigger(
        triggered_by_hex64=_HEX_B,
        reason="Need emergency access to debug tooling",
        scope="specific_tools",
        specific_tools=["debug.inspect"],
        ttl=300,
        session_id=_SESSION_ID,
        triggered_at=now,
    )
    allow_proxy = _build_proxy(
        contract,
        tmp_path / "bg_allow_events.jsonl",
        active_breakglass=active_breakglass,
    )
    allowed = allow_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert allowed == {"ok": True}

    expired_breakglass = breakglass_manager.trigger(
        triggered_by_hex64=_HEX_B,
        reason="Need emergency access to debug tooling",
        scope="specific_tools",
        specific_tools=["debug.inspect"],
        ttl=1,
        session_id=_SESSION_ID,
        triggered_at=now - timedelta(seconds=10),
    )
    expired_proxy = _build_proxy(
        contract,
        tmp_path / "bg_expired_events.jsonl",
        active_breakglass=expired_breakglass,
    )
    expired = expired_proxy.handle_tool_call(
        {"tool_name": "debug.inspect", "inputs": {}},
        lambda _request: {"ok": True},
    )
    assert expired["reason"] == "not_in_contract"


def test_inheritance_across_three_layers(base_dict):
    resolver = InheritanceResolver()
    org_payload = {
        **base_dict,
        "contract_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "allowed_tools": ["web.search"],
        "never_allow_tools": ["shell.exec", "dangerous.api"],
        "egress_allowlist": ["api.example.com"],
        "max_tool_calls": 8,
        "max_net_calls": 4,
        "expires_at": "2080-01-01T00:00:00Z",
        "tool_risk_classes": {"web.search": "write"},
    }
    agent_payload = {
        **org_payload,
        "contract_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "never_allow_tools": ["shell.exec", "dangerous.api", "filesystem.write"],
        "max_tool_calls": 6,
        "max_net_calls": 2,
        "expires_at": "2070-01-01T00:00:00Z",
        "tool_risk_classes": {"web.search": "irreversible"},
    }

    resolved = resolver.resolve(
        [
            ContractLayer(level="base", contract=Contract.from_dict(base_dict), source="base"),
            ContractLayer(level="org", contract=Contract.from_dict(org_payload), source="org"),
            ContractLayer(level="agent", contract=Contract.from_dict(agent_payload), source="agent"),
        ]
    )

    assert resolved.effective.allowed_tools == frozenset({"web.search"})
    assert resolved.effective.never_allow_tools == frozenset(
        {"shell.exec", "dangerous.api", "filesystem.write"}
    )
    assert resolved.effective.max_tool_calls == 6
    assert resolved.effective.max_net_calls == 2
    assert resolved.effective.tool_risk_classes["web.search"].value == "irreversible"


def test_bypass_detector_with_real_wrapper_log(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    wrapper_log_path = tmp_path / "wrapper_log.jsonl"
    monkeypatch.setenv("STIPUL_WRAPPER_LOG_PATH", str(wrapper_log_path))
    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id=_SESSION_ID,
        contract_id="2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f",
    )

    handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"path": "out.txt"},
            "headers": {"Authorization": f"Bearer {token}"},
        },
        lambda _request: {"ok": True},
    )

    proxy_events_path = tmp_path / "events.jsonl"
    proxy_events_path.write_text("", encoding="utf-8")

    detector = BypassDetector(proxy_events_path, wrapper_log_path)
    report = detector.detect(_now() - timedelta(seconds=10), _now() + timedelta(seconds=10))

    assert report.coverage_percentage == 0.0
    assert report.gaps[0].source == "wrapper_only"
    assert BypassDetector.emit_gap_events(report.gaps)[0]["reason"] == "gap_detected"


def test_simulator_detects_changes_and_diff_mode(contract, base_dict, make_test_events):
    simulator = PolicySimulator()
    modified_payload = dict(base_dict)
    modified_payload["tool_risk_classes"] = dict(base_dict["tool_risk_classes"])
    modified_payload["tool_risk_classes"]["filesystem.write"] = "irreversible"
    modified_contract = Contract.from_dict(modified_payload)
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    summary = simulator.simulate(events_path, modified_contract)
    diff = simulator.diff(events_path, contract, modified_contract)

    assert summary.changed_count == 1
    assert diff.changed_count == 1
    assert diff.records[0].tool_name == "filesystem.write"
