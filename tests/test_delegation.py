from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.charter.delegation import (
    DEFAULT_MAX_DELEGATION_CHAIN_DEPTH,
    DelegationManager,
)
from stipul.charter.permits import PERMIT_SECRET_ENV
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.writ.proxy.server import ProxyServer

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_DELEGATION_SECRET = b"permit-secret"


def _build_proxy(
    contract: Contract,
    events_path: Path,
    *,
    requesting_agent_id: str,
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
        requesting_agent_id=requesting_agent_id,
    )


def _read_events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _create_chain(
    contract: Contract,
    *,
    actors: list[str],
    tool_name: str,
    issued_at: datetime | None = None,
    ttl: int = 300,
) -> list[dict[str, object]]:
    manager = DelegationManager(contract, _DELEGATION_SECRET, _SESSION_ID)
    grants = []
    grant_time = issued_at or _now()
    for parent_actor, delegated_actor in zip(actors, actors[1:]):
        grant = manager.create_grant(
            parent_actor=parent_actor,
            delegated_actor=delegated_actor,
            scope_tools=[tool_name],
            scope_destinations=[],
            ttl=ttl,
            session_id=_SESSION_ID,
            issued_at=grant_time,
        )
        grants.append(grant.to_dict())
    return grants


def test_valid_single_step_delegation_chain_succeeds_and_logs_metadata(
    tmp_path: Path,
    monkeypatch,
    contract: Contract,
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    events_path = tmp_path / "events.jsonl"
    delegated_actor = "delegate.worker"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=delegated_actor)
    tool_name = "filesystem.write"
    chain = _create_chain(
        contract,
        actors=[contract.identity_agent_id, delegated_actor],
        tool_name=tool_name,
    )

    response = proxy.handle_tool_call(
        {
            "tool_name": tool_name,
            "inputs": {"path": "out.txt", "content": "hello"},
            "delegation_chain": chain,
        },
        lambda _request: {"ok": True},
    )

    assert response == {"ok": True}
    events = _read_events(events_path)
    assert events[-1]["decision"] == "allow"
    metadata = events[-1]["metadata"]["delegation_context"]
    assert metadata["chain_depth"] == 1
    assert metadata["parent_actor"] == contract.identity_agent_id
    assert metadata["delegated_actor"] == delegated_actor
    assert metadata["scope_tools"] == [tool_name]


def test_valid_multi_step_delegation_chain_within_max_depth_succeeds(
    tmp_path: Path,
    monkeypatch,
    contract: Contract,
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    events_path = tmp_path / "events.jsonl"
    leaf_actor = "delegate.leaf"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=leaf_actor)
    tool_name = "filesystem.write"
    chain = _create_chain(
        contract,
        actors=[contract.identity_agent_id, "delegate.mid", leaf_actor],
        tool_name=tool_name,
    )

    response = proxy.handle_tool_call(
        {
            "tool_name": tool_name,
            "inputs": {"path": "out.txt", "content": "hello"},
            "delegation_chain": chain,
        },
        lambda _request: {"ok": True},
    )

    assert response == {"ok": True}
    events = _read_events(events_path)
    assert events[-1]["metadata"]["delegation_context"]["chain_depth"] == 2


def test_delegation_chain_exceeding_max_depth_fails_deterministically(
    tmp_path: Path,
    monkeypatch,
    contract: Contract,
) -> None:
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    events_path = tmp_path / "events.jsonl"
    leaf_actor = "delegate.depth4"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=leaf_actor)
    tool_name = "filesystem.write"
    chain = _create_chain(
        contract,
        actors=[
            contract.identity_agent_id,
            "delegate.one",
            "delegate.two",
            "delegate.three",
            leaf_actor,
        ],
        tool_name=tool_name,
    )
    called = {"count": 0}

    response = proxy.handle_tool_call(
        {
            "tool_name": tool_name,
            "inputs": {"path": "out.txt"},
            "delegation_chain": chain,
        },
        lambda _request: called.__setitem__("count", called["count"] + 1),
    )

    assert response == {
        "decision": "deny",
        "reason": "delegation_depth_exceeded",
        "tool_name": tool_name,
    }
    assert called["count"] == 0
    events = _read_events(events_path)
    assert events[-1]["reason"] == "delegation_depth_exceeded"
    assert events[-1]["metadata"]["delegation_context"]["chain_depth"] == (
        DEFAULT_MAX_DELEGATION_CHAIN_DEPTH + 1
    )


def test_expired_delegation_fails(tmp_path: Path, monkeypatch, contract: Contract) -> None:
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    events_path = tmp_path / "events.jsonl"
    delegated_actor = "delegate.expired"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=delegated_actor)
    tool_name = "filesystem.write"
    chain = _create_chain(
        contract,
        actors=[contract.identity_agent_id, delegated_actor],
        tool_name=tool_name,
        issued_at=_now() - timedelta(seconds=10),
        ttl=1,
    )

    response = proxy.handle_tool_call(
        {
            "tool_name": tool_name,
            "inputs": {"path": "out.txt"},
            "delegation_chain": chain,
        },
        lambda _request: {"ok": True},
    )

    assert response["reason"] == "delegation_expired"
    assert _read_events(events_path)[-1]["reason"] == "delegation_expired"


def test_wrong_contract_binding_fails(tmp_path: Path, monkeypatch, base_dict: dict) -> None:
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    contract = Contract.from_dict(base_dict)
    other_payload = dict(base_dict)
    other_payload["contract_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_contract = Contract.from_dict(other_payload)
    events_path = tmp_path / "events.jsonl"
    delegated_actor = "delegate.contract"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=delegated_actor)
    chain = _create_chain(
        other_contract,
        actors=[other_contract.identity_agent_id, delegated_actor],
        tool_name="filesystem.write",
    )

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"path": "out.txt"},
            "delegation_chain": chain,
        },
        lambda _request: {"ok": True},
    )

    assert response["reason"] == "delegation_contract_mismatch"
    assert _read_events(events_path)[-1]["reason"] == "delegation_contract_mismatch"


def test_invalid_delegation_signature_fails(tmp_path: Path, monkeypatch, contract: Contract) -> None:
    monkeypatch.setenv(PERMIT_SECRET_ENV, _DELEGATION_SECRET.decode("utf-8"))
    events_path = tmp_path / "events.jsonl"
    delegated_actor = "delegate.tampered"
    proxy = _build_proxy(contract, events_path, requesting_agent_id=delegated_actor)
    chain = _create_chain(
        contract,
        actors=[contract.identity_agent_id, delegated_actor],
        tool_name="filesystem.write",
    )
    chain[0]["signature"] = base64.b64encode(b"tampered").decode("ascii")

    response = proxy.handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"path": "out.txt"},
            "delegation_chain": chain,
        },
        lambda _request: {"ok": True},
    )

    assert response["reason"] == "delegation_invalid_signature"
    assert _read_events(events_path)[-1]["reason"] == "delegation_invalid_signature"
