from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash
import stipul.writ.proxy.server as proxy_server_module
from stipul.writ.proxy.server import ProxyServer
from stipul.writ.proxy.session import SessionState

SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _read_events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _build_proxy(contract: Contract, events_path: Path) -> ProxyServer:
    keypair = generate_keypair(events_path.parent / ".stipul" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=events_path.parent,
    )
    return ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=SESSION_ID,
        state_dir=events_path.parent,
    )


def _tool_input_hash(arguments: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(arguments)).hexdigest()


def _new_session_state(contract: Contract, events_path: Path) -> SessionState:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return SessionState(
        session_id=SESSION_ID,
        contract_id=contract.contract_id,
        session_start=start,
        events_path=events_path,
        decisions_path=events_path.parent / "decisions.jsonl",
        summary_path=events_path.parent / "summary.json",
    )


def _assert_lifecycle_nulls(event: dict[str, object], *, metadata_is_null: bool) -> None:
    assert event["tool_name"] is None
    assert event["decision"] is None
    assert event["tool_input"] is None
    assert event["rule_triggered"] is None
    assert event["lifecycle_hash"] is None
    assert event["risk_class"] is None
    assert event["input_hash"] is None
    if metadata_is_null:
        assert event["metadata"] is None
    else:
        assert event["metadata"] is not None


def test_tool_input_persisted_on_allow_path(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    arguments = {"path": "/tmp/test", "content": "hello"}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": arguments},
        lambda _request: {"ok": True},
    )

    events = _read_events(events_path)
    tool_call = events[1]

    assert response == {"ok": True}
    assert tool_call["event_type"] == "tool_call"
    assert tool_call["tool_input"] == arguments
    assert tool_call["input_hash"] == _tool_input_hash(arguments)


def test_tool_input_is_null_on_elev_op_and_present_on_denied_tool_call(
    tmp_path: Path,
    monkeypatch,
    base_dict,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    payload = json.loads(json.dumps(base_dict))
    payload["allowed_tools"] = sorted({*payload["allowed_tools"], "dangerous.op"})
    payload["tool_risk_classes"]["dangerous.op"] = "irreversible"
    contract = Contract.from_dict(payload)
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    arguments = {"path": "/tmp/test"}

    response = proxy.handle_tool_call(
        {"tool_name": "dangerous.op", "inputs": arguments},
        lambda _request: {"ok": True},
    )

    events = _read_events(events_path)
    elev_op = events[1]
    denied_tool_call = events[2]

    assert response == {
        "decision": "deny",
        "reason": "approval_required",
        "tool_name": "dangerous.op",
    }
    assert elev_op["event_type"] == "elev_op"
    assert elev_op["tool_input"] is None
    assert denied_tool_call["event_type"] == "tool_call"
    assert denied_tool_call["decision"] == "deny"
    assert denied_tool_call["tool_input"] == arguments


def test_session_open_is_first_event_and_runtime_chains_from_it(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    proxy.close()

    events = _read_events(events_path)
    session_open = events[0]
    first_runtime = events[1]

    assert session_open["event_type"] == "session_open"
    assert session_open["reason"] == "session_started"
    assert session_open["sequence_id"] == 1
    assert session_open["prev_hash"] == compute_contract_hash(contract)
    _assert_lifecycle_nulls(session_open, metadata_is_null=True)
    assert first_runtime["prev_hash"] == compute_prev_hash(session_open)


def test_session_close_is_last_event(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    proxy.close()

    events = _read_events(events_path)
    session_close = events[-1]

    assert session_close["event_type"] == "session_close"
    assert session_close["reason"] == "session_closed"
    _assert_lifecycle_nulls(session_close, metadata_is_null=False)
    metadata = session_close["metadata"]
    assert isinstance(metadata, dict)
    assert {"session_id", "total_calls", "chain_length", "tools_invoked"} <= set(metadata)


def test_empty_session_still_emits_lifecycle_boundary(tmp_path: Path, contract) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    proxy.close()

    events = _read_events(events_path)
    assert [event["event_type"] for event in events] == ["session_open", "session_close"]



def test_session_local_trust_inputs_exist_before_close_and_remain_stable(
    tmp_path: Path,
    contract,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    session_dir = events_path.parent
    contract_path = session_dir / "contract.json"
    public_key_path = session_dir / "public_key.pem"
    expected_public_key = proxy.event_logger.signing_key.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert contract_path.exists()
    assert public_key_path.exists()
    assert json.loads(contract_path.read_text(encoding="utf-8")) == contract.to_canonical_dict()
    assert public_key_path.read_bytes() == expected_public_key

    contract_bytes = contract_path.read_bytes()
    public_key_bytes = public_key_path.read_bytes()
    contract_mtime_ns = contract_path.stat().st_mtime_ns
    public_key_mtime_ns = public_key_path.stat().st_mtime_ns

    proxy.close()
    proxy.close()

    assert contract_path.read_bytes() == contract_bytes
    assert public_key_path.read_bytes() == public_key_bytes
    assert contract_path.stat().st_mtime_ns == contract_mtime_ns
    assert public_key_path.stat().st_mtime_ns == public_key_mtime_ns


def test_chain_integrity_with_lifecycle_events(tmp_path: Path, monkeypatch, contract) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    denied = proxy.handle_tool_call(
        {"tool_name": "totally.unknown.tool", "inputs": {"path": "/tmp/test"}},
        lambda _request: {"ok": True},
    )
    proxy.close()

    assert denied == {
        "decision": "deny",
        "reason": "not_in_contract",
        "tool_name": "totally.unknown.tool",
    }


def test_close_is_idempotent_and_does_not_duplicate_session_close(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    proxy.close()
    first_close_bytes = events_path.read_bytes()

    proxy.close()

    events = _read_events(events_path)
    assert events_path.read_bytes() == first_close_bytes
    assert [event["event_type"] for event in events].count("session_close") == 1
    assert events[-1]["event_type"] == "session_close"


def test_close_seals_from_terminal_session_close_event(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    proxy.close()

    events = _read_events(events_path)
    terminal_event = events[-1]
    seal = json.loads((events_path.parent / "seal.json").read_text(encoding="utf-8"))

    assert terminal_event["event_type"] == "session_close"
    assert seal["terminal_sequence_id"] == terminal_event["sequence_id"]
    assert seal["terminal_timestamp"] == terminal_event["timestamp"]
    assert seal["terminal_event_hash"] == compute_prev_hash(terminal_event)


def test_close_logs_seal_omitted_when_terminal_attestation_is_missing(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    monkeypatch.setattr(proxy, "_terminal_attestation", lambda: None)

    proxy.close()

    events = _read_events(events_path)
    seal_omitted = events[-1]

    assert [event["event_type"] for event in events] == [
        "session_open",
        "session_close",
        "seal_omitted",
    ]
    assert seal_omitted["reason"] == "terminal_attestation_missing"
    _assert_lifecycle_nulls(seal_omitted, metadata_is_null=False)
    assert seal_omitted["metadata"] == {
        "seal_generation_skipped": True,
        "omission_reason": "terminal_attestation_missing",
    }
    assert not (events_path.parent / "seal.json").exists()


def test_close_with_valid_attestation_does_not_record_seal_omitted(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test", "content": "hello"}},
        lambda _request: {"ok": True},
    )
    proxy.close()

    events = _read_events(events_path)

    assert all(event["event_type"] != "seal_omitted" for event in events)
    assert (events_path.parent / "seal.json").exists()


def test_close_preserves_attestation_missing_outcome_when_seal_omission_log_fails(
    tmp_path: Path,
    monkeypatch,
    contract,
    caplog,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    monkeypatch.setattr(proxy, "_terminal_attestation", lambda: None)

    original_log_event = proxy.event_logger.log_event

    def fail_on_seal_omitted(event_kwargs: dict[str, object]):
        if event_kwargs.get("event_type") == "seal_omitted":
            raise RuntimeError("chronicle unavailable")
        return original_log_event(event_kwargs)

    monkeypatch.setattr(proxy.event_logger, "log_event", fail_on_seal_omitted)

    with caplog.at_level(logging.WARNING):
        assert proxy.close() is None

    events = _read_events(events_path)

    assert [event["event_type"] for event in events] == ["session_open", "session_close"]
    assert "Failed to record seal omission event in Chronicle" in caplog.text
    assert not (events_path.parent / "seal.json").exists()


def test_close_records_seal_build_failure_in_chronicle(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def fail_build(*_args, **_kwargs):
        raise ValueError("bad attestation")

    monkeypatch.setattr(proxy_server_module, "build_session_seal", fail_build)

    with pytest.raises(ValueError, match="bad attestation"):
        proxy.close()

    events = _read_events(events_path)
    session_close = next(event for event in events if event["event_type"] == "session_close")
    seal_omitted = events[-1]

    assert session_close["reason"] == "session_closed"
    assert seal_omitted["event_type"] == "seal_omitted"
    assert seal_omitted["reason"] == "seal_generation_failed"
    assert seal_omitted["metadata"] == {
        "stage": "build",
        "error_type": "ValueError",
        "error": "bad attestation",
    }
    assert not (events_path.parent / "seal.json").exists()


def test_close_logs_warning_when_seal_failure_chronicle_write_fails(
    tmp_path: Path,
    monkeypatch,
    contract,
    caplog,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    def fail_build(*_args, **_kwargs):
        raise ValueError("bad attestation")

    original_append = proxy.event_logger.store.append

    def fail_on_seal_omitted(line: str) -> None:
        if json.loads(line).get("event_type") == "seal_omitted":
            raise RuntimeError("chronicle unavailable")
        original_append(line)

    monkeypatch.setattr(proxy_server_module, "build_session_seal", fail_build)
    monkeypatch.setattr(proxy.event_logger.store, "append", fail_on_seal_omitted)

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError, match="bad attestation"):
            proxy.close()

    events = _read_events(events_path)

    assert [event["event_type"] for event in events] == ["session_open", "session_close"]
    assert "Failed to record seal omission event in Chronicle" in caplog.text
    assert not (events_path.parent / "seal.json").exists()


def test_same_session_rehydration_keeps_single_session_open_and_single_session_close(
    tmp_path: Path,
    monkeypatch,
    contract,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    first_proxy = _build_proxy(contract, events_path)
    first_proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test-a", "content": "a"}},
        lambda _request: {"ok": True},
    )

    rehydrated_logger = EventLogger(
        store=EventStore(events_path),
        session_id=SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=first_proxy.event_logger.signing_key,
        state_dir=events_path.parent,
    )
    rehydrated_proxy = ProxyServer(
        contract=contract,
        event_logger=rehydrated_logger,
        session_id=SESSION_ID,
        state_dir=events_path.parent,
    )
    rehydrated_proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "/tmp/test-b", "content": "b"}},
        lambda _request: {"ok": True},
    )

    rehydrated_proxy.close()
    first_proxy.close()

    events = _read_events(events_path)
    event_types = [event["event_type"] for event in events]
    assert event_types.count("session_open") == 1
    assert event_types.count("session_close") == 1
    assert events[-1]["event_type"] == "session_close"
