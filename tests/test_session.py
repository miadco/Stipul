from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.contract.utils import compute_contract_hash
from agentshield.events.logger import EventLogger, EventWriteError
from agentshield.events.store import EventStore
from agentshield.proxy.server import ProxyServer
from agentshield.proxy.session_lock import (
    SessionLockError,
    acquire_session_lock,
    release_session_lock,
)
from agentshield.signing.keys import generate_keypair
from agentshield.utils.canonical import compute_prev_hash

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_OTHER_SESSION_ID = "99999999-9999-9999-9999-999999999999"


def _event_kwargs(reason: str = "risk_class") -> dict:
    return {
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": reason,
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
    }


def _build_logger(tmp_path: Path, contract, session_id: str = _SESSION_ID) -> EventLogger:
    keypair = generate_keypair(tmp_path / ".agentshield" / "keys")
    return EventLogger(
        store=EventStore(tmp_path / "events.jsonl"),
        session_id=session_id,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=tmp_path,
    )


def _write_contract(path: Path, base_dict: dict) -> None:
    path.write_text(json.dumps(base_dict), encoding="utf-8")


def _read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_session_id_identical_across_events_written(tmp_path: Path, contract) -> None:
    logger = _build_logger(tmp_path, contract)
    logger.log_event(_event_kwargs("first"))
    logger.log_event(_event_kwargs("second"))

    events = _read_events(tmp_path / "events.jsonl")
    assert {event["session_id"] for event in events} == {_SESSION_ID}


def test_writing_to_file_with_different_session_id_raises_fatal_error(
    tmp_path: Path, contract
) -> None:
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(json.dumps({"session_id": _OTHER_SESSION_ID}) + "\n", encoding="utf-8")
    logger = _build_logger(tmp_path, contract, session_id=_SESSION_ID)

    with pytest.raises(EventWriteError, match="session_id mismatch"):
        logger.log_event(_event_kwargs())


def test_session_open_renames_prior_session_file(tmp_path: Path, base_dict, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, base_dict)

    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        json.dumps({"session_id": _OTHER_SESSION_ID, "sequence_id": 1, "signature": None}) + "\n",
        encoding="utf-8",
    )

    proxy = ProxyServer.from_contract_path(
        contract_path=contract_path,
        session_id=_SESSION_ID,
        events_path=events_path,
    )
    proxy.close()

    assert (tmp_path / f"events_{_OTHER_SESSION_ID}.jsonl").exists()
    if events_path.exists():
        assert _read_events(events_path) == []


def test_session_lock_conflict_raises_error(tmp_path: Path) -> None:
    first = acquire_session_lock(tmp_path)
    try:
        with pytest.raises(SessionLockError, match="Another proxy instance is running"):
            acquire_session_lock(tmp_path)
    finally:
        release_session_lock(first)


def test_session_lock_released_on_close(tmp_path: Path) -> None:
    lock = acquire_session_lock(tmp_path)
    release_session_lock(lock)
    second = acquire_session_lock(tmp_path)
    release_session_lock(second)


def test_proxy_second_instance_same_state_dir_rejected(
    tmp_path: Path, base_dict, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, base_dict)
    events_path = tmp_path / "events.jsonl"

    proxy = ProxyServer.from_contract_path(
        contract_path=contract_path,
        session_id=_SESSION_ID,
        events_path=events_path,
    )
    try:
        with pytest.raises(SessionLockError, match="Another proxy instance is running"):
            ProxyServer.from_contract_path(
                contract_path=contract_path,
                session_id=_SESSION_ID,
                events_path=events_path,
            )
    finally:
        proxy.close()


def test_prev_unsigned_terminal_hash_present_on_genesis_when_unsigned_exists(
    tmp_path: Path, contract
) -> None:
    unsigned_event = {
        "sequence_id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "session_id": _SESSION_ID,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "legacy_unsigned",
        "contract_id": contract.contract_id,
        "contract_hash": compute_contract_hash(contract),
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "prev_hash": None,
        "signature": None,
    }
    (tmp_path / "events.jsonl").write_text(json.dumps(unsigned_event) + "\n", encoding="utf-8")

    logger = _build_logger(tmp_path, contract, session_id=_SESSION_ID)
    logger.log_event(_event_kwargs("signed"))

    events = _read_events(tmp_path / "events.jsonl")
    genesis = events[-1]
    expected_unsigned_hash = compute_prev_hash(unsigned_event)
    assert genesis["prev_hash"] == compute_contract_hash(contract)
    assert genesis["prev_unsigned_terminal_hash"] == expected_unsigned_hash


def test_prev_unsigned_terminal_hash_absent_on_fresh_start(tmp_path: Path, contract) -> None:
    logger = _build_logger(tmp_path, contract, session_id=_SESSION_ID)
    logger.log_event(_event_kwargs())
    events = _read_events(tmp_path / "events.jsonl")
    assert "prev_unsigned_terminal_hash" not in events[0]


def test_prev_unsigned_terminal_hash_absent_when_unsigned_was_in_renamed_file(
    tmp_path: Path, base_dict, monkeypatch
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, base_dict)

    events_path = tmp_path / "events.jsonl"
    unsigned_prior = {
        "sequence_id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "session_id": _OTHER_SESSION_ID,
        "signature": None,
    }
    events_path.write_text(json.dumps(unsigned_prior) + "\n", encoding="utf-8")

    proxy = ProxyServer.from_contract_path(
        contract_path=contract_path,
        session_id=_SESSION_ID,
        events_path=events_path,
    )
    try:
        proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda request: {"ok": True, "request": request},
        )
    finally:
        proxy.close()

    current_events = _read_events(events_path)
    assert len(current_events) == 1
    assert "prev_unsigned_terminal_hash" not in current_events[0]
    assert (tmp_path / f"events_{_OTHER_SESSION_ID}.jsonl").exists()


def test_genesis_includes_prev_chain_fields_when_prior_signed_session_is_renamed(
    tmp_path: Path, base_dict, monkeypatch
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, base_dict)

    previous_signed = {
        "sequence_id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "session_id": _OTHER_SESSION_ID,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "risk_class",
        "contract_id": base_dict["contract_id"],
        "contract_hash": "a" * 64,
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": "d" * 64,
        "signature": "ZmFrZQ==",
    }

    events_path = tmp_path / "events.jsonl"
    events_path.write_text(json.dumps(previous_signed) + "\n", encoding="utf-8")
    expected_terminal_hash = compute_prev_hash(previous_signed)

    proxy = ProxyServer.from_contract_path(
        contract_path=contract_path,
        session_id=_SESSION_ID,
        events_path=events_path,
    )
    try:
        proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda request: {"ok": True, "request": request},
        )
    finally:
        proxy.close()

    current_events = _read_events(events_path)
    assert len(current_events) == 1
    genesis = current_events[0]
    assert genesis["prev_session_id"] == _OTHER_SESSION_ID
    assert genesis["prev_chain_terminal_hash"] == expected_terminal_hash
