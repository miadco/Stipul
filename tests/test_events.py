from __future__ import annotations

import json
from pathlib import Path

import pytest

from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger, EventWriteError
from stipul.chronicle.events.models import CanonicalEvent
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.utils.canonical import compute_prev_hash

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


class BrokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, _line: str) -> None:
        raise OSError("disk full")


def _direct_event_kwargs(contract) -> dict:
    return {
        "session_id": _SESSION_ID,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "risk_class",
        "contract_id": contract.contract_id,
        "contract_hash": "a" * 64,
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": "d" * 64,
        "signature": "c2lnbg==",
    }


def _logger_event_kwargs() -> dict:
    return {
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "risk_class",
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
    }


def _build_logger(tmp_path: Path, contract) -> EventLogger:
    keys_dir = tmp_path / ".stipul" / "keys"
    keypair = generate_keypair(keys_dir)
    return EventLogger(
        store=EventStore(tmp_path / "events.jsonl"),
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=tmp_path,
    )


def test_canonical_event_validates_enums(contract):
    kwargs = _direct_event_kwargs(contract)
    kwargs["event_type"] = "bad_type"

    with pytest.raises(ValueError):
        CanonicalEvent(sequence_id=1, timestamp="2026-01-01T00:00:00Z", **kwargs)


def test_canonical_event_to_dict_keeps_signing_fields(contract):
    event = CanonicalEvent(
        sequence_id=1,
        timestamp="2026-01-01T00:00:00Z",
        **_direct_event_kwargs(contract),
    )

    payload = event.to_dict()
    assert payload["prev_hash"] == "d" * 64
    assert payload["signature"] == "c2lnbg=="
    assert payload["algorithm"] == "ed25519"
    assert payload["key_id"] == "deadbeef"


def test_logger_writes_monotonic_sequence_ids(tmp_path: Path, contract):
    logger = _build_logger(tmp_path, contract)

    logger.log_event(_logger_event_kwargs())
    logger.log_event(_logger_event_kwargs())

    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]

    assert [e["sequence_id"] for e in events] == [1, 2]
    assert events[0]["prev_hash"] == compute_contract_hash(contract)
    assert isinstance(events[0]["signature"], str) and events[0]["signature"]
    assert events[0]["session_id"] == _SESSION_ID


def test_logger_log_decision_event_writes_authoritative_decision_record(tmp_path: Path, contract):
    logger = _build_logger(tmp_path, contract)

    event = logger.log_decision_event(
        event_type="tool_call",
        tool_name="filesystem.write",
        risk_class="write",
        decision="deny",
        reason="not_in_contract",
        agent_identity="b" * 64,
        input_hash="c" * 64,
        metadata={"path": "out.txt"},
    )

    assert event.decision == "deny"
    assert event.reason == "not_in_contract"
    persisted = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert persisted["decision"] == "deny"
    assert persisted["metadata"] == {"path": "out.txt"}


def test_logger_exposes_last_attestation_for_written_event(tmp_path: Path, contract):
    logger = _build_logger(tmp_path, contract)

    event = logger.log_decision_event(
        event_type="tool_call",
        tool_name="filesystem.write",
        risk_class="write",
        decision="allow",
        reason="risk_class",
        agent_identity="b" * 64,
        input_hash="c" * 64,
    )

    attestation = logger.last_attestation
    assert attestation is not None
    persisted = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert attestation["kind"] == "chronicle_attestation"
    assert attestation["event_hash"] == compute_prev_hash(persisted)
    assert attestation["sequence_id"] == event.sequence_id
    assert attestation["session_id"] == event.session_id
    assert attestation["tool_name"] == event.tool_name
    assert attestation["decision"] == event.decision
    assert attestation["signature"] == persisted["signature"] == event.signature


def test_logger_log_decision_event_supports_operator_toggle_event(tmp_path: Path, contract):
    logger = _build_logger(tmp_path, contract)

    event = logger.log_decision_event(
        event_type="elev_op",
        tool_name="__operator__",
        risk_class="write",
        decision="allow",
        reason="operator_kill_switch_enabled",
        agent_identity="e" * 64,
        input_hash="f" * 64,
        metadata={
            "kill_switch_active": True,
            "updated_at": "2026-03-07T17:00:00Z",
            "updated_by": "e" * 64,
            "reason": "operator_kill_switch_enabled",
        },
    )

    assert event.event_type == "elev_op"
    assert event.decision == "allow"
    persisted = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert persisted["event_type"] == "elev_op"
    assert persisted["tool_name"] == "__operator__"
    assert persisted["metadata"]["kill_switch_active"] is True


def test_logger_rejects_sequence_gaps(tmp_path: Path, contract):
    logger = _build_logger(tmp_path, contract)

    with pytest.raises(ValueError):
        logger.log_event({**_logger_event_kwargs(), "sequence_id": 3})


def test_logger_raises_event_write_error_on_append_failure(tmp_path: Path, contract):
    keypair = generate_keypair(tmp_path / "keys")
    logger = EventLogger(
        store=BrokenStore(tmp_path / "events.jsonl"),  # type: ignore[arg-type]
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=tmp_path,
    )

    with pytest.raises(EventWriteError):
        logger.log_event(_logger_event_kwargs())
