from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.chronicle.signing.signer import sign_event
from stipul.chronicle.signing.verifier import verify_chain
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash
from stipul.writ.proxy.server import ProxyServer

SESSION_ID = "11111111-1111-1111-1111-111111111111"
OTHER_SESSION_ID = "99999999-9999-9999-9999-999999999999"


def _iso(offset_minutes: int) -> str:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (base + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def _write_jsonl(path: Path, entries: list[dict[str, Any] | str]) -> None:
    lines: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            lines.append(entry)
        else:
            lines.append(canonical_json_bytes(entry).decode("utf-8"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_signed_event(
    *,
    private_key,
    contract,
    sequence_id: int,
    prev_hash: str,
    timestamp: str,
    session_id: str = SESSION_ID,
    contract_hash: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "sequence_id": sequence_id,
        "timestamp": timestamp,
        "session_id": session_id,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "risk_class",
        "contract_id": contract.contract_id,
        "contract_hash": contract_hash or compute_contract_hash(contract),
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": prev_hash,
    }
    if extras:
        payload.update(extras)
    payload["signature"] = sign_event(payload, private_key)
    return payload


def _build_valid_chain(private_key, contract, count: int = 3) -> list[dict[str, Any]]:
    contract_hash = compute_contract_hash(contract)
    events: list[dict[str, Any]] = []
    prev_hash = contract_hash
    for sequence_id in range(1, count + 1):
        event = _make_signed_event(
            private_key=private_key,
            contract=contract,
            sequence_id=sequence_id,
            prev_hash=prev_hash,
            timestamp=_iso(sequence_id),
        )
        events.append(event)
        prev_hash = compute_prev_hash(event)
    return events


def _failure_kinds(result) -> list[str]:
    return [failure.kind for failure in result.failures]


@pytest.mark.signed_chain
def test_verify_chain_accepts_real_proxy_allow_path(tmp_path: Path, contract, monkeypatch) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "events.jsonl"
    keypair = generate_keypair(tmp_path / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=tmp_path,
    )
    proxy = ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=SESSION_ID,
        state_dir=tmp_path,
    )

    try:
        response = proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}

        attestation = proxy.event_logger.last_attestation
        assert attestation is not None
        persisted = json.loads(events_path.read_text(encoding="utf-8").splitlines()[0])
        assert attestation["kind"] == "chronicle_attestation"
        assert attestation["event_hash"] == compute_prev_hash(persisted)
        assert attestation["signature"] == persisted["signature"]
        assert attestation["decision"] == "allow"

        result = verify_chain(events_path, keypair.public_key, contract)
        assert result.status == "INTACT"
        assert result.signed_event_count == 1
        assert result.failures == []
    finally:
        proxy.close()


@pytest.mark.signed_chain
def test_chain_intact_status(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=3)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "INTACT"
    assert result.signed_event_count == 3
    assert result.failures == []


@pytest.mark.signed_chain
def test_signature_tamper_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=3)
    events[1]["reason"] = "tampered_without_resign"
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert "SignatureFailure" in _failure_kinds(result)
    assert result.first_failure_sequence_id == 2


@pytest.mark.signed_chain
def test_deleted_event_gap_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=3)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [events[0], events[2]])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert "SequenceFailure" in _failure_kinds(result)


@pytest.mark.signed_chain
def test_inserted_duplicate_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=3)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [events[0], events[1], events[1], events[2]])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert any(f.kind == "SequenceFailure" and f.detail == "duplicate" for f in result.failures)


@pytest.mark.signed_chain
def test_genesis_prev_hash_mismatch_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    events[0] = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash="0" * 64,
        timestamp=_iso(1),
    )
    events[1]["prev_hash"] = compute_prev_hash(events[0])
    events[1]["signature"] = sign_event(events[1], keypair.private_key)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert any(
        f.kind == "HashFailure" and f.detail == "genesis_contract_mismatch"
        for f in result.failures
    )


@pytest.mark.signed_chain
def test_contract_hash_splice_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=3)
    events[1] = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_prev_hash(events[0]),
        timestamp=_iso(2),
        contract_hash="f" * 64,
    )
    events[2]["prev_hash"] = compute_prev_hash(events[1])
    events[2]["signature"] = sign_event(events[2], keypair.private_key)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert "SplicingFailure" in _failure_kinds(result)


@pytest.mark.signed_chain
def test_timestamp_reversal_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    events[1] = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_prev_hash(events[0]),
        timestamp=_iso(0),
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert "TimestampFailure" in _failure_kinds(result)


@pytest.mark.signed_chain
def test_cross_chain_fields_on_non_genesis_is_broken(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    events[1] = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_prev_hash(events[0]),
        timestamp=_iso(2),
        extras={
            "prev_chain_terminal_hash": "e" * 64,
            "prev_session_id": OTHER_SESSION_ID,
        },
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "BROKEN"
    assert any(
        f.kind == "SchemaViolation" and f.detail == "cross_chain_fields_on_non_genesis"
        for f in result.failures
    )


@pytest.mark.signed_chain
def test_line1_unparseable_is_error(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, ["{bad_json"])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "ERROR"
    assert result.session_id is None
    assert result.error == "First event unparseable. Cannot establish session identity or chain head."


@pytest.mark.signed_chain
def test_genesis_missing_required_field_is_error(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
    )
    del genesis["key_id"]
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "ERROR"
    assert result.error is not None
    assert "Genesis event missing required fields" in result.error


@pytest.mark.signed_chain
def test_genesis_signature_not_base64_is_error(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
    )
    genesis["signature"] = "***"
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "ERROR"
    assert result.error == "Genesis signature not base64-decodable."


@pytest.mark.signed_chain
def test_genesis_prev_hash_malformed_is_error(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash="abc",
        timestamp=_iso(1),
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "ERROR"
    assert result.error == "Genesis prev_hash malformed."


@pytest.mark.signed_chain
def test_mid_file_parse_failure_is_unverifiable(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [events[0], "{broken", events[1]])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "UNVERIFIABLE"
    assert result.verifiable_up_to_sequence_id == 1
    assert "ParseFailure" in _failure_kinds(result)


@pytest.mark.signed_chain
def test_mid_file_schema_violation_is_unverifiable(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    del events[1]["prev_hash"]
    events[1]["signature"] = sign_event(events[1], keypair.private_key)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "UNVERIFIABLE"
    assert "SchemaViolation" in _failure_kinds(result)


@pytest.mark.signed_chain
def test_multiple_session_ids_is_error(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=2)
    events[1] = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_prev_hash(events[0]),
        timestamp=_iso(2),
        session_id=OTHER_SESSION_ID,
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.status == "ERROR"
    assert (
        result.error
        == "Multiple session_ids detected. events.jsonl must contain exactly one session. Split file before verifying."
    )


@pytest.mark.signed_chain
def test_prev_unsigned_terminal_hash_valid(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    unsigned = {
        "sequence_id": 1,
        "timestamp": _iso(1),
        "session_id": SESSION_ID,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "legacy",
        "contract_id": contract.contract_id,
        "contract_hash": compute_contract_hash(contract),
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "prev_hash": None,
        "signature": None,
    }
    bridge = compute_prev_hash(unsigned)
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(2),
        extras={"prev_unsigned_terminal_hash": bridge},
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [unsigned, genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.unsigned_count == 1
    assert result.unsigned_link_valid is True


@pytest.mark.signed_chain
def test_prev_unsigned_terminal_hash_invalid(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    unsigned = {
        "sequence_id": 1,
        "timestamp": _iso(1),
        "session_id": SESSION_ID,
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "legacy",
        "contract_id": contract.contract_id,
        "contract_hash": compute_contract_hash(contract),
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "prev_hash": None,
        "signature": None,
    }
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=2,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(2),
        extras={"prev_unsigned_terminal_hash": "0" * 64},
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [unsigned, genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.unsigned_link_valid is False


@pytest.mark.signed_chain
def test_prev_unsigned_terminal_hash_absent(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    events = _build_valid_chain(keypair.private_key, contract, count=1)
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, events)

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.unsigned_count == 0
    assert result.unsigned_link_valid is None


@pytest.mark.signed_chain
def test_cross_restart_link_valid(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    prior_events = _build_valid_chain(keypair.private_key, contract, count=2)
    archived_path = tmp_path / f"events_{OTHER_SESSION_ID}.jsonl"
    _write_jsonl(archived_path, prior_events)
    prior_terminal_hash = compute_prev_hash(prior_events[-1])

    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
        extras={
            "prev_chain_terminal_hash": prior_terminal_hash,
            "prev_session_id": OTHER_SESSION_ID,
        },
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.cross_chain_link_valid is True


@pytest.mark.signed_chain
def test_cross_restart_link_invalid(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    prior_events = _build_valid_chain(keypair.private_key, contract, count=1)
    archived_path = tmp_path / f"events_{OTHER_SESSION_ID}.jsonl"
    _write_jsonl(archived_path, prior_events)

    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
        extras={
            "prev_chain_terminal_hash": "0" * 64,
            "prev_session_id": OTHER_SESSION_ID,
        },
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.cross_chain_link_valid is False


@pytest.mark.signed_chain
def test_cross_restart_link_missing_archive_is_none(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
        extras={
            "prev_chain_terminal_hash": "0" * 64,
            "prev_session_id": OTHER_SESSION_ID,
        },
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.cross_chain_link_valid is None


@pytest.mark.signed_chain
def test_cross_restart_link_archive_without_signed_events_is_none(tmp_path: Path, contract) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    archived_path = tmp_path / f"events_{OTHER_SESSION_ID}.jsonl"
    _write_jsonl(
        archived_path,
        [
            {
                "sequence_id": 1,
                "session_id": OTHER_SESSION_ID,
                "prev_hash": None,
                "signature": None,
            }
        ],
    )
    genesis = _make_signed_event(
        private_key=keypair.private_key,
        contract=contract,
        sequence_id=1,
        prev_hash=compute_contract_hash(contract),
        timestamp=_iso(1),
        extras={
            "prev_chain_terminal_hash": "0" * 64,
            "prev_session_id": OTHER_SESSION_ID,
        },
    )
    events_path = tmp_path / "events.jsonl"
    _write_jsonl(events_path, [genesis])

    result = verify_chain(events_path, keypair.public_key, contract)
    assert result.cross_chain_link_valid is None
