"""Verification helpers for session Seal artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.signing.keys import get_key_id
from stipul.seal.builder import seal_path
from stipul.seal.signer import canonical_seal_payload
from stipul.utils.canonical import compute_prev_hash

SealStatus = Literal["VALID", "INVALID", "ABSENT"]


@dataclass(frozen=True)
class SealVerificationResult:
    status: SealStatus
    error: str | None = None
    terminal_sequence_id: int | None = None
    terminal_timestamp: str | None = None
    key_id: str | None = None


@dataclass(frozen=True)
class _SealContext:
    terminal_event_type: str | None = None
    terminal_sequence_id: int | None = None
    terminal_timestamp: str | None = None
    key_id: str | None = None


def verify_seal(
    session_dir: str | Path,
    public_key: Ed25519PublicKey,
    contract: Contract,
) -> SealVerificationResult:
    resolved_session_dir = Path(session_dir)
    resolved_seal_path = seal_path(resolved_session_dir)
    events_path = resolved_session_dir / "events.jsonl"
    seal_context = _best_effort_seal_context(events_path)
    if not resolved_seal_path.exists():
        return _seal_result(
            status="ABSENT",
            error=_absent_seal_reason(seal_context),
            context=seal_context,
        )

    try:
        payload = json.loads(resolved_seal_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("seal.json must be a JSON object")

        _validate_seal_payload(
            payload, public_key=public_key, contract=contract, events_path=events_path
        )
        public_key.verify(
            _decode_signature(str(payload["signature"])),
            canonical_seal_payload(payload),
        )
        return _seal_result(status="VALID", context=seal_context)
    except InvalidSignature:
        return _seal_result(
            status="INVALID",
            error="seal signature verification failed",
            context=seal_context,
        )
    except (OSError, TypeError, ValueError) as exc:
        return _seal_result(status="INVALID", error=str(exc), context=seal_context)


def _validate_seal_payload(
    payload: dict[str, Any],
    *,
    public_key: Ed25519PublicKey,
    contract: Contract,
    events_path: Path,
) -> None:
    if payload.get("kind") != "session_seal":
        raise ValueError("seal kind mismatch")

    version = payload.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ValueError("seal version mismatch")

    session_id = _required_non_empty_str(payload, "session_id")
    contract_id = _required_non_empty_str(payload, "contract_id")
    contract_hash = _required_lower_hex(payload, "contract_hash", length=64)
    events_sha256 = _required_lower_hex(payload, "events_sha256", length=64)
    key_id = _required_lower_hex(payload, "key_id", length=8)
    algorithm = _required_non_empty_str(payload, "algorithm")
    key_created_at = _required_non_empty_str(payload, "key_created_at")
    terminal_event_hash = _required_lower_hex(payload, "terminal_event_hash", length=64)
    terminal_sequence_id = _required_positive_int(payload, "terminal_sequence_id")
    terminal_timestamp = _required_non_empty_str(payload, "terminal_timestamp")
    _required_base64_str(payload, "signature")

    expected_contract_hash = compute_contract_hash(contract)
    if contract_id != contract.contract_id:
        raise ValueError("seal contract_id does not match requested contract")
    if contract_hash != expected_contract_hash:
        raise ValueError("seal contract_hash does not match requested contract")
    if key_id != get_key_id(public_key):
        raise ValueError("seal key_id does not match verification key")
    if algorithm != "ed25519":
        raise ValueError("seal algorithm must be ed25519")

    source_events_sha256 = hashlib.sha256(events_path.read_bytes()).hexdigest()
    if events_sha256 != source_events_sha256:
        raise ValueError("seal events_sha256 does not match authoritative events.jsonl")

    first_session_id, terminal_event = _load_events_session_binding(events_path)
    if first_session_id != session_id:
        raise ValueError("seal session_id does not match authoritative events.jsonl")
    if terminal_event is None:
        raise ValueError("authoritative events.jsonl has no signed terminal event")

    if terminal_event_hash != compute_prev_hash(terminal_event):
        raise ValueError(
            "seal terminal_event_hash does not match authoritative events.jsonl"
        )
    if terminal_event.get("sequence_id") != terminal_sequence_id:
        raise ValueError(
            "seal does not match authoritative session evidence"
        )
    if terminal_event.get("timestamp") != terminal_timestamp:
        raise ValueError(
            "seal terminal_timestamp does not match authoritative events.jsonl"
        )
    if terminal_event.get("session_id") != session_id:
        raise ValueError("authoritative terminal event session_id does not match seal")
    if terminal_event.get("contract_id") != contract_id:
        raise ValueError("authoritative terminal event contract_id does not match seal")
    if terminal_event.get("contract_hash") != contract_hash:
        raise ValueError(
            "authoritative terminal event contract_hash does not match seal"
        )
    if terminal_event.get("key_id") != key_id:
        raise ValueError("authoritative terminal event key_id does not match seal")
    if terminal_event.get("algorithm") != algorithm:
        raise ValueError("authoritative terminal event algorithm does not match seal")
    if terminal_event.get("key_created_at") != key_created_at:
        raise ValueError(
            "authoritative terminal event key_created_at does not match seal"
        )


def _load_events_session_binding(
    events_path: Path,
) -> tuple[str, dict[str, Any] | None]:
    first_session_id: str | None = None
    terminal_event: dict[str, Any] | None = None
    for raw_line in events_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in authoritative events.jsonl: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError("authoritative events.jsonl contains a non-object record")

        if first_session_id is None:
            session_id = payload.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise ValueError(
                    "authoritative events.jsonl first record missing session_id"
                )
            first_session_id = session_id

        signature = payload.get("signature")
        if isinstance(signature, str) and signature:
            terminal_event = payload

    if first_session_id is None:
        raise ValueError("authoritative events.jsonl is empty")
    return first_session_id, terminal_event


def _seal_result(
    *,
    status: SealStatus,
    error: str | None = None,
    context: _SealContext | None = None,
) -> SealVerificationResult:
    return SealVerificationResult(
        status=status,
        error=error,
        terminal_sequence_id=context.terminal_sequence_id
        if context is not None
        else None,
        terminal_timestamp=context.terminal_timestamp if context is not None else None,
        key_id=context.key_id if context is not None else None,
    )


def _absent_seal_reason(context: _SealContext | None) -> str:
    if context is None or context.terminal_event_type is None:
        return "no seal.json found for session"
    if context.terminal_event_type == "session_close":
        return "no seal.json found for closed session"
    return (
        "session is unsealed; terminal event is "
        f"{context.terminal_event_type}, not session_close"
    )


def _best_effort_seal_context(events_path: Path) -> _SealContext | None:
    try:
        raw_lines = events_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    terminal_event: dict[str, Any] | None = None
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        signature = payload.get("signature")
        if isinstance(signature, str) and signature:
            terminal_event = payload

    if terminal_event is None:
        return None

    sequence_id = terminal_event.get("sequence_id")
    timestamp = terminal_event.get("timestamp")
    key_id = terminal_event.get("key_id")
    event_type = terminal_event.get("event_type")
    return _SealContext(
        terminal_event_type=event_type
        if isinstance(event_type, str) and event_type
        else None,
        terminal_sequence_id=sequence_id if isinstance(sequence_id, int) else None,
        terminal_timestamp=timestamp
        if isinstance(timestamp, str) and timestamp
        else None,
        key_id=key_id if isinstance(key_id, str) and key_id else None,
    )


def _decode_signature(signature: str) -> bytes:
    return base64.b64decode(signature.encode("ascii"), validate=True)


def _required_non_empty_str(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _required_lower_hex(payload: dict[str, Any], field: str, *, length: int) -> str:
    value = _required_non_empty_str(payload, field).lower()
    if len(value) != length or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field} must be a {length}-character lowercase hex string")
    return value


def _required_positive_int(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _required_base64_str(payload: dict[str, Any], field: str) -> str:
    value = _required_non_empty_str(payload, field)
    try:
        _decode_signature(value)
    except Exception as exc:
        raise ValueError(f"{field} must be valid base64") from exc
    return value


__all__ = ["SealVerificationResult", "verify_seal"]
