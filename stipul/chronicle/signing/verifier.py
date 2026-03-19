"""Chain verification and tamper detection for signed event streams."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.utils.canonical import canonical_event_payload, compute_prev_hash

VerificationStatus = Literal["INTACT", "BROKEN", "UNVERIFIABLE", "ERROR"]

_REQUIRED_SIGNED_FIELDS = {"session_id", "prev_hash", "signature", "contract_hash", "key_id"}
_GENESIS_ONLY_FIELDS = {
    "prev_unsigned_terminal_hash",
    "prev_chain_terminal_hash",
    "prev_session_id",
}


@dataclass
class VerificationFailure:
    kind: str
    sequence_id: int | None
    detail: str
    line_number: int | None = None
    expected: str | None = None
    found: str | None = None
    timestamp: str | None = None


@dataclass
class VerificationResult:
    status: VerificationStatus
    session_id: str | None
    signed_event_count: int
    unsigned_count: int
    unsigned_link_valid: bool | None
    cross_chain_link_valid: bool | None
    verifiable_up_to_sequence_id: int | None
    failures: list[VerificationFailure]
    first_failure_sequence_id: int | None
    error: str | None


@dataclass
class DecisionsVerificationResult:
    status: Literal["VALID", "DIVERGENT", "NOT_GENERATED"]
    missing_from_decisions: list[int]
    extra_in_decisions: list[int]
    field_mismatches: list[tuple[int, str]]


def _is_lower_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _is_base64(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return False
    return True


def _parse_iso_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return None
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _decode_signature(signature: str) -> bytes:
    return base64.b64decode(signature.encode("ascii"), validate=True)


def _load_lines(events_path: Path) -> list[str]:
    try:
        return events_path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        raise OSError(f"Unable to read events file: {events_path}") from exc


def _project_decisions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for event in events:
        if "decision" not in event:
            continue
        projected.append(
            {
                "sequence_id": event.get("sequence_id"),
                "event_type": event.get("event_type"),
                "decision": event.get("decision"),
                "reason": event.get("reason"),
                "tool_name": event.get("tool_name"),
                "contract_id": event.get("contract_id"),
                "contract_hash": event.get("contract_hash"),
            }
        )
    return projected


def verify_decisions(events_path: Path, decisions_path: Path) -> DecisionsVerificationResult:
    if not decisions_path.exists():
        return DecisionsVerificationResult(
            status="NOT_GENERATED",
            missing_from_decisions=[],
            extra_in_decisions=[],
            field_mismatches=[],
        )

    events_payload = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    decisions_payload = [
        json.loads(line)
        for line in decisions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected = {item["sequence_id"]: item for item in _project_decisions(events_payload)}
    actual = {item.get("sequence_id"): item for item in decisions_payload}

    missing = sorted(seq for seq in expected if seq not in actual)
    extra = sorted(seq for seq in actual if seq not in expected)
    mismatches: list[tuple[int, str]] = []
    for sequence_id in sorted(set(expected).intersection(actual)):
        for field in (
            "event_type",
            "decision",
            "reason",
            "tool_name",
            "contract_id",
            "contract_hash",
        ):
            if expected[sequence_id].get(field) != actual[sequence_id].get(field):
                mismatches.append((sequence_id, field))

    status: Literal["VALID", "DIVERGENT", "NOT_GENERATED"] = "VALID"
    if missing or extra or mismatches:
        status = "DIVERGENT"
    return DecisionsVerificationResult(
        status=status,
        missing_from_decisions=missing,
        extra_in_decisions=extra,
        field_mismatches=mismatches,
    )


def _verify_cross_chain_link(events_path: Path, genesis: dict[str, Any]) -> bool | None:
    prev_chain_hash = genesis.get("prev_chain_terminal_hash")
    prev_session_id = genesis.get("prev_session_id")
    if prev_chain_hash is None and prev_session_id is None:
        return None
    if not isinstance(prev_chain_hash, str) or not isinstance(prev_session_id, str):
        return False

    archived_path = events_path.parent / f"events_{prev_session_id}.jsonl"
    if not archived_path.exists():
        return None

    last_hash: str | None = None
    for raw_line in archived_path.read_text(encoding="utf-8").splitlines():
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
        if signature is None or not _is_base64(signature):
            continue
        last_hash = compute_prev_hash(payload)

    if last_hash is None:
        return None
    return last_hash == prev_chain_hash


def verify_chain(
    events_path: Path,
    public_key: Ed25519PublicKey,
    contract: Contract,
) -> VerificationResult:
    """
    Verify a single-session signed chain against a governing contract.

    Caller must supply the contract that governed this session. Without it,
    genesis binding cannot be verified.
    """
    try:
        lines = _load_lines(events_path)
    except OSError as exc:
        return VerificationResult(
            status="ERROR",
            session_id=None,
            signed_event_count=0,
            unsigned_count=0,
            unsigned_link_valid=None,
            cross_chain_link_valid=None,
            verifiable_up_to_sequence_id=None,
            failures=[],
            first_failure_sequence_id=None,
            error=str(exc),
        )

    if not lines:
        return VerificationResult(
            status="ERROR",
            session_id=None,
            signed_event_count=0,
            unsigned_count=0,
            unsigned_link_valid=None,
            cross_chain_link_valid=None,
            verifiable_up_to_sequence_id=None,
            failures=[],
            first_failure_sequence_id=None,
            error="First event unparseable. Cannot establish session identity or chain head.",
        )

    # First line must be parseable to establish session identity.
    try:
        first_event = json.loads(lines[0])
    except Exception:
        return VerificationResult(
            status="ERROR",
            session_id=None,
            signed_event_count=0,
            unsigned_count=0,
            unsigned_link_valid=None,
            cross_chain_link_valid=None,
            verifiable_up_to_sequence_id=None,
            failures=[],
            first_failure_sequence_id=None,
            error="First event unparseable. Cannot establish session identity or chain head.",
        )
    if not isinstance(first_event, dict):
        return VerificationResult(
            status="ERROR",
            session_id=None,
            signed_event_count=0,
            unsigned_count=0,
            unsigned_link_valid=None,
            cross_chain_link_valid=None,
            verifiable_up_to_sequence_id=None,
            failures=[],
            first_failure_sequence_id=None,
            error="First event unparseable. Cannot establish session identity or chain head.",
        )

    first_session_id = first_event.get("session_id")
    if not isinstance(first_session_id, str) or not first_session_id:
        return VerificationResult(
            status="ERROR",
            session_id=None,
            signed_event_count=0,
            unsigned_count=0,
            unsigned_link_valid=None,
            cross_chain_link_valid=None,
            verifiable_up_to_sequence_id=None,
            failures=[],
            first_failure_sequence_id=None,
            error="First event unparseable. Cannot establish session identity or chain head.",
        )

    failures: list[VerificationFailure] = []
    expected_contract_hash = compute_contract_hash(contract)
    signed_event_count = 0
    leading_unsigned: list[dict[str, Any]] = []
    unsigned_count = 0
    unsigned_link_valid: bool | None = None
    cross_chain_link_valid: bool | None = None
    first_failure_sequence_id: int | None = None
    status: VerificationStatus = "INTACT"
    verifiable_up_to_sequence_id: int | None = None
    chain_linkage_active = True
    parse_gap_line: int | None = None

    genesis_event: dict[str, Any] | None = None
    previous_signed_for_chain: dict[str, Any] | None = None
    previous_sequence: int | None = None
    previous_timestamp: datetime | None = None

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except Exception:
            if genesis_event is None:
                return VerificationResult(
                    status="ERROR",
                    session_id=first_session_id,
                    signed_event_count=signed_event_count,
                    unsigned_count=unsigned_count,
                    unsigned_link_valid=unsigned_link_valid,
                    cross_chain_link_valid=cross_chain_link_valid,
                    verifiable_up_to_sequence_id=None,
                    failures=failures,
                    first_failure_sequence_id=first_failure_sequence_id,
                    error="Genesis event missing required fields: parse_failure. Chain cannot be verified.",
                )
            failures.append(
                VerificationFailure(
                    kind="ParseFailure",
                    sequence_id=None,
                    detail=f"line {line_number} unparseable",
                    line_number=line_number,
                )
            )
            if status != "ERROR":
                status = "UNVERIFIABLE"
            chain_linkage_active = False
            parse_gap_line = line_number if parse_gap_line is None else parse_gap_line
            verifiable_up_to_sequence_id = previous_sequence
            continue

        if not isinstance(event, dict):
            if genesis_event is None:
                return VerificationResult(
                    status="ERROR",
                    session_id=first_session_id,
                    signed_event_count=signed_event_count,
                    unsigned_count=unsigned_count,
                    unsigned_link_valid=unsigned_link_valid,
                    cross_chain_link_valid=cross_chain_link_valid,
                    verifiable_up_to_sequence_id=None,
                    failures=failures,
                    first_failure_sequence_id=first_failure_sequence_id,
                    error="Genesis event missing required fields: parse_failure. Chain cannot be verified.",
                )
            failures.append(
                VerificationFailure(
                    kind="ParseFailure",
                    sequence_id=None,
                    detail=f"line {line_number} is not a JSON object",
                    line_number=line_number,
                )
            )
            status = "UNVERIFIABLE"
            chain_linkage_active = False
            parse_gap_line = line_number if parse_gap_line is None else parse_gap_line
            verifiable_up_to_sequence_id = previous_sequence
            continue

        session_id = event.get("session_id")
        if isinstance(session_id, str) and session_id != first_session_id:
            return VerificationResult(
                status="ERROR",
                session_id=first_session_id,
                signed_event_count=signed_event_count,
                unsigned_count=unsigned_count,
                unsigned_link_valid=unsigned_link_valid,
                cross_chain_link_valid=cross_chain_link_valid,
                verifiable_up_to_sequence_id=verifiable_up_to_sequence_id,
                failures=failures,
                first_failure_sequence_id=first_failure_sequence_id,
                error=(
                    "Multiple session_ids detected. events.jsonl must contain exactly one session. "
                    "Split file before verifying."
                ),
            )

        signature_value = event.get("signature")
        is_signed = signature_value is not None
        if genesis_event is None and not is_signed:
            leading_unsigned.append(event)
            unsigned_count += 1
            continue

        if not is_signed:
            # Unsigned events are only expected before genesis.
            failures.append(
                VerificationFailure(
                    kind="SchemaViolation",
                    sequence_id=event.get("sequence_id") if isinstance(event.get("sequence_id"), int) else None,
                    detail="unsigned_event_after_signed_chain_start",
                    line_number=line_number,
                )
            )
            status = "BROKEN" if status == "INTACT" else status
            continue

        missing_fields = sorted(field for field in _REQUIRED_SIGNED_FIELDS if field not in event)
        sequence_id = event.get("sequence_id") if isinstance(event.get("sequence_id"), int) else None
        timestamp_raw = event.get("timestamp")
        timestamp = _parse_iso_utc(timestamp_raw)

        if genesis_event is None:
            if missing_fields:
                return VerificationResult(
                    status="ERROR",
                    session_id=first_session_id,
                    signed_event_count=signed_event_count,
                    unsigned_count=unsigned_count,
                    unsigned_link_valid=unsigned_link_valid,
                    cross_chain_link_valid=cross_chain_link_valid,
                    verifiable_up_to_sequence_id=None,
                    failures=failures,
                    first_failure_sequence_id=first_failure_sequence_id,
                    error=(
                        "Genesis event missing required fields: "
                        f"{', '.join(missing_fields)}. Chain cannot be verified."
                    ),
                )
            if not _is_base64(signature_value):
                return VerificationResult(
                    status="ERROR",
                    session_id=first_session_id,
                    signed_event_count=signed_event_count,
                    unsigned_count=unsigned_count,
                    unsigned_link_valid=unsigned_link_valid,
                    cross_chain_link_valid=cross_chain_link_valid,
                    verifiable_up_to_sequence_id=None,
                    failures=failures,
                    first_failure_sequence_id=first_failure_sequence_id,
                    error="Genesis signature not base64-decodable.",
                )
            signature_text = cast(str, signature_value)
            if not _is_lower_hex64(event.get("prev_hash")):
                return VerificationResult(
                    status="ERROR",
                    session_id=first_session_id,
                    signed_event_count=signed_event_count,
                    unsigned_count=unsigned_count,
                    unsigned_link_valid=unsigned_link_valid,
                    cross_chain_link_valid=cross_chain_link_valid,
                    verifiable_up_to_sequence_id=None,
                    failures=failures,
                    first_failure_sequence_id=first_failure_sequence_id,
                    error="Genesis prev_hash malformed.",
                )
            genesis_event = event
            signed_event_count += 1
            previous_signed_for_chain = event
            previous_sequence = sequence_id
            previous_timestamp = timestamp

            if leading_unsigned:
                bridge = genesis_event.get("prev_unsigned_terminal_hash")
                if bridge is not None:
                    last_unsigned = leading_unsigned[-1]
                    expected_unsigned_bridge = compute_prev_hash(last_unsigned)
                    unsigned_link_valid = bridge == expected_unsigned_bridge
                    if not unsigned_link_valid:
                        failures.append(
                            VerificationFailure(
                                kind="HashFailure",
                                sequence_id=sequence_id,
                                detail="unsigned_bridge_mismatch",
                                expected=expected_unsigned_bridge,
                                found=str(bridge),
                                timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                            )
                        )
                        status = "BROKEN" if status == "INTACT" else status
                else:
                    unsigned_link_valid = None

            if event.get("prev_hash") != expected_contract_hash:
                failures.append(
                    VerificationFailure(
                        kind="HashFailure",
                        sequence_id=sequence_id,
                        detail="genesis_contract_mismatch",
                        expected=expected_contract_hash,
                        found=str(event.get("prev_hash")),
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                status = "BROKEN" if status == "INTACT" else status
                if first_failure_sequence_id is None and sequence_id is not None:
                    first_failure_sequence_id = sequence_id

            if event.get("contract_hash") != expected_contract_hash:
                failures.append(
                    VerificationFailure(
                        kind="SplicingFailure",
                        sequence_id=sequence_id,
                        detail="contract_hash_mismatch",
                        expected=expected_contract_hash,
                        found=str(event.get("contract_hash")),
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                status = "BROKEN" if status == "INTACT" else status
                if first_failure_sequence_id is None and sequence_id is not None:
                    first_failure_sequence_id = sequence_id

            try:
                public_key.verify(_decode_signature(signature_text), canonical_event_payload(event))
            except (InvalidSignature, ValueError):
                failures.append(
                    VerificationFailure(
                        kind="SignatureFailure",
                        sequence_id=sequence_id,
                        detail="signature_invalid",
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                status = "BROKEN" if status == "INTACT" else status
                if first_failure_sequence_id is None and sequence_id is not None:
                    first_failure_sequence_id = sequence_id
            continue

        # Mid-chain schema checks.
        mid_chain_missing = sorted(field for field in _REQUIRED_SIGNED_FIELDS if field not in event)
        malformed_signature = not _is_base64(signature_value)
        malformed_prev_hash = not _is_lower_hex64(event.get("prev_hash"))
        if mid_chain_missing or malformed_signature or malformed_prev_hash:
            field_name = (
                ",".join(mid_chain_missing)
                if mid_chain_missing
                else "signature" if malformed_signature else "prev_hash"
            )
            failures.append(
                VerificationFailure(
                    kind="SchemaViolation",
                    sequence_id=sequence_id,
                    detail=field_name,
                    line_number=line_number,
                    timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                )
            )
            status = "UNVERIFIABLE"
            chain_linkage_active = False
            parse_gap_line = line_number if parse_gap_line is None else parse_gap_line
            verifiable_up_to_sequence_id = previous_sequence

        # Signature verification still runs for parseable events with decodable signatures.
        if _is_base64(signature_value):
            signature_text = cast(str, signature_value)
            try:
                public_key.verify(_decode_signature(signature_text), canonical_event_payload(event))
            except (InvalidSignature, ValueError):
                failures.append(
                    VerificationFailure(
                        kind="SignatureFailure",
                        sequence_id=sequence_id,
                        detail="signature_invalid",
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                if status == "INTACT":
                    status = "BROKEN"
                if first_failure_sequence_id is None and sequence_id is not None:
                    first_failure_sequence_id = sequence_id

        if event.get("contract_hash") != expected_contract_hash:
            failures.append(
                VerificationFailure(
                    kind="SplicingFailure",
                    sequence_id=sequence_id,
                    detail="contract_hash_mismatch",
                    expected=expected_contract_hash,
                    found=str(event.get("contract_hash")),
                    timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                )
            )
            if status == "INTACT":
                status = "BROKEN"
            if first_failure_sequence_id is None and sequence_id is not None:
                first_failure_sequence_id = sequence_id

        # Sequence checks apply to all parseable signed events.
        if previous_sequence is not None and sequence_id is not None:
            expected_sequence = previous_sequence + 1
            if sequence_id != expected_sequence:
                detail = "duplicate" if sequence_id < expected_sequence else "gap"
                failures.append(
                    VerificationFailure(
                        kind="SequenceFailure",
                        sequence_id=sequence_id,
                        detail=detail,
                        expected=str(expected_sequence),
                        found=str(sequence_id),
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                if status == "INTACT":
                    status = "BROKEN"
                if first_failure_sequence_id is None:
                    first_failure_sequence_id = sequence_id

        if previous_timestamp is not None and timestamp is not None and timestamp < previous_timestamp:
            failures.append(
                VerificationFailure(
                    kind="TimestampFailure",
                    sequence_id=sequence_id,
                    detail="reversal",
                    timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                )
            )
            if status == "INTACT":
                status = "BROKEN"
            if first_failure_sequence_id is None and sequence_id is not None:
                first_failure_sequence_id = sequence_id

        # Genesis-only fields must not appear after genesis.
        if any(field in event for field in _GENESIS_ONLY_FIELDS):
            failures.append(
                VerificationFailure(
                    kind="SchemaViolation",
                    sequence_id=sequence_id,
                    detail="cross_chain_fields_on_non_genesis",
                    timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                )
            )
            if status == "INTACT":
                status = "BROKEN"
            if first_failure_sequence_id is None and sequence_id is not None:
                first_failure_sequence_id = sequence_id

        # Chain linkage checks stop after structural gaps.
        if chain_linkage_active and previous_signed_for_chain is not None and _is_lower_hex64(
            event.get("prev_hash")
        ):
            expected_prev_hash = compute_prev_hash(previous_signed_for_chain)
            if event.get("prev_hash") != expected_prev_hash:
                failures.append(
                    VerificationFailure(
                        kind="HashFailure",
                        sequence_id=sequence_id,
                        detail="chain_break",
                        expected=expected_prev_hash,
                        found=str(event.get("prev_hash")),
                        timestamp=timestamp_raw if isinstance(timestamp_raw, str) else None,
                    )
                )
                if status == "INTACT":
                    status = "BROKEN"
                if first_failure_sequence_id is None and sequence_id is not None:
                    first_failure_sequence_id = sequence_id

        signed_event_count += 1
        previous_signed_for_chain = event
        previous_sequence = sequence_id if sequence_id is not None else previous_sequence
        previous_timestamp = timestamp if timestamp is not None else previous_timestamp

    if genesis_event is not None:
        cross_chain_link_valid = _verify_cross_chain_link(events_path, genesis_event)
        if cross_chain_link_valid is False and status == "INTACT":
            status = "BROKEN"
        if first_failure_sequence_id is None and cross_chain_link_valid is False:
            first_failure_sequence_id = (
                genesis_event.get("sequence_id")
                if isinstance(genesis_event.get("sequence_id"), int)
                else None
            )

    if status == "UNVERIFIABLE" and verifiable_up_to_sequence_id is None:
        verifiable_up_to_sequence_id = previous_sequence
    if failures and first_failure_sequence_id is None:
        for failure in failures:
            if failure.sequence_id is not None:
                first_failure_sequence_id = failure.sequence_id
                break

    return VerificationResult(
        status=status,
        session_id=first_session_id,
        signed_event_count=signed_event_count,
        unsigned_count=unsigned_count,
        unsigned_link_valid=unsigned_link_valid,
        cross_chain_link_valid=cross_chain_link_valid,
        verifiable_up_to_sequence_id=verifiable_up_to_sequence_id,
        failures=failures,
        first_failure_sequence_id=first_failure_sequence_id,
        error=None,
    )


def print_verification_result(result: VerificationResult) -> str:
    lines = [
        f"Chain integrity: {result.status}",
        f"Session: {result.session_id or 'unknown'}",
        (
            f"Signed events: {result.signed_event_count} | Unsigned events: "
            f"{result.unsigned_count} (unverified, not invalid)"
        ),
    ]

    if result.unsigned_link_valid is True:
        lines.append("Unsigned link: valid")
    elif result.unsigned_link_valid is False:
        lines.append("Unsigned link: invalid")
    else:
        lines.append("Unsigned link: not present")

    if result.cross_chain_link_valid is True:
        lines.append("Cross-chain link: valid")
    elif result.cross_chain_link_valid is False:
        lines.append("Cross-chain link: invalid")
    else:
        lines.append("Cross-chain link: not available")

    if result.status == "BROKEN" and result.failures:
        first = next((f for f in result.failures if f.sequence_id is not None), result.failures[0])
        lines.append(
            f"First failure: sequence_id {first.sequence_id}, timestamp {first.timestamp or 'unknown'}"
        )
        lines.append(f"  - {first.kind}: {first.detail}")
    elif result.status == "UNVERIFIABLE":
        lines.append(
            f"Chain verifiable up to sequence_id {result.verifiable_up_to_sequence_id}."
        )
        parse_failure = next((f for f in result.failures if f.kind == "ParseFailure"), None)
        if parse_failure is not None:
            lines.append(
                f"Unverifiable from line {parse_failure.line_number}: {parse_failure.detail}"
            )
        signature_failures = sum(1 for f in result.failures if f.kind == "SignatureFailure")
        lines.append(
            "Individual signature checks for remaining parseable events: "
            f"{'fail' if signature_failures else 'pass'} ({signature_failures} failures)"
        )
    elif result.status == "ERROR":
        lines.append(f"Verification failed: {result.error}")

    return "\n".join(lines)
