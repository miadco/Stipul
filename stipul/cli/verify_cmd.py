"""Verify command for signed sessions."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stipul.cli.io import CLIError
from stipul.cli.io import ensure_session_dir, read_json, write_json
from stipul.exceptions import ContractValidationError
from stipul.charter.contract.schema import Contract
from stipul.chronicle.signing.verifier import verify_chain
from stipul.seal.verifier import SealVerificationResult, verify_seal


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "verify",
        help="Verify the authoritative signed events stream for a session",
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run)


def _load_contract(path: Path) -> Contract:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise CLIError(f"Contract JSON must be an object: {path}", exit_code=3)
    return Contract.from_dict(payload)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except FileNotFoundError as exc:
        raise CLIError(f"Public key file not found: {path}", exit_code=3) from exc
    except ValueError as exc:
        raise CLIError(f"Invalid public key PEM: {path}", exit_code=3) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CLIError(f"Public key is not Ed25519: {path}", exit_code=3)
    return key


def _build_report(
    chain_result: Any, *, seal_status: str, seal_reason: str | None
) -> dict[str, Any]:
    break_point: dict[str, int] | None = None
    if chain_result.first_failure_sequence_id is not None:
        break_point = {
            "first_failure_sequence_id": chain_result.first_failure_sequence_id
        }
    elif chain_result.verifiable_up_to_sequence_id is not None:
        break_point = {
            "verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id
        }

    return {
        "break_point": break_point,
        "chain_status": chain_result.status,
        "error": chain_result.error,
        "failures": [asdict(failure) for failure in chain_result.failures],
        "first_failure_sequence_id": chain_result.first_failure_sequence_id,
        "signed_event_count": chain_result.signed_event_count,
        "seal_reason": seal_reason,
        "seal_status": seal_status,
        "total_events": chain_result.signed_event_count + chain_result.unsigned_count,
        "unsigned_count": chain_result.unsigned_count,
        "verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id,
    }


def _render_receipt(chain_result: Any, seal_result: SealVerificationResult) -> str:
    lines = [
        "Verification receipt",
        f"Session: {chain_result.session_id or 'unknown'}",
        f"Chain: {chain_result.status}",
        f"Seal: {seal_result.status}",
    ]

    if seal_result.status != "VALID" and seal_result.error:
        lines.append(f"Reason: {seal_result.error}")

    chain_detail = _chain_detail(chain_result)
    if chain_detail is not None:
        lines.append(f"Chain detail: {chain_detail}")

    terminal_line = _terminal_line(seal_result)
    if terminal_line is not None:
        lines.append(terminal_line)
    if seal_result.key_id is not None:
        lines.append(f"Key: {seal_result.key_id}")
    return "\n".join(lines)


def _chain_detail(chain_result: Any) -> str | None:
    if chain_result.status == "BROKEN" and chain_result.failures:
        first = next(
            (
                failure
                for failure in chain_result.failures
                if failure.sequence_id is not None
            ),
            chain_result.failures[0],
        )
        if first.sequence_id is not None:
            prefix = f"first failure at sequence_id {first.sequence_id}"
        elif first.line_number is not None:
            prefix = f"first failure at line {first.line_number}"
        else:
            prefix = "first failure detected"
        return f"{prefix} ({first.kind}: {first.detail})"

    if chain_result.status == "UNVERIFIABLE":
        parts: list[str] = []
        if chain_result.verifiable_up_to_sequence_id is not None:
            parts.append(
                f"verifiable up to sequence_id {chain_result.verifiable_up_to_sequence_id}"
            )
        parse_failure = next(
            (
                failure
                for failure in chain_result.failures
                if failure.kind == "ParseFailure"
            ),
            None,
        )
        if parse_failure is not None and parse_failure.line_number is not None:
            parts.append(f"line {parse_failure.line_number} unparseable")
        if parts:
            return "; ".join(parts)
        return "chain structure could not be fully verified"

    if chain_result.status == "ERROR":
        return chain_result.error or "verification failed"

    return None


def _terminal_line(seal_result: SealVerificationResult) -> str | None:
    if (
        seal_result.terminal_sequence_id is not None
        and seal_result.terminal_timestamp is not None
    ):
        return (
            "Terminal: "
            f"seq={seal_result.terminal_sequence_id} at {seal_result.terminal_timestamp}"
        )
    if seal_result.terminal_sequence_id is not None:
        return f"Terminal: seq={seal_result.terminal_sequence_id}"
    if seal_result.terminal_timestamp is not None:
        return f"Terminal: at {seal_result.terminal_timestamp}"
    return None


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        contract = _load_contract(Path(args.contract))
        public_key = _load_public_key(Path(args.public_key))
        events_path = session_dir / "events.jsonl"

        chain_result = verify_chain(events_path, public_key, contract)
        seal_result = verify_seal(session_dir, public_key, contract)
        report = _build_report(
            chain_result,
            seal_status=seal_result.status,
            seal_reason=seal_result.error,
        )
        print(_render_receipt(chain_result, seal_result))

        if args.json_out:
            write_json(Path(args.json_out), report, pretty=True, sort_keys=True)

        if chain_result.status == "ERROR":
            return 3
        if chain_result.status == "INTACT":
            return 0
        return 2
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
