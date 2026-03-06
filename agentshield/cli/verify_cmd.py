"""Verify command for signed sessions."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentshield.cli.io import CLIError
from agentshield.cli.io import ensure_session_dir, read_json, write_json
from agentshield.exceptions import ContractValidationError
from agentshield.contract.schema import Contract
from agentshield.events.decisions import DecisionVerification, generate_decisions
from agentshield.events.decisions import verify_decisions as verify_decisions_projection
from agentshield.signing.verifier import print_verification_result, verify_chain


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "verify",
        help="Verify a signed session and derived decisions projection",
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


def _verify_decisions(
    events_path: Path,
    decisions_path: Path,
) -> tuple[DecisionVerification, bool]:
    if decisions_path.exists():
        return verify_decisions_projection(events_path, decisions_path), True

    expected = generate_decisions(events_path)
    return (
        DecisionVerification(
            is_valid=False,
            expected_count=len(expected),
            actual_count=0,
            mismatches=[],
        ),
        False,
    )


def _build_report(
    chain_result: Any,
    decisions_result: DecisionVerification,
    decisions_file_present: bool,
) -> dict[str, Any]:
    break_point: dict[str, int] | None = None
    if chain_result.first_failure_sequence_id is not None:
        break_point = {"first_failure_sequence_id": chain_result.first_failure_sequence_id}
    elif chain_result.verifiable_up_to_sequence_id is not None:
        break_point = {"verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id}

    return {
        "break_point": break_point,
        "chain_status": chain_result.status,
        "decisions_actual_count": decisions_result.actual_count,
        "decisions_expected_count": decisions_result.expected_count,
        "decisions_file_present": decisions_file_present,
        "decisions_mismatches": [asdict(mismatch) for mismatch in decisions_result.mismatches],
        "decisions_valid": decisions_result.is_valid and decisions_file_present,
        "error": chain_result.error,
        "failures": [asdict(failure) for failure in chain_result.failures],
        "first_failure_sequence_id": chain_result.first_failure_sequence_id,
        "signed_event_count": chain_result.signed_event_count,
        "total_events": chain_result.signed_event_count + chain_result.unsigned_count,
        "unsigned_count": chain_result.unsigned_count,
        "verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id,
    }


def _format_decisions_report(
    decisions_result: DecisionVerification,
    *,
    decisions_file_present: bool,
) -> str:
    if not decisions_file_present:
        status = "INVALID (decisions.jsonl missing)"
    else:
        status = "VALID" if decisions_result.is_valid else "INVALID"

    lines = [
        f"Decision projection: {status}",
        (
            "Expected decisions: "
            f"{decisions_result.expected_count} | Actual decisions: {decisions_result.actual_count}"
        ),
    ]
    if decisions_result.mismatches:
        first = decisions_result.mismatches[0]
        lines.append(
            "First mismatch: "
            f"sequence_id {first.sequence_id}, type {first.mismatch_type}, field {first.field}"
        )
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        contract = _load_contract(Path(args.contract))
        public_key = _load_public_key(Path(args.public_key))
        events_path = session_dir / "events.jsonl"
        decisions_path = session_dir / "decisions.jsonl"

        chain_result = verify_chain(events_path, public_key, contract)
        decisions_result, decisions_file_present = _verify_decisions(events_path, decisions_path)
        report = _build_report(chain_result, decisions_result, decisions_file_present)

        human_output = "\n\n".join(
            [
                print_verification_result(chain_result),
                _format_decisions_report(
                    decisions_result,
                    decisions_file_present=decisions_file_present,
                ),
            ]
        )
        print(human_output)

        if args.json_out:
            write_json(Path(args.json_out), report, pretty=True, sort_keys=True)

        if chain_result.status == "ERROR":
            return 3
        if chain_result.status == "INTACT" and decisions_file_present and decisions_result.is_valid:
            return 0
        return 2
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
