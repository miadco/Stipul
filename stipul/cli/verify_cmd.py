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
from stipul.chronicle.signing.verifier import print_verification_result, verify_chain


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


def _build_report(chain_result: Any) -> dict[str, Any]:
    break_point: dict[str, int] | None = None
    if chain_result.first_failure_sequence_id is not None:
        break_point = {"first_failure_sequence_id": chain_result.first_failure_sequence_id}
    elif chain_result.verifiable_up_to_sequence_id is not None:
        break_point = {"verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id}

    return {
        "break_point": break_point,
        "chain_status": chain_result.status,
        "error": chain_result.error,
        "failures": [asdict(failure) for failure in chain_result.failures],
        "first_failure_sequence_id": chain_result.first_failure_sequence_id,
        "signed_event_count": chain_result.signed_event_count,
        "total_events": chain_result.signed_event_count + chain_result.unsigned_count,
        "unsigned_count": chain_result.unsigned_count,
        "verifiable_up_to_sequence_id": chain_result.verifiable_up_to_sequence_id,
    }


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        contract = _load_contract(Path(args.contract))
        public_key = _load_public_key(Path(args.public_key))
        events_path = session_dir / "events.jsonl"

        chain_result = verify_chain(events_path, public_key, contract)
        report = _build_report(chain_result)
        print(print_verification_result(chain_result))

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
