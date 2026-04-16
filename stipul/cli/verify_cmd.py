"""Verify command for signed sessions."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stipul.cli.color import colorize, GREEN, RED, YELLOW
from stipul.cli.io import CLIError
from stipul.cli.io import ensure_session_dir, write_json
from stipul.charter.contract.loader import load_charter
from stipul.exceptions import ContractValidationError
from stipul.charter.contract.schema import Contract
from stipul.chronicle.signing.verifier import verify_chain
from stipul.seal.verifier import SealVerificationResult, verify_seal


@dataclass(frozen=True)
class VerificationOutcome:
    chain_result: Any
    seal_result: SealVerificationResult
    report: dict[str, Any]


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "verify",
        help="Verify the authoritative signed events stream for a session",
    )
    parser.add_argument("session_dir", nargs="?")
    parser.add_argument("--session-dir", dest="session_dir_flag")
    parser.add_argument("--contract")
    parser.add_argument("--public-key")
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run, parser=parser)


def _load_contract(path: Path) -> Contract:
    return load_charter(path).contract


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
    chain_status_display = chain_result.status
    if chain_result.status == "INTACT":
        chain_status_display = colorize("INTACT", GREEN)
    elif chain_result.status == "BROKEN":
        chain_status_display = colorize("BROKEN", RED)
    elif chain_result.status == "ERROR":
        chain_status_display = colorize("ERROR", RED)
    elif chain_result.status == "UNVERIFIABLE":
        chain_status_display = colorize("UNVERIFIABLE", YELLOW)

    seal_status_display = seal_result.status
    if seal_result.status == "VALID":
        seal_status_display = colorize("VALID", GREEN)
    elif seal_result.status == "INVALID":
        seal_status_display = colorize("INVALID", RED)
    elif seal_result.status == "ABSENT":
        seal_status_display = colorize("ABSENT", YELLOW)

    lines = [
        "Verification receipt",
        f"Session: {chain_result.session_id or 'unknown'}",
        f"Trust: {trust_status(chain_status=chain_result.status, seal_status=seal_result.status)}",
        f"Chain: {chain_status_display}",
        f"Seal: {seal_status_display}",
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


def trust_status(*, chain_status: str, seal_status: str) -> str:
    if chain_status == "INTACT" and seal_status == "VALID":
        return colorize("VERIFIED", GREEN)
    if chain_status == "INTACT" and seal_status == "ABSENT":
        return colorize("UNVERIFIED (unsealed)", YELLOW)
    return colorize("REJECTED", RED)


def verification_exit_code(
    chain_result: Any,
    seal_result: SealVerificationResult,
) -> int:
    if chain_result.status == "ERROR":
        return 3
    if chain_result.status != "INTACT":
        return 2
    if seal_result.status == "INVALID":
        return 2
    return 0


def _parser_error(args: argparse.Namespace, message: str) -> None:
    parser = getattr(args, "parser", None)
    if parser is None:
        raise CLIError(message, exit_code=2)
    parser.error(message)


def _resolve_session_dir(args: argparse.Namespace) -> Path:
    positional = args.session_dir
    flagged = args.session_dir_flag
    if positional is None and flagged is None:
        _parser_error(args, "session_dir is required unless --session-dir is provided")

    if positional is not None and flagged is not None:
        positional_resolved = Path(positional).expanduser().resolve(strict=False)
        flagged_resolved = Path(flagged).expanduser().resolve(strict=False)
        if positional_resolved != flagged_resolved:
            _parser_error(
                args,
                "session_dir positional argument and --session-dir must resolve to the same path",
            )

    selected = positional if positional is not None else flagged
    return ensure_session_dir(Path(selected))


def _autodiscovered_input_path(
    *,
    session_dir: Path,
    filename: str,
    flag_name: str,
    label: str,
) -> Path:
    candidate = session_dir / filename
    if not candidate.exists():
        raise CLIError(
            f"Operational error: missing session-local {label}: {candidate}. "
            f"Use {flag_name} <path> to override.",
            exit_code=2,
        )
    if not candidate.is_file():
        raise CLIError(
            f"Operational error: session-local {label} is not a file: {candidate}. "
            f"Use {flag_name} <path> to override.",
            exit_code=2,
        )
    return candidate


def verify_session(
    session_dir: Path,
    *,
    contract_path: Path,
    public_key_path: Path,
) -> VerificationOutcome:
    contract = _load_contract(contract_path)
    public_key = _load_public_key(public_key_path)
    events_path = session_dir / "events.jsonl"
    chain_result = verify_chain(events_path, public_key, contract)
    seal_result = verify_seal(session_dir, public_key, contract)
    report = _build_report(
        chain_result,
        seal_status=seal_result.status,
        seal_reason=seal_result.error,
    )
    return VerificationOutcome(
        chain_result=chain_result,
        seal_result=seal_result,
        report=report,
    )


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = _resolve_session_dir(args)
        contract_path = (
            Path(args.contract)
            if args.contract is not None
            else _autodiscovered_input_path(
                session_dir=session_dir,
                filename="contract.json",
                flag_name="--contract",
                label="contract file",
            )
        )
        public_key_path = (
            Path(args.public_key)
            if args.public_key is not None
            else _autodiscovered_input_path(
                session_dir=session_dir,
                filename="public_key.pem",
                flag_name="--public-key",
                label="public key file",
            )
        )
        outcome = verify_session(
            session_dir,
            contract_path=contract_path,
            public_key_path=public_key_path,
        )
        print(_render_receipt(outcome.chain_result, outcome.seal_result))

        if args.json_out:
            write_json(Path(args.json_out), outcome.report, pretty=True, sort_keys=True)

        return verification_exit_code(outcome.chain_result, outcome.seal_result)
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
