#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stipul.charter.contract.loader import load_charter
from stipul.chronicle.signing.verifier import print_verification_result, verify_chain
from stipul.cli.history_cmd import _load_canonical_events, _render_history
from stipul.seal.verifier import verify_seal
from stipul.writ.proxy.server import ProxyServer

SESSION_ID = "11111111-1111-1111-1111-111111111111"
CHARTER_PATH = Path(__file__).parent / "demo-charter.yaml"
CHARTER_LABEL = "demo/demo-charter.yaml"


@contextmanager
def _suppress_startup_warning() -> Any:
    logger = logging.getLogger("stipul.writ.proxy.startup")
    previous_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(previous_level)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Public key is not Ed25519: {path}")
    return key


def _run_step(
    proxy: ProxyServer,
    *,
    step_number: int,
    tool_name: str,
    description: str,
    raw_request: Mapping[str, Any],
    forward_call: Callable[[Mapping[str, Any]], Any],
    approval_note: bool = False,
) -> None:
    print(f"─── Step {step_number}: {tool_name} ───")
    print(f"Request: {description}")
    print("Response:")
    try:
        response = proxy.handle_tool_call(raw_request, forward_call)
        print(response)
        if approval_note:
            print("Approval request created — pending operator review")
    except Exception as exc:  # pragma: no cover - demo resilience
        print(f"ERROR: {exc}")


def _render_evidence(events_path: Path) -> str:
    events = _load_canonical_events(events_path)
    return _render_history(events, session_id=None, limit=None)


def _print_proof(
    *,
    contract_path: Path,
    events_path: Path,
    session_dir: Path,
    public_key_path: Path,
) -> None:
    contract = load_charter(contract_path).contract
    public_key = _load_public_key(public_key_path)
    chain_result = verify_chain(events_path, public_key, contract)
    seal_result = verify_seal(session_dir, public_key, contract)
    print(print_verification_result(chain_result))
    print(f"Seal: {seal_result.status}")


def main() -> None:
    clean = "--clean" in sys.argv[1:]

    print("═══ Stipul Local Enforcement Demo ═══")
    print(f"Charter: {CHARTER_LABEL}")
    print()
    print("═══ Actions ═══")

    demo_root = Path(tempfile.mkdtemp(prefix="stipul-local-demo-"))
    session_dir = demo_root / "session"
    events_path = session_dir / "events.jsonl"
    session_dir.mkdir(parents=True, exist_ok=True)

    previous_home = os.environ.get("HOME")
    previous_token_secret = os.environ.get("STIPUL_TOKEN_SECRET")

    proxy: ProxyServer | None = None
    public_key_path: Path | None = None
    close_error: Exception | None = None

    try:
        os.environ["HOME"] = str(demo_root)
        os.environ["STIPUL_TOKEN_SECRET"] = "demo-secret"

        with _suppress_startup_warning():
            proxy = ProxyServer.from_contract_path(
                CHARTER_PATH,
                session_id=SESSION_ID,
                events_path=events_path,
            )
        public_key_path = proxy.event_logger.signing_key.public_key_path

        _run_step(
            proxy,
            step_number=1,
            tool_name="filesystem.read",
            description="read notes.txt",
            raw_request={
                "tool_name": "filesystem.read",
                "inputs": {"path": "notes.txt"},
                "metadata": {"path": "notes.txt"},
            },
            forward_call=lambda _request: {"ok": True, "content": "meeting notes..."},
        )

        _run_step(
            proxy,
            step_number=2,
            tool_name="web.search",
            description="search for sensitive data via evil.example.com",
            raw_request={
                "tool_name": "web.search",
                "inputs": {
                    "query": "sensitive data",
                    "egress_target": "evil.example.com",
                },
                "metadata": {"egress_target": "evil.example.com"},
            },
            forward_call=lambda _request: {"ok": True},
        )

        _run_step(
            proxy,
            step_number=3,
            tool_name="filesystem.delete",
            description="delete archive.tar",
            raw_request={
                "tool_name": "filesystem.delete",
                "inputs": {"path": "archive.tar"},
                "metadata": {"path": "archive.tar"},
            },
            forward_call=lambda _request: {"ok": True},
            approval_note=True,
        )
    finally:
        if proxy is not None:
            try:
                proxy.close()
            except Exception as exc:  # pragma: no cover - demo resilience
                close_error = exc

    print()
    print("═══ Evidence: Chronicle ═══")
    try:
        print(_render_evidence(events_path))
    except Exception as exc:  # pragma: no cover - demo resilience
        print(f"ERROR: {exc}")

    print()
    print("═══ Proof: Verification ═══")
    try:
        if public_key_path is None:
            raise RuntimeError("public key path unavailable")
        _print_proof(
            contract_path=CHARTER_PATH,
            events_path=events_path,
            session_dir=session_dir,
            public_key_path=public_key_path,
        )
        if close_error is not None:
            print(f"ERROR: {close_error}")
    except Exception as exc:  # pragma: no cover - demo resilience
        print(f"ERROR: {exc}")

    print()
    if clean:
        print(f"Evidence directory: {session_dir}")
        print("Cleaning up temporary demo files")
    else:
        print(f"Preserved evidence directory: {session_dir}")

    if previous_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = previous_home

    if previous_token_secret is None:
        os.environ.pop("STIPUL_TOKEN_SECRET", None)
    else:
        os.environ["STIPUL_TOKEN_SECRET"] = previous_token_secret

    if clean:
        shutil.rmtree(demo_root, ignore_errors=True)

    print("═══ Demo complete ═══")


if __name__ == "__main__":
    main()
