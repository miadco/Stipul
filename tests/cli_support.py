from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.decisions import generate_decisions, write_decisions
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.events.summary import build_summary, write_summary_json
from stipul.chronicle.signing.keys import RuntimeKeyPair, generate_keypair


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "base_contract.json"
DEFAULT_SESSION_ID = "11111111-1111-1111-1111-111111111111"


class _ChainOk:
    status = "INTACT"
    first_failure_sequence_id = None


CHAIN_OK = _ChainOk()


@dataclass(frozen=True)
class SessionArtifacts:
    session_dir: Path
    contract_path: Path
    session_contract_path: Path
    contract: Contract
    keypair: RuntimeKeyPair
    session_public_key_path: Path
    events_path: Path
    decisions_path: Path
    summary_path: Path


def load_base_contract_dict() -> dict[str, Any]:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("base contract fixture must be a JSON object")
    return payload


def write_contract_file(tmp_path: Path, payload: dict[str, Any] | None = None) -> tuple[Path, Contract]:
    contract_payload = dict(payload or load_base_contract_dict())
    contract_path = tmp_path / "contract.json"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_text(
        json.dumps(contract_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return contract_path, Contract.from_dict(contract_payload)


def create_signed_session(
    tmp_path: Path,
    *,
    event_specs: list[dict[str, Any]] | None = None,
    include_decisions: bool = False,
    include_summary: bool = False,
) -> SessionArtifacts:
    contract_path, contract = write_contract_file(tmp_path)
    session_dir = tmp_path / "session"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_contract_path = session_dir / "contract.json"
    events_path = session_dir / "events.jsonl"
    session_public_key_path = session_dir / "public_key.pem"
    decisions_path = session_dir / "decisions.jsonl"
    summary_path = session_dir / "summary.json"
    keypair = generate_keypair(tmp_path / ".stipul" / "keys")

    session_contract_path.write_text(
        json.dumps(contract.to_canonical_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    session_public_key_path.write_bytes(
        keypair.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    logger = EventLogger(
        store=EventStore(events_path),
        session_id=DEFAULT_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=session_dir,
    )
    for spec in event_specs or _default_event_specs():
        logger.log_event(spec)

    if include_decisions:
        write_decisions(generate_decisions(events_path), decisions_path)

    if include_summary:
        session_start = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        session_end = session_start + timedelta(minutes=5)
        tool_calls = sum(1 for spec in event_specs or _default_event_specs() if spec["event_type"] == "tool_call")
        net_calls = sum(1 for spec in event_specs or _default_event_specs() if spec["event_type"] == "net_call")
        summary = build_summary(
            events_path=events_path,
            contract=contract,
            session_id=DEFAULT_SESSION_ID,
            session_start=session_start,
            session_end=session_end,
            chain_result=CHAIN_OK,
            budget_consumed={"tool_calls": float(tool_calls), "net_calls": float(net_calls)},
        )
        write_summary_json(summary, summary_path)

    return SessionArtifacts(
        session_dir=session_dir,
        contract_path=contract_path,
        session_contract_path=session_contract_path,
        contract=contract,
        keypair=keypair,
        session_public_key_path=session_public_key_path,
        events_path=events_path,
        decisions_path=decisions_path,
        summary_path=summary_path,
    )


def _default_event_specs() -> list[dict[str, Any]]:
    return [
        {
            "event_type": "tool_call",
            "tool_name": "filesystem.write",
            "risk_class": "write",
            "decision": "allow",
            "reason": "risk_class",
            "agent_identity": "b" * 64,
            "input_hash": "c" * 64,
        },
        {
            "event_type": "tool_call",
            "tool_name": "web.search",
            "risk_class": "read",
            "decision": "allow",
            "reason": "risk_class",
            "agent_identity": "b" * 64,
            "input_hash": "d" * 64,
        },
    ]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "stipul.cli.main", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
