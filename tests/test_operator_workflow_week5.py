from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentshield.contract.schema import Contract
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.decisions import generate_decisions, write_decisions
from agentshield.events.logger import EventLogger
from agentshield.events.store import EventStore
from agentshield.events.summary import build_summary, write_summary_json
from agentshield.signing.keys import generate_keypair
from tests.cli_support import DEFAULT_SESSION_ID, load_base_contract_dict, run_cli


class _ChainOk:
    status = "INTACT"
    first_failure_sequence_id = None


def test_operator_workflow_week5(tmp_path: Path) -> None:
    contract_payload = load_base_contract_dict()
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        json.dumps(contract_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    contract = Contract.from_dict(contract_payload)
    session_dir = tmp_path / "session"
    events_path = session_dir / "events.jsonl"
    decisions_path = session_dir / "decisions.jsonl"
    summary_path = session_dir / "summary.json"
    keypair = generate_keypair(tmp_path / ".agentshield" / "keys")

    logger = EventLogger(
        store=EventStore(events_path),
        session_id=DEFAULT_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=session_dir,
    )
    logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "filesystem.write",
            "risk_class": "write",
            "decision": "allow",
            "reason": "risk_class",
            "agent_identity": "b" * 64,
            "input_hash": "c" * 64,
        }
    )
    logger.log_event(
        {
            "event_type": "tool_call",
            "tool_name": "web.search",
            "risk_class": "read",
            "decision": "allow",
            "reason": "risk_class",
            "agent_identity": "b" * 64,
            "input_hash": "d" * 64,
        }
    )

    decisions = generate_decisions(events_path)
    write_decisions(decisions, decisions_path)

    session_start = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    session_end = session_start + timedelta(minutes=5)
    summary = build_summary(
        events_path=events_path,
        contract=contract,
        session_id=DEFAULT_SESSION_ID,
        session_start=session_start,
        session_end=session_end,
        chain_result=_ChainOk(),
        budget_consumed={"tool_calls": 2.0, "net_calls": 0.0},
    )
    write_summary_json(summary, summary_path)

    lint_result = run_cli("lint-contract", "--contract", str(contract_path))
    assert lint_result.returncode == 0

    verify_result = run_cli(
        "verify",
        "--session-dir",
        str(session_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(keypair.public_key_path),
    )
    assert verify_result.returncode == 0

    bundle_dir = tmp_path / "bundle"
    export_result = run_cli(
        "export",
        "--session-dir",
        str(session_dir),
        "--out-dir",
        str(bundle_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(keypair.public_key_path),
    )
    assert export_result.returncode == 0

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    for filename, digest in manifest["hashes"].items():
        exported_path = bundle_dir / filename
        assert exported_path.exists()
        assert hashlib.sha256(exported_path.read_bytes()).hexdigest() == digest

    exported_verify_result = run_cli(
        "verify",
        "--session-dir",
        str(bundle_dir),
        "--contract",
        str(bundle_dir / "contract.json"),
        "--public-key",
        str(bundle_dir / "public_key.pem"),
    )
    assert exported_verify_result.returncode == 0
