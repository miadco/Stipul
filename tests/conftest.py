import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from agentshield.contract.schema import Contract
from agentshield.engine.policy import RuntimeState
from agentshield.models import RiskClass

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "base_contract.json"


@pytest.fixture
def base_dict() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


@pytest.fixture
def contract(base_dict) -> Contract:
    return Contract.from_dict(base_dict)


def make_state(contract: Contract, **overrides) -> RuntimeState:
    """Build a RuntimeState defaulting to a valid, non-expired session for the given contract."""
    defaults = dict(
        tool_calls_made=0,
        net_calls_made=0,
        current_time=datetime(2030, 1, 1, tzinfo=timezone.utc),
        requesting_agent_id=contract.identity_agent_id,
        egress_target=None,
    )
    return RuntimeState(**{**defaults, **overrides})


def pick_read_tool(contract: Contract) -> str:
    """Return the first tool in allowed_tools with risk RiskClass.read."""
    for t, r in contract.tool_risk_classes.items():
        if r == RiskClass.read and t in contract.allowed_tools:
            return t
    raise ValueError("Fixture has no read-risk tool in allowed_tools")


def pick_write_tool(contract: Contract) -> str:
    """Return the first tool in allowed_tools with effective risk RiskClass.write."""
    for t in contract.allowed_tools:
        if contract.tool_risk_classes.get(t, RiskClass.write) == RiskClass.write:
            return t
    raise ValueError("Fixture has no write-risk tool in allowed_tools")


@pytest.fixture
def make_test_events(tmp_path: Path) -> Callable[[list[dict[str, Any]]], Path]:
    """
    Create unsigned JSONL events with stable defaults for derivation-focused tests.

    These fixtures intentionally use fake signatures and prev_hash values.
    Do not use outputs from this helper with the chain verifier; use a signed
    chain fixture backed by EventLogger.log_event(...) for chain-integrity tests.
    """
    counter = 0

    def _make(specs: list[dict[str, Any]]) -> Path:
        nonlocal counter
        counter += 1
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        default_signature = base64.b64encode(b"test-signature").decode("ascii")
        rows: list[dict[str, Any]] = []
        for index, overrides in enumerate(specs, start=1):
            row = {
                "sequence_id": index,
                "timestamp": (base_time + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "session_id": "11111111-1111-1111-1111-111111111111",
                "event_type": "tool_call",
                "tool_name": "tool.default",
                "risk_class": "read",
                "decision": "allow",
                "reason": "risk_class",
                "contract_id": "2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f",
                "contract_hash": "a" * 64,
                "agent_identity": "b" * 64,
                "input_hash": "c" * 64,
                "key_id": "deadbeef",
                "algorithm": "ed25519",
                "key_created_at": "2026-01-01T00:00:00Z",
                "prev_hash": "0" * 64,
                "signature": default_signature,
                "metadata": None,
            }
            if "drop_decision" in overrides:
                overrides = dict(overrides)
                overrides.pop("drop_decision")
                row.pop("decision", None)
            row.update(overrides)
            rows.append(row)

        events_path = tmp_path / f"events_{counter}.jsonl"
        with events_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return events_path

    return _make
