from __future__ import annotations

import json
from pathlib import Path

import pytest

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.writ.proxy.server import ProxyServer

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _build_proxy(contract: Contract, events_path: Path) -> ProxyServer:
    keypair = generate_keypair(events_path.parent / ".stipul" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=events_path.parent,
    )
    return ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=_SESSION_ID,
        passthrough=True,
    )


def test_missing_operator_state_file_defaults_inactive(tmp_path: Path, contract: Contract) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
        forward_call,
    )

    assert response == {"ok": True}
    assert called["count"] == 1

    payload = proxy.health.payload()
    assert payload["kill_switch_active"] is False
    assert payload["operator_updated_at"] is None
    assert payload["operator_updated_by"] is None
    assert payload["operator_reason"] is None


@pytest.mark.parametrize(
    ("name", "raw_payload"),
    [
        ("malformed_json", "{"),
        (
            "missing_field",
            json.dumps(
                {
                    "kill_switch_active": True,
                    "updated_at": "2026-03-07T17:00:00Z",
                    "reason": "operator_kill_switch_enabled",
                }
            ),
        ),
        (
            "invalid_type",
            json.dumps(
                {
                    "kill_switch_active": "true",
                    "updated_at": "2026-03-07T17:00:00Z",
                    "updated_by": "e" * 64,
                    "reason": "operator_kill_switch_enabled",
                }
            ),
        ),
        (
            "partial_corrupt",
            '{"kill_switch_active":true,"updated_at":"2026-03-07T17:00:00Z"',
        ),
    ],
)
def test_invalid_operator_state_denies_without_execution(
    tmp_path: Path,
    contract: Contract,
    name: str,
    raw_payload: str,
) -> None:
    events_path = tmp_path / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    (tmp_path / "operator_state.json").write_text(raw_payload, encoding="utf-8")

    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": f"{name}.txt", "content": "x"}},
        forward_call,
    )

    assert response == {
        "decision": "deny",
        "reason": "proxy_degraded",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0

    events = _read_events(events_path)
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "proxy_degraded"
