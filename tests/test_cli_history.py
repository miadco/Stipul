from __future__ import annotations

import argparse
import json
from pathlib import Path

from stipul.cli import history_cmd
from tests.cli_support import run_cli

_SESSION_A = "11111111-1111-1111-1111-111111111111"
_SESSION_B = "22222222-2222-2222-2222-222222222222"
_CONTRACT_ID = "33333333-3333-3333-3333-333333333333"


def _event(
    sequence_id: int,
    timestamp: str,
    *,
    session_id: str,
    event_type: str,
    tool_name: str,
    risk_class: str,
    decision: str,
    reason: str,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "sequence_id": sequence_id,
        "timestamp": timestamp,
        "session_id": session_id,
        "event_type": event_type,
        "tool_name": tool_name,
        "risk_class": risk_class,
        "decision": decision,
        "reason": reason,
        "contract_id": _CONTRACT_ID,
        "contract_hash": "a" * 64,
        "agent_identity": "b" * 64,
        "input_hash": f"{sequence_id:064x}",
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": "d" * 64,
        "signature": "c2lnbg==",
    }
    if metadata is not None:
        payload["metadata"] = metadata
    return payload


def _write_events(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def test_cli_history_renders_grouped_human_timeline(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    _write_events(
        events_path,
        [
            _event(
                1,
                "2026-03-10T00:00:00Z",
                session_id=_SESSION_A,
                event_type="tool_call",
                tool_name="filesystem.read",
                risk_class="read",
                decision="allow",
                reason="risk_class",
                metadata={"path": "notes.txt"},
            ),
            _event(
                2,
                "2026-03-10T00:01:00Z",
                session_id=_SESSION_A,
                event_type="elev_op",
                tool_name="__operator__",
                risk_class="write",
                decision="allow",
                reason="operator_kill_switch_enabled",
                metadata={
                    "kill_switch_active": True,
                    "updated_by": "operator@example.com",
                    "updated_at": "2026-03-10T00:01:00Z",
                    "reason": "operator_kill_switch_enabled",
                },
            ),
            _event(
                3,
                "2026-03-10T00:02:00Z",
                session_id=_SESSION_A,
                event_type="tool_call",
                tool_name="delete_file",
                risk_class="irreversible",
                decision="deny",
                reason="kill_switch_active",
                metadata={
                    "kill_switch_active": True,
                    "operator_reason": "operator_kill_switch_enabled",
                    "operator_updated_by": "operator@example.com",
                },
            ),
            _event(
                4,
                "2026-03-10T00:03:00Z",
                session_id=_SESSION_A,
                event_type="budget_exhausted",
                tool_name="__budget__",
                risk_class="write",
                decision="deny",
                reason="budget_exhausted",
                metadata={"exhausted_dimension": "tool_calls"},
            ),
            _event(
                5,
                "2026-03-10T00:04:00Z",
                session_id=_SESSION_B,
                event_type="budget_anomaly",
                tool_name="__budget__",
                risk_class="write",
                decision="allow",
                reason="budget_anomaly",
                metadata={"dimension": "net_calls", "burn_rate": 2.5},
            ),
            _event(
                6,
                "2026-03-10T00:05:00Z",
                session_id=_SESSION_B,
                event_type="net_call",
                tool_name="web.fetch",
                risk_class="exfil-risk",
                decision="deny",
                reason="not_in_egress_allowlist",
                metadata={"egress_target": "evil.example.org"},
            ),
            _event(
                7,
                "2026-03-10T00:06:00Z",
                session_id=_SESSION_B,
                event_type="write_op",
                tool_name="filesystem.delete",
                risk_class="irreversible",
                decision="require_approval",
                reason="approval_required",
                metadata={
                    "path": "secrets.txt",
                    "approval_context": {"request_id": "req-7"},
                },
            ),
        ],
    )

    result = run_cli("history", "--events", str(events_path))

    assert result.returncode == 0
    assert f"Session {_SESSION_A}" in result.stdout
    assert "Agent called filesystem.read - allowed within allowed risk class" in result.stdout
    assert "target: notes.txt" in result.stdout
    assert "Kill switch enabled by operator@example.com" in result.stdout
    assert "Agent attempted delete_file - denied because kill switch was active" in result.stdout
    assert "Budget exhausted for tool calls - denied because budget was exhausted" in result.stdout
    assert f"Session {_SESSION_B}" in result.stdout
    assert "Budget anomaly detected for net calls - allowed after unusual budget burn was detected" in result.stdout
    assert "burn rate: 2.50x" in result.stdout
    assert (
        "Agent attempted network call via web.fetch - denied because the target was not in the egress allowlist"
        in result.stdout
    )
    assert "target: evil.example.org" in result.stdout
    assert "Agent attempted write via filesystem.delete - approval required because approval was required" in result.stdout
    assert "request: req-7" in result.stdout


def test_cli_history_filters_session_and_applies_recent_limit(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    _write_events(
        events_path,
        [
            _event(
                1,
                "2026-03-10T00:00:00Z",
                session_id=_SESSION_A,
                event_type="tool_call",
                tool_name="filesystem.read",
                risk_class="read",
                decision="allow",
                reason="risk_class",
            ),
            _event(
                2,
                "2026-03-10T00:01:00Z",
                session_id=_SESSION_B,
                event_type="tool_call",
                tool_name="filesystem.write",
                risk_class="write",
                decision="deny",
                reason="not_in_contract",
            ),
            _event(
                3,
                "2026-03-10T00:02:00Z",
                session_id=_SESSION_A,
                event_type="net_call",
                tool_name="web.fetch",
                risk_class="exfil-risk",
                decision="deny",
                reason="not_in_egress_allowlist",
                metadata={"egress_target": "evil.example.org"},
            ),
        ],
    )

    result = run_cli(
        "history",
        "--events",
        str(events_path),
        "--session-id",
        _SESSION_A,
        "--limit",
        "1",
    )

    assert result.returncode == 0
    assert result.stdout.count("Session ") == 1
    assert f"Session {_SESSION_A}" in result.stdout
    assert "filesystem.read" not in result.stdout
    assert "filesystem.write" not in result.stdout
    assert "Agent attempted network call via web.fetch - denied" in result.stdout


def test_cli_history_defaults_to_events_jsonl_in_current_directory(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    _write_events(
        tmp_path / "events.jsonl",
        [
            _event(
                1,
                "2026-03-10T00:00:00Z",
                session_id=_SESSION_A,
                event_type="tool_call",
                tool_name="filesystem.read",
                risk_class="read",
                decision="allow",
                reason="risk_class",
            )
        ],
    )
    monkeypatch.chdir(tmp_path)

    args = argparse.Namespace(events="events.jsonl", session_id=None, limit=None)

    assert history_cmd.run(args) == 0
    assert "Agent called filesystem.read - allowed" in capsys.readouterr().out
