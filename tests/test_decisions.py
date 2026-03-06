from __future__ import annotations

from pathlib import Path
from typing import Any

from stipul.chronicle.signing.verifier import verify_decisions
from stipul.utils.canonical import canonical_json_bytes


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = [canonical_json_bytes(row).decode("utf-8") for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _events() -> list[dict[str, Any]]:
    return [
        {
            "sequence_id": 1,
            "event_type": "tool_call",
            "decision": "allow",
            "reason": "risk_class",
            "tool_name": "filesystem.write",
            "contract_id": "22222222-2222-2222-2222-222222222222",
            "contract_hash": "a" * 64,
        },
        {
            "sequence_id": 2,
            "event_type": "tool_call",
            "decision": "deny",
            "reason": "budget_exhausted",
            "tool_name": "filesystem.write",
            "contract_id": "22222222-2222-2222-2222-222222222222",
            "contract_hash": "a" * 64,
        },
    ]


def _decisions_projection() -> list[dict[str, Any]]:
    return [
        {
            "sequence_id": 1,
            "event_type": "tool_call",
            "decision": "allow",
            "reason": "risk_class",
            "tool_name": "filesystem.write",
            "contract_id": "22222222-2222-2222-2222-222222222222",
            "contract_hash": "a" * 64,
        },
        {
            "sequence_id": 2,
            "event_type": "tool_call",
            "decision": "deny",
            "reason": "budget_exhausted",
            "tool_name": "filesystem.write",
            "contract_id": "22222222-2222-2222-2222-222222222222",
            "contract_hash": "a" * 64,
        },
    ]


def test_decisions_not_generated(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    _write_jsonl(events_path, _events())

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "NOT_GENERATED"
    assert result.missing_from_decisions == []
    assert result.extra_in_decisions == []
    assert result.field_mismatches == []


def test_decisions_valid_projection(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    _write_jsonl(events_path, _events())
    _write_jsonl(decisions_path, _decisions_projection())

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "VALID"
    assert result.missing_from_decisions == []
    assert result.extra_in_decisions == []
    assert result.field_mismatches == []


def test_decisions_divergent_missing_entry(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    _write_jsonl(events_path, _events())
    _write_jsonl(decisions_path, _decisions_projection()[:1])

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "DIVERGENT"
    assert result.missing_from_decisions == [2]


def test_decisions_divergent_extra_entry(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    _write_jsonl(events_path, _events())
    rows = _decisions_projection()
    rows.append(
        {
            "sequence_id": 999,
            "event_type": "tool_call",
            "decision": "allow",
            "reason": "risk_class",
            "tool_name": "filesystem.write",
            "contract_id": "22222222-2222-2222-2222-222222222222",
            "contract_hash": "a" * 64,
        }
    )
    _write_jsonl(decisions_path, rows)

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "DIVERGENT"
    assert result.extra_in_decisions == [999]


def test_decisions_divergent_contract_hash_mismatch(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    _write_jsonl(events_path, _events())
    rows = _decisions_projection()
    rows[1]["contract_hash"] = "b" * 64
    _write_jsonl(decisions_path, rows)

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "DIVERGENT"
    assert result.field_mismatches == [(2, "contract_hash")]


def test_budget_exhausted_denial_present_in_projection(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    events = _events()
    _write_jsonl(events_path, events)
    _write_jsonl(decisions_path, _decisions_projection())

    result = verify_decisions(events_path, decisions_path)
    assert result.status == "VALID"
    assert any(event["reason"] == "budget_exhausted" for event in events)
