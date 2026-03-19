from __future__ import annotations

import hashlib
import json
from pathlib import Path

from stipul.seal.siem_export import SiemExportFilters, export_siem_jsonl, siem_manifest_path


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _event(
    *,
    sequence_id: int,
    timestamp: str,
    event_type: str,
    tool_name: str,
    decision: str,
    reason: str,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "sequence_id": sequence_id,
        "timestamp": timestamp,
        "session_id": "11111111-1111-1111-1111-111111111111",
        "event_type": event_type,
        "tool_name": tool_name,
        "risk_class": "write",
        "decision": decision,
        "reason": reason,
        "contract_id": "2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f",
        "contract_hash": "a" * 64,
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": "d" * 64,
        "signature": "c2lnbmF0dXJl",
    }
    if metadata is not None:
        payload["metadata"] = metadata
    return payload


def test_siem_export_flattens_metadata_and_writes_manifest(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    events_path = session_dir / "events.jsonl"
    _write_jsonl(
        events_path,
        [
            _event(
                sequence_id=1,
                timestamp="2026-01-01T00:00:01Z",
                event_type="tool_call",
                tool_name="filesystem.write",
                decision="allow",
                reason="risk_class",
                metadata={
                    "ingress": "mcp_gateway",
                    "approval_context": {
                        "request_id": "req-1",
                        "approver_ids": ["a" * 64, "b" * 64],
                    },
                    "nested": {"code": "alpha"},
                },
            )
        ],
    )
    out_path = tmp_path / "siem.jsonl"

    manifest = export_siem_jsonl(session_dir, out_path)

    rows = _read_jsonl(out_path)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "tool_call"
    assert rows[0]["decision"] == "allow"
    assert rows[0]["metadata_ingress"] == "mcp_gateway"
    assert rows[0]["metadata_approval_context_request_id"] == "req-1"
    assert rows[0]["metadata_approval_context_approver_ids"] == ["a" * 64, "b" * 64]
    assert rows[0]["metadata_nested_code"] == "alpha"
    assert "metadata" not in rows[0]

    expected_sha = hashlib.sha256(events_path.read_bytes()).hexdigest()
    assert manifest["source_events_sha256"] == expected_sha
    assert manifest["source_session_id"] == "11111111-1111-1111-1111-111111111111"
    assert manifest["source_contract_hash"] == "a" * 64
    assert manifest["exported_event_count"] == 1
    assert siem_manifest_path(out_path).exists()


def test_siem_export_applies_filters_deterministically(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    events_path = session_dir / "events.jsonl"
    _write_jsonl(
        events_path,
        [
            _event(
                sequence_id=1,
                timestamp="2026-01-01T00:00:01Z",
                event_type="tool_call",
                tool_name="filesystem.write",
                decision="allow",
                reason="risk_class",
                metadata={"ingress": "mcp_gateway"},
            ),
            _event(
                sequence_id=2,
                timestamp="2026-01-01T00:00:02Z",
                event_type="net_call",
                tool_name="filesystem.write",
                decision="deny",
                reason="not_in_egress_allowlist",
            ),
            _event(
                sequence_id=3,
                timestamp="2026-01-01T00:00:03Z",
                event_type="tool_call",
                tool_name="web.search",
                decision="allow",
                reason="risk_class",
                metadata={"ingress": "other_ingress"},
            ),
        ],
    )
    out_path = tmp_path / "filtered.jsonl"

    manifest = export_siem_jsonl(
        session_dir,
        out_path,
        filters=SiemExportFilters.create(
            event_type="tool_call",
            decision="allow",
            ingress="mcp_gateway",
            since="2026-01-01T00:00:01Z",
            until="2026-01-01T00:00:02Z",
        ),
    )

    rows = _read_jsonl(out_path)
    assert [row["sequence_id"] for row in rows] == [1]
    assert manifest["applied_filters"] == {
        "event_type": "tool_call",
        "decision": "allow",
        "ingress": "mcp_gateway",
        "since": "2026-01-01T00:00:01Z",
        "until": "2026-01-01T00:00:02Z",
    }
    assert manifest["exported_at"] == "2026-01-01T00:00:01Z"


def test_siem_export_preserves_authoritative_source_file(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    events_path = session_dir / "events.jsonl"
    _write_jsonl(
        events_path,
        [
            _event(
                sequence_id=1,
                timestamp="2026-01-01T00:00:01Z",
                event_type="elev_op",
                tool_name="__operator__",
                decision="allow",
                reason="operator_kill_switch_enabled",
                metadata={"updated_by": "operator@example.com"},
            )
        ],
    )
    original_bytes = events_path.read_bytes()

    export_siem_jsonl(session_dir, tmp_path / "siem.jsonl")

    assert events_path.read_bytes() == original_bytes
