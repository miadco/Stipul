from __future__ import annotations

import copy
import json
from pathlib import Path

from tests.cli_support import load_base_contract_dict, run_cli, write_contract_file


def _write_events(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_cli_simulate_reports_changed_count_and_json(tmp_path: Path) -> None:
    payload = load_base_contract_dict()
    payload["allowed_tools"] = ["web.search"]
    payload["tool_risk_classes"] = {"web.search": "read"}
    contract_path, _ = write_contract_file(tmp_path, payload)
    events_path = tmp_path / "events.jsonl"
    _write_events(
        events_path,
        [
            {
                "sequence_id": 1,
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ],
    )
    json_out = tmp_path / "simulate.json"

    result = run_cli(
        "simulate",
        "--events",
        str(events_path),
        "--contract",
        str(contract_path),
        "--json-out",
        str(json_out),
    )

    assert result.returncode == 0
    assert "Simulation Results" in result.stdout
    assert "Changed: 1" in result.stdout
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["changed_count"] == 1
    assert report["records"][0]["simulated_decision"] == "deny"


def test_cli_diff_reports_only_changed_records(tmp_path: Path) -> None:
    payload_a = load_base_contract_dict()
    payload_b = copy.deepcopy(payload_a)
    payload_b["tool_risk_classes"]["filesystem.write"] = "irreversible"
    contract_a_path, _ = write_contract_file(tmp_path / "a", payload_a)
    contract_b_path, _ = write_contract_file(tmp_path / "b", payload_b)
    events_path = tmp_path / "events.jsonl"
    _write_events(
        events_path,
        [
            {
                "sequence_id": 1,
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            },
            {
                "sequence_id": 2,
                "timestamp": "2026-01-01T00:00:02Z",
                "event_type": "tool_call",
                "tool_name": "web.search",
                "decision": "allow",
                "reason": "risk_class",
            },
        ],
    )
    json_out = tmp_path / "diff.json"

    result = run_cli(
        "diff",
        "--events",
        str(events_path),
        "--contract-a",
        str(contract_a_path),
        "--contract-b",
        str(contract_b_path),
        "--json-out",
        str(json_out),
    )

    assert result.returncode == 0
    assert "Simulation Diff" in result.stdout
    assert "Changed: 1" in result.stdout
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["changed_count"] == 1
    assert len(report["records"]) == 1
    assert report["records"][0]["tool_name"] == "filesystem.write"


def test_cli_simulate_returns_fatal_for_missing_input(tmp_path: Path) -> None:
    contract_path, _ = write_contract_file(tmp_path)

    result = run_cli(
        "simulate",
        "--events",
        str(tmp_path / "missing.jsonl"),
        "--contract",
        str(contract_path),
    )

    assert result.returncode == 3
    assert "Events file not found" in result.stderr
