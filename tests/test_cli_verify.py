from __future__ import annotations

import json
from pathlib import Path

from tests.cli_support import create_signed_session, run_cli


def _rewrite_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_verify_succeeds_for_intact_chain(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True)
    report_path = tmp_path / "verify.json"

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Decision projection" not in result.stdout

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["signed_event_count"] == 2
    assert report["unsigned_count"] == 0
    assert "decisions_valid" not in report


def test_verify_reports_broken_chain_at_first_failure(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path)
    rows = _read_jsonl(artifacts.events_path)
    rows[1]["reason"] = "tampered_without_resign"
    _rewrite_jsonl(artifacts.events_path, rows)

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
    )

    assert result.returncode == 2
    assert "Chain integrity: BROKEN" in result.stdout
    assert "First failure: sequence_id 2" in result.stdout
    assert "Decision projection" not in result.stdout


def test_verify_reports_unverifiable_chain(tmp_path: Path) -> None:
    artifacts = create_signed_session(
        tmp_path,
        event_specs=[
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
            {
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "risk_class": "write",
                "decision": "deny",
                "reason": "not_in_contract",
                "agent_identity": "b" * 64,
                "input_hash": "e" * 64,
            },
        ],
    )
    raw_lines = artifacts.events_path.read_text(encoding="utf-8").splitlines()
    raw_lines[1] = "{bad_json"
    artifacts.events_path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
    )

    assert result.returncode == 2
    assert "Chain integrity: UNVERIFIABLE" in result.stdout
    assert "Chain verifiable up to sequence_id 1." in result.stdout
    assert "Decision projection" not in result.stdout


def test_verify_ignores_missing_decisions_file(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=False)

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Decision projection" not in result.stdout


def test_verify_ignores_tampered_decisions_projection(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True)
    decisions = _read_jsonl(artifacts.decisions_path)
    decisions[0]["reason"] = "tampered"
    _rewrite_jsonl(artifacts.decisions_path, decisions)

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Decision projection" not in result.stdout
