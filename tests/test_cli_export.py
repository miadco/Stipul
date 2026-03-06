from __future__ import annotations

import json
from pathlib import Path

from tests.cli_support import create_signed_session, run_cli


def test_cli_export_writes_bundle_and_manifest(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    result = run_cli(
        "export",
        "--session-dir",
        str(artifacts.session_dir),
        "--out-dir",
        str(out_dir),
        "--contract",
        str(artifacts.contract_path),
        "--public-key",
        str(artifacts.keypair.public_key_path),
    )

    assert result.returncode == 0
    assert "Export complete" in result.stdout
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["missing_artifacts"] == []
    assert (out_dir / "events.jsonl").exists()


def test_cli_export_redact_uses_redacted_events_file(tmp_path: Path) -> None:
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
                "metadata": {"secret": "value"},
            }
        ],
    )
    out_dir = tmp_path / "bundle"

    result = run_cli(
        "export",
        "--session-dir",
        str(artifacts.session_dir),
        "--out-dir",
        str(out_dir),
        "--contract",
        str(artifacts.contract_path),
        "--redact",
    )

    assert result.returncode == 0
    assert (out_dir / "redacted_events.jsonl").exists()
    assert not (out_dir / "events.jsonl").exists()
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["missing_artifacts"] == [
        "decisions.jsonl",
        "public_key.pem",
        "summary.json",
    ]
