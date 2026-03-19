from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from stipul.cli import export_cmd
from stipul.cli.io import CLIError
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


def test_cli_export_siem_out_writes_filtered_jsonl_and_manifest_from_yaml_contract(
    tmp_path: Path,
) -> None:
    contract_payload = json.loads((Path(__file__).parent / "fixtures" / "base_contract.json").read_text(encoding="utf-8"))
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(yaml.safe_dump(contract_payload, sort_keys=False), encoding="utf-8")
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
                "metadata": {
                    "ingress": "mcp_gateway",
                    "approval_context": {"request_id": "req-1"},
                },
            },
            {
                "event_type": "elev_op",
                "tool_name": "__operator__",
                "risk_class": "write",
                "decision": "allow",
                "reason": "operator_kill_switch_enabled",
                "agent_identity": "b" * 64,
                "input_hash": "d" * 64,
                "metadata": {"updated_by": "operator@example.com"},
            },
        ],
        include_decisions=True,
        include_summary=True,
    )
    out_dir = tmp_path / "bundle"
    siem_out = tmp_path / "siem.jsonl"

    result = run_cli(
        "export",
        "--session-dir",
        str(artifacts.session_dir),
        "--out-dir",
        str(out_dir),
        "--contract",
        str(contract_path),
        "--siem-out",
        str(siem_out),
        "--decision",
        "allow",
        "--ingress",
        "mcp_gateway",
    )

    assert result.returncode == 0
    assert "SIEM JSONL" in result.stdout
    assert (out_dir / "events.jsonl").exists()
    assert siem_out.exists()

    siem_rows = [
        json.loads(line)
        for line in siem_out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(siem_rows) == 1
    assert siem_rows[0]["tool_name"] == "filesystem.write"
    assert siem_rows[0]["metadata_ingress"] == "mcp_gateway"
    assert siem_rows[0]["metadata_approval_context_request_id"] == "req-1"

    siem_manifest_path = siem_out.with_suffix(".manifest.json")
    siem_manifest = json.loads(siem_manifest_path.read_text(encoding="utf-8"))
    assert siem_manifest["source_events_sha256"] == hashlib.sha256(
        artifacts.events_path.read_bytes()
    ).hexdigest()
    assert siem_manifest["applied_filters"] == {
        "decision": "allow",
        "event_type": None,
        "ingress": "mcp_gateway",
        "since": None,
        "until": None,
    }


def test_cli_export_timestamp_rfc3161_reports_receipt_details(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"
    captured: dict[str, object] = {}

    def fake_timestamp_export_bundle_rfc3161(bundle_dir: Path, tsa_url: str) -> dict[str, object]:
        captured["bundle_dir"] = bundle_dir
        captured["tsa_url"] = tsa_url
        return {
            "tsa_url": tsa_url,
            "manifest_path": str((bundle_dir / "manifest.json").resolve()),
            "anchored_top_level_sha256": "a" * 64,
            "message_imprint_algorithm": "sha256",
            "message_imprint_hex": "a" * 64,
            "receipt_content_type": "application/timestamp-reply",
            "timestamp_token_der_base64": "ZGVtbw==",
            "tsa_gen_time": "2026-01-01T00:00:01Z",
            "serial_number": "123",
            "policy": "1.2.3.4.5",
        }

    monkeypatch.setattr(
        export_cmd,
        "timestamp_export_bundle_rfc3161",
        fake_timestamp_export_bundle_rfc3161,
    )

    args = argparse.Namespace(
        session_dir=str(artifacts.session_dir),
        out_dir=str(out_dir),
        contract=str(artifacts.contract_path),
        public_key=str(artifacts.keypair.public_key_path),
        scan_report=None,
        redact=False,
        siem_out=None,
        event_type=None,
        decision=None,
        ingress=None,
        since=None,
        until=None,
        timestamp_rfc3161="https://tsa.example",
    )

    result = export_cmd.run(args)

    stdout = capsys.readouterr().out
    assert result == 0
    assert captured["bundle_dir"] == out_dir
    assert captured["tsa_url"] == "https://tsa.example"
    assert "Export complete" in stdout
    assert "RFC 3161 TSA: https://tsa.example" in stdout
    assert f"RFC 3161 receipt: {out_dir / 'rfc3161_receipt.json'}" in stdout
    assert "TSA generation time: 2026-01-01T00:00:01Z" in stdout
    assert "TSA serial number: 123" in stdout


def test_cli_export_rejects_redact_with_timestamp_rfc3161(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    args = argparse.Namespace(
        session_dir=str(artifacts.session_dir),
        out_dir=str(out_dir),
        contract=str(artifacts.contract_path),
        public_key=None,
        scan_report=None,
        redact=True,
        siem_out=None,
        event_type=None,
        decision=None,
        ingress=None,
        since=None,
        until=None,
        timestamp_rfc3161="https://tsa.example",
    )

    with pytest.raises(CLIError, match="--redact is incompatible with --timestamp-rfc3161"):
        export_cmd.run(args)
