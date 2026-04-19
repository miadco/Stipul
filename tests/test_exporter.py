from __future__ import annotations

import json
from pathlib import Path

from stipul.seal.exporter import export_session_bundle
from tests.cli_support import create_signed_session


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_exporter_writes_expected_bundle_files(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    assert (out_dir / "manifest.json").exists()
    assert (out_dir / "events.jsonl").exists()
    assert (out_dir / "decisions.jsonl").exists()
    assert (out_dir / "summary.json").exists()
    assert (out_dir / "contract.json").exists()
    assert (out_dir / "public_key.pem").exists()
    assert (out_dir / "trust_boundaries.json").exists()
    assert manifest["missing_artifacts"] == []


def test_exporter_manifest_hashes_match_files(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    for filename, digest in manifest["hashes"].items():
        path = out_dir / filename
        assert path.exists()
        assert digest == __import__("hashlib").sha256(path.read_bytes()).hexdigest()


def test_exporter_writes_trust_boundaries_with_supplied_charter_wording(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    trust_boundaries = json.loads((out_dir / "trust_boundaries.json").read_text(encoding="utf-8"))
    proxy_proves = trust_boundaries["proxy_proves"]

    assert "Tool calls routed through the MCP Proxy were evaluated against the supplied charter." in proxy_proves
    assert all("signed charter" not in item for item in proxy_proves)


def test_exporter_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir_a = tmp_path / "bundle_a"
    out_dir_b = tmp_path / "bundle_b"

    manifest_a = export_session_bundle(
        artifacts.session_dir,
        out_dir_a,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )
    manifest_b = export_session_bundle(
        artifacts.session_dir,
        out_dir_b,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    assert manifest_a == manifest_b
    for filename in manifest_a["included_files"]:
        assert (out_dir_a / filename).read_bytes() == (out_dir_b / filename).read_bytes()


def test_exporter_redacts_metadata_without_touching_signature_fields(tmp_path: Path) -> None:
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
                    "destination": "api.example.com",
                    "nested": {"token": "secret", "count": 2},
                    "items": ["a", "b"],
                },
            }
        ],
    )
    original_events_bytes = artifacts.events_path.read_bytes()
    out_dir = tmp_path / "bundle"

    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
        redact=True,
    )

    original_event = _read_jsonl(artifacts.events_path)[0]
    redacted_event = _read_jsonl(out_dir / "redacted_events.jsonl")[0]

    assert artifacts.events_path.read_bytes() == original_events_bytes
    assert redacted_event["signature"] == original_event["signature"]
    assert redacted_event["agent_identity"] == original_event["agent_identity"]
    assert redacted_event["input_hash"] == original_event["input_hash"]
    assert redacted_event["metadata"] == {
        "destination": "[REDACTED]",
        "items": ["[REDACTED]", "[REDACTED]"],
        "nested": {"count": "[REDACTED]", "token": "[REDACTED]"},
    }
    assert manifest["original_events_sha256"] != manifest["redacted_events_sha256"]


def test_exporter_records_missing_optional_artifacts(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=False, include_summary=False)
    out_dir = tmp_path / "bundle"

    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=None,
    )

    assert manifest["missing_artifacts"] == [
        "decisions.jsonl",
        "public_key.pem",
        "summary.json",
    ]


def test_exporter_replaces_stale_bundle_artifacts(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    out_dir = tmp_path / "bundle"

    export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )
    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=None,
        redact=True,
    )

    assert not (out_dir / "events.jsonl").exists()
    assert not (out_dir / "public_key.pem").exists()
    assert (out_dir / "redacted_events.jsonl").exists()
    assert manifest["missing_artifacts"] == ["public_key.pem"]
