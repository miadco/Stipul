from __future__ import annotations

import json
from pathlib import Path

from stipul.seal.verifier import verify_seal
from stipul.writ.proxy.server import ProxyServer

from tests.cli_support import DEFAULT_SESSION_ID, create_signed_session, run_cli, write_contract_file


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
    assert report["seal_status"] == "ABSENT"
    assert report["signed_event_count"] == 2
    assert report["unsigned_count"] == 0
    assert "decisions_valid" not in report


def test_verify_reports_valid_seal_for_real_allow_path_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract_path, _contract = write_contract_file(tmp_path)
    session_dir = tmp_path / "session"
    session_dir.mkdir(parents=True, exist_ok=True)
    proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=session_dir / "events.jsonl",
    )
    public_key_path = proxy.event_logger.signing_key.public_key_path

    try:
        response = proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}
    finally:
        proxy.close()

    assert (session_dir / "seal.json").exists()
    report_path = tmp_path / "verify.json"
    result = run_cli(
        "verify",
        "--session-dir",
        str(session_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(public_key_path),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Seal: VALID" in result.stdout
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_status"] == "VALID"


def test_seal_valid_on_real_proxy_deny_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract_path, contract = write_contract_file(tmp_path)
    session_dir = tmp_path / "deny-session"
    session_dir.mkdir(parents=True, exist_ok=True)
    proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=session_dir / "events.jsonl",
    )
    public_key = proxy.event_logger.signing_key.public_key
    public_key_path = proxy.event_logger.signing_key.public_key_path
    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    try:
        response = proxy.handle_tool_call(
            {"tool_name": "totally.unknown.tool", "inputs": {"x": 1}},
            forward_call,
        )
        assert response == {
            "decision": "deny",
            "reason": "not_in_contract",
            "tool_name": "totally.unknown.tool",
        }
        assert called["count"] == 0
    finally:
        proxy.close()

    events = _read_jsonl(session_dir / "events.jsonl")
    assert len(events) == 1
    assert events[0]["event_type"] == "tool_call"
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "not_in_contract"

    assert (session_dir / "seal.json").exists()
    assert verify_seal(session_dir, public_key, contract).status == "VALID"

    report_path = tmp_path / "deny-verify.json"
    result = run_cli(
        "verify",
        "--session-dir",
        str(session_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(public_key_path),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Seal: VALID" in result.stdout
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_status"] == "VALID"


def test_seal_valid_on_real_proxy_approval_gate_path(
    tmp_path: Path,
    monkeypatch,
    base_dict,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

    contract_payload = json.loads(json.dumps(base_dict))
    contract_payload["allowed_tools"] = sorted({*contract_payload["allowed_tools"], "dangerous.op"})
    contract_payload["tool_risk_classes"]["dangerous.op"] = "irreversible"
    contract_path, contract = write_contract_file(tmp_path, contract_payload)

    session_dir = tmp_path / "approval-gate-session"
    session_dir.mkdir(parents=True, exist_ok=True)
    proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=session_dir / "events.jsonl",
    )
    public_key = proxy.event_logger.signing_key.public_key
    public_key_path = proxy.event_logger.signing_key.public_key_path
    called = {"count": 0}

    def forward_call(_request):
        called["count"] += 1
        return {"ok": True}

    try:
        response = proxy.handle_tool_call(
            {"tool_name": "dangerous.op", "inputs": {"path": "out.txt"}},
            forward_call,
        )
        assert response == {
            "decision": "deny",
            "reason": "approval_required",
            "tool_name": "dangerous.op",
        }
        assert called["count"] == 0
    finally:
        proxy.close()

    events = _read_jsonl(session_dir / "events.jsonl")
    assert len(events) == 2
    approval_created, approval_denied = events
    assert approval_created["event_type"] == "elev_op"
    assert approval_created["decision"] == "allow"
    assert approval_created["reason"] == "approval_request_created"
    assert approval_denied["event_type"] == "tool_call"
    assert approval_denied["decision"] == "deny"
    assert approval_denied["reason"] == "approval_required"
    assert (
        approval_created["metadata"]["approval_context"]["request_id"]
        == approval_denied["metadata"]["approval_context"]["request_id"]
    )

    assert (session_dir / "seal.json").exists()
    assert verify_seal(session_dir, public_key, contract).status == "VALID"

    report_path = tmp_path / "approval-gate-verify.json"
    result = run_cli(
        "verify",
        "--session-dir",
        str(session_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(public_key_path),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Seal: VALID" in result.stdout
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_status"] == "VALID"


def test_verify_reports_invalid_seal_without_changing_chronicle_verdict(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract_path, _contract = write_contract_file(tmp_path)
    session_dir = tmp_path / "session"
    session_dir.mkdir(parents=True, exist_ok=True)
    proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=session_dir / "events.jsonl",
    )
    public_key_path = proxy.event_logger.signing_key.public_key_path

    try:
        response = proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}
    finally:
        proxy.close()

    seal_path = session_dir / "seal.json"
    seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
    seal_payload["terminal_sequence_id"] = 99
    seal_path.write_text(json.dumps(seal_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = run_cli(
        "verify",
        "--session-dir",
        str(session_dir),
        "--contract",
        str(contract_path),
        "--public-key",
        str(public_key_path),
    )

    assert result.returncode == 0
    assert "Chain integrity: INTACT" in result.stdout
    assert "Seal: INVALID" in result.stdout


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
    assert "Seal: ABSENT" in result.stdout
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
    assert "Seal: ABSENT" in result.stdout
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
    assert "Seal: ABSENT" in result.stdout
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
    assert "Seal: ABSENT" in result.stdout
    assert "Decision projection" not in result.stdout
