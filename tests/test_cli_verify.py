from __future__ import annotations

import json
from pathlib import Path

import yaml

from stipul.seal.builder import (
    build_session_seal,
    seal_path as resolve_seal_path,
    write_seal,
)
from stipul.seal.signer import sign_seal
from stipul.seal.verifier import verify_seal
from stipul.utils.canonical import compute_prev_hash
from stipul.writ.proxy.server import ProxyServer

from tests.cli_support import (
    DEFAULT_SESSION_ID,
    create_signed_session,
    run_cli,
    write_contract_file,
)


def _rewrite_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
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


def _receipt_lines(stdout: str) -> list[str]:
    return stdout.strip().splitlines()


def _expected_trust(chain_status: str, seal_status: str) -> str:
    if chain_status == "INTACT" and seal_status == "VALID":
        return "VERIFIED"
    if chain_status == "INTACT" and seal_status == "ABSENT":
        return "UNVERIFIED (unsealed)"
    return "REJECTED"


def _assert_receipt(
    stdout: str,
    *,
    chain_status: str,
    seal_status: str,
    session_id: str = DEFAULT_SESSION_ID,
) -> list[str]:
    lines = _receipt_lines(stdout)
    assert lines[:5] == [
        "Verification receipt",
        f"Session: {session_id}",
        f"Trust: {_expected_trust(chain_status, seal_status)}",
        f"Chain: {chain_status}",
        f"Seal: {seal_status}",
    ]
    assert "Chain integrity:" not in stdout
    return lines


def _line_with_prefix(lines: list[str], prefix: str) -> str | None:
    return next((line for line in lines if line.startswith(prefix)), None)


def _write_yaml_contract(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _write_synthetic_seal(session_dir: Path, events_path: Path, private_key) -> None:
    terminal_event = _read_jsonl(events_path)[-1]
    seal = build_session_seal(
        {
            "session_id": terminal_event["session_id"],
            "contract_id": terminal_event["contract_id"],
            "contract_hash": terminal_event["contract_hash"],
            "event_hash": compute_prev_hash(terminal_event),
            "sequence_id": terminal_event["sequence_id"],
            "timestamp": terminal_event["timestamp"],
            "key_id": terminal_event["key_id"],
            "algorithm": terminal_event["algorithm"],
            "key_created_at": terminal_event["key_created_at"],
        },
        events_path,
    )
    seal["signature"] = sign_seal(seal, private_key)
    write_seal(resolve_seal_path(session_dir), seal)


def _assert_operational_error(result, *, expected_path: Path, expected_flag: str) -> None:
    assert result.returncode == 2
    assert "Verification receipt" not in result.stdout
    assert "Traceback" not in result.stderr
    assert str(expected_path) in result.stderr
    assert expected_flag in result.stderr


def test_verify_positional_succeeds_for_open_session_with_session_local_trust_inputs(
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True)

    result = run_cli("verify", str(artifacts.session_dir))

    assert result.returncode == 0
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")
    assert (
        _line_with_prefix(lines, "Reason: ")
        == "Reason: session is unsealed; terminal event is tool_call, not session_close"
    )
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=2 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {artifacts.keypair.key_id}"


def test_verify_positional_succeeds_for_closed_sealed_synthetic_session(
    tmp_path: Path,
) -> None:
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
                "event_type": "session_close",
                "tool_name": None,
                "risk_class": None,
                "decision": None,
                "reason": "session_closed",
                "agent_identity": "b" * 64,
                "input_hash": None,
                "metadata": {
                    "session_id": DEFAULT_SESSION_ID,
                    "total_calls": 1,
                    "chain_length": 2,
                    "tools_invoked": ["filesystem.write"],
                },
            },
        ],
    )
    _write_synthetic_seal(
        artifacts.session_dir,
        artifacts.events_path,
        artifacts.keypair.private_key,
    )

    result = run_cli("verify", str(artifacts.session_dir))

    assert result.returncode == 0
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="VALID")
    assert _line_with_prefix(lines, "Reason: ") is None
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=2 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {artifacts.keypair.key_id}"


def test_verify_accepts_matching_positional_and_session_dir_flag(
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path)

    result = run_cli(
        "verify",
        str(artifacts.session_dir),
        "--session-dir",
        str(artifacts.session_dir),
    )

    assert result.returncode == 0
    _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")


def test_verify_rejects_conflicting_session_dir_inputs(tmp_path: Path) -> None:
    first = create_signed_session(tmp_path / "first")
    second = create_signed_session(tmp_path / "second")

    result = run_cli(
        "verify",
        str(first.session_dir),
        "--session-dir",
        str(second.session_dir),
    )

    assert result.returncode == 2
    assert "usage: stipul verify" in result.stderr
    assert (
        "session_dir positional argument and --session-dir must resolve to the same path"
        in result.stderr
    )


def test_verify_operational_error_when_session_local_contract_is_missing(
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path)
    artifacts.session_contract_path.unlink()

    result = run_cli("verify", str(artifacts.session_dir))

    _assert_operational_error(
        result,
        expected_path=artifacts.session_contract_path,
        expected_flag="--contract",
    )


def test_verify_operational_error_when_session_local_public_key_is_missing(
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path)
    artifacts.session_public_key_path.unlink()

    result = run_cli("verify", str(artifacts.session_dir))

    _assert_operational_error(
        result,
        expected_path=artifacts.session_public_key_path,
        expected_flag="--public-key",
    )


def test_verify_explicit_flag_invocation_supports_yaml_contract_override(
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path)
    yaml_contract_path = _write_yaml_contract(
        tmp_path / "contract.yaml",
        artifacts.contract.to_canonical_dict(),
    )

    result = run_cli(
        "verify",
        "--session-dir",
        str(artifacts.session_dir),
        "--contract",
        str(yaml_contract_path),
        "--public-key",
        str(artifacts.session_public_key_path),
    )

    assert result.returncode == 0
    _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")


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
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")
    assert (
        _line_with_prefix(lines, "Reason: ")
        == "Reason: session is unsealed; terminal event is tool_call, not session_close"
    )
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=2 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {artifacts.keypair.key_id}"
    assert "Decision projection" not in result.stdout

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert (
        report["seal_reason"]
        == "session is unsealed; terminal event is tool_call, not session_close"
    )
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
    key_id = proxy.event_logger.signing_key.key_id

    try:
        response = proxy.handle_tool_call(
            {
                "tool_name": "filesystem.write",
                "inputs": {"path": "out.txt", "content": "x"},
            },
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}
    finally:
        proxy.close()

    assert (session_dir / "seal.json").exists()
    report_path = tmp_path / "verify.json"
    result = run_cli(
        "verify",
        str(session_dir),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="VALID")
    assert _line_with_prefix(lines, "Reason: ") is None
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=3 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {key_id}"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_reason"] is None
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
    key_id = proxy.event_logger.signing_key.key_id
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
    assert len(events) == 3
    assert events[0]["event_type"] == "session_open"
    assert events[1]["event_type"] == "tool_call"
    assert events[1]["decision"] == "deny"
    assert events[1]["reason"] == "not_in_contract"
    assert events[2]["event_type"] == "session_close"
    assert events[2]["reason"] == "session_closed"

    assert (session_dir / "seal.json").exists()
    assert verify_seal(session_dir, public_key, contract).status == "VALID"

    report_path = tmp_path / "deny-verify.json"
    result = run_cli(
        "verify",
        str(session_dir),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="VALID")
    assert _line_with_prefix(lines, "Reason: ") is None
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=3 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {key_id}"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_reason"] is None
    assert report["seal_status"] == "VALID"


def test_seal_valid_on_real_proxy_approval_gate_path(
    tmp_path: Path,
    monkeypatch,
    base_dict,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

    contract_payload = json.loads(json.dumps(base_dict))
    contract_payload["allowed_tools"] = sorted(
        {*contract_payload["allowed_tools"], "dangerous.op"}
    )
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
    key_id = proxy.event_logger.signing_key.key_id
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
    assert len(events) == 4
    approval_created, approval_denied, session_close = events[1:]
    assert events[0]["event_type"] == "session_open"
    assert approval_created["event_type"] == "elev_op"
    assert approval_created["decision"] == "allow"
    assert approval_created["reason"] == "approval_request_created"
    assert approval_denied["event_type"] == "tool_call"
    assert approval_denied["decision"] == "deny"
    assert approval_denied["reason"] == "approval_required"
    assert session_close["event_type"] == "session_close"
    assert session_close["reason"] == "session_closed"
    assert (
        approval_created["metadata"]["approval_context"]["request_id"]
        == approval_denied["metadata"]["approval_context"]["request_id"]
    )

    assert (session_dir / "seal.json").exists()
    assert verify_seal(session_dir, public_key, contract).status == "VALID"

    report_path = tmp_path / "approval-gate-verify.json"
    result = run_cli(
        "verify",
        str(session_dir),
        "--json-out",
        str(report_path),
    )

    assert result.returncode == 0
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="VALID")
    assert _line_with_prefix(lines, "Reason: ") is None
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=4 at ")
    assert _line_with_prefix(lines, "Key: ") == f"Key: {key_id}"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_reason"] is None
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
            {
                "tool_name": "filesystem.write",
                "inputs": {"path": "out.txt", "content": "x"},
            },
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}
    finally:
        proxy.close()

    seal_path = session_dir / "seal.json"
    seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
    seal_payload["terminal_sequence_id"] = 99
    seal_path.write_text(
        json.dumps(seal_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report_path = tmp_path / "invalid-verify.json"

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

    assert result.returncode == 2
    lines = _assert_receipt(result.stdout, chain_status="INTACT", seal_status="INVALID")
    assert (
        _line_with_prefix(lines, "Reason: ")
        == "Reason: seal does not match authoritative session evidence"
    )
    assert _line_with_prefix(lines, "Terminal: ").startswith("Terminal: seq=3 at ")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_status"] == "INTACT"
    assert report["seal_status"] == "INVALID"
    assert report["seal_reason"] == "seal does not match authoritative session evidence"


def test_r002_unsealed_session_ambiguity(tmp_path: Path, monkeypatch) -> None:
    """Current behavior collapses multiple materially different missing-Seal causes into the same Seal: ABSENT outcome, with no durable artifact indicating whether a Seal was expected."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    contract_path, _contract = write_contract_file(tmp_path)

    def _run_verify(session_dir: Path, report_name: str) -> dict[str, object]:
        report_path = tmp_path / report_name
        result = run_cli(
            "verify",
            str(session_dir),
            "--json-out",
            str(report_path),
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return {
            "exit_code": result.returncode,
            "chain_status": report["chain_status"],
            "seal_reason": report["seal_reason"],
            "seal_status": report["seal_status"],
            "stdout": result.stdout,
        }

    scenario_a_proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=tmp_path / "scenario-a" / "events.jsonl",
    )
    scenario_b_proxy: ProxyServer | None = None

    try:
        scenario_a_response = scenario_a_proxy.handle_tool_call(
            {
                "tool_name": "filesystem.write",
                "inputs": {"path": "out-a.txt", "content": "a"},
            },
            lambda _request: {"ok": True},
        )
        assert scenario_a_response == {"ok": True}

        scenario_a_session_dir = scenario_a_proxy.event_logger.store.path.parent
        assert not resolve_seal_path(scenario_a_session_dir).exists()
        # Keep scenario_a_proxy alive until both verify runs complete; __del__ would otherwise call
        # close() and silently convert the "never closed" case into a sealed session.
        scenario_a_result = _run_verify(
            scenario_a_session_dir,
            "scenario-a-verify.json",
        )

        assert scenario_a_result["exit_code"] == 0
        assert scenario_a_result["chain_status"] == "INTACT"
        assert scenario_a_result["seal_reason"] == (
            "session is unsealed; terminal event is tool_call, not session_close"
        )
        assert scenario_a_result["seal_status"] == "ABSENT"
        scenario_a_lines = _assert_receipt(
            str(scenario_a_result["stdout"]),
            chain_status="INTACT",
            seal_status="ABSENT",
        )
        assert (
            _line_with_prefix(scenario_a_lines, "Reason: ")
            == "Reason: session is unsealed; terminal event is tool_call, not session_close"
        )
        assert _line_with_prefix(scenario_a_lines, "Terminal: ").startswith(
            "Terminal: seq=2 at "
        )

        scenario_b_proxy = ProxyServer.from_contract_path(
            contract_path,
            session_id=DEFAULT_SESSION_ID,
            events_path=tmp_path / "scenario-b" / "events.jsonl",
        )
        scenario_b_response = scenario_b_proxy.handle_tool_call(
            {
                "tool_name": "filesystem.write",
                "inputs": {"path": "out-b.txt", "content": "b"},
            },
            lambda _request: {"ok": True},
        )
        assert scenario_b_response == {"ok": True}
        scenario_b_proxy.close()

        scenario_b_session_dir = scenario_b_proxy.event_logger.store.path.parent
        scenario_b_seal_path = resolve_seal_path(scenario_b_session_dir)
        assert scenario_b_seal_path.exists()
        scenario_b_seal_path.unlink()
        scenario_b_result = _run_verify(
            scenario_b_session_dir,
            "scenario-b-verify.json",
        )

        assert scenario_b_result["exit_code"] == 0
        assert scenario_b_result["chain_status"] == "INTACT"
        assert (
            scenario_b_result["seal_reason"] == "no seal.json found for closed session"
        )
        assert scenario_b_result["seal_status"] == "ABSENT"
        scenario_b_lines = _assert_receipt(
            str(scenario_b_result["stdout"]),
            chain_status="INTACT",
            seal_status="ABSENT",
        )
        assert (
            _line_with_prefix(scenario_b_lines, "Reason: ")
            == "Reason: no seal.json found for closed session"
        )
        assert _line_with_prefix(scenario_b_lines, "Terminal: ").startswith(
            "Terminal: seq=3 at "
        )

        assert scenario_a_result["seal_reason"] != scenario_b_result["seal_reason"]
        assert scenario_a_result != scenario_b_result
    finally:
        if scenario_b_proxy is not None:
            scenario_b_proxy.close()
        scenario_a_proxy.close()


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
    lines = _assert_receipt(result.stdout, chain_status="BROKEN", seal_status="ABSENT")
    assert (
        _line_with_prefix(lines, "Reason: ")
        == "Reason: session is unsealed; terminal event is tool_call, not session_close"
    )
    assert (
        _line_with_prefix(lines, "Chain detail: ")
        == "Chain detail: first failure at sequence_id 2 (SignatureFailure: signature_invalid)"
    )
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
    lines = _assert_receipt(
        result.stdout, chain_status="UNVERIFIABLE", seal_status="ABSENT"
    )
    assert (
        _line_with_prefix(lines, "Reason: ")
        == "Reason: session is unsealed; terminal event is tool_call, not session_close"
    )
    assert (
        _line_with_prefix(lines, "Chain detail: ")
        == "Chain detail: verifiable up to sequence_id 1; line 2 unparseable"
    )
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
    _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")
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
    _assert_receipt(result.stdout, chain_status="INTACT", seal_status="ABSENT")
    assert "Decision projection" not in result.stdout
