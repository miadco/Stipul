from __future__ import annotations

import json
from pathlib import Path

from stipul.writ.proxy.server import ProxyServer

from tests.cli_support import DEFAULT_SESSION_ID, run_cli, write_contract_file


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_report_renders_real_proxy_approval_gate_session(
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
    assert events[0]["event_type"] == "session_open"
    assert events[1]["event_type"] == "elev_op"
    assert events[2]["event_type"] == "tool_call"
    assert events[3]["event_type"] == "session_close"

    result = run_cli("report", str(session_dir))

    expected = "\n".join(
        [
            "1. What session is this?",
            f"Session ID: {DEFAULT_SESSION_ID}",
            f"Contract ID: {contract.contract_id}",
            f"Time range: {events[0]['timestamp']} to {events[3]['timestamp']}",
            "",
            "2. What did the agent try to do?",
            "1. Attempted dangerous.op on path=out.txt.",
            "Related approval event matched from nearby Chronicle entries. Approval event. Reason: approval was requested. (seq 2)",
            "",
            "3. What did Stipul decide for each one?",
            "1. dangerous.op was held for approval. Reason: approval required. Rule: risk class policy. (seq 3)",
            "",
            "4. Did anything policy-significant happen?",
            "1. Approval was requested. Tool: dangerous.op. Details: No additional details recorded for this event type. (seq 2) Related attempt: seq 3.",
            "2. Approval was required before execution. Tool: dangerous.op. Rule: risk class policy. Details: path=out.txt. (seq 3)",
            "",
            "5. Can I trust this record?",
            "Fresh verification only.",
            "Trust: VERIFIED",
            "Chain: INTACT",
            "Seal: VALID",
        ]
    )

    assert result.returncode == 0
    assert result.stdout == expected + "\n"
    assert "request_id" not in result.stdout
    assert "chain_integrity" not in result.stdout
    assert "pre_close_chain_integrity" not in result.stdout
