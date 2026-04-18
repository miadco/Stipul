from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from stipul.cli import operator_cmd

from tests.cli_support import REPO_ROOT, create_signed_session


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _run_cli(home_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["HOME"] = str(home_dir)
    return subprocess.run(
        [sys.executable, "-m", "stipul.cli.main", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_operator_cli_enable_status_and_disable(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=False, include_summary=False)

    status_result = _run_cli(
        tmp_path,
        "operator",
        "status",
        "--session-dir",
        str(artifacts.session_dir),
        "--charter",
        str(artifacts.contract_path),
    )

    assert status_result.returncode == 0
    assert "status: healthy" in status_result.stdout
    assert "kill_switch_active: false" in status_result.stdout
    assert "operator_updated_by: -" in status_result.stdout
    assert "operator_reason: -" in status_result.stdout

    enable_result = _run_cli(
        tmp_path,
        "operator",
        "kill-switch",
        "enable",
        "--session-dir",
        str(artifacts.session_dir),
        "--charter",
        str(artifacts.contract_path),
        "--by",
        "operator@example.com",
        "--reason",
        "operator_kill_switch_enabled",
    )

    assert enable_result.returncode == 0
    assert "kill_switch_active: true" in enable_result.stdout
    assert "operator_updated_by: operator@example.com" in enable_result.stdout
    assert "operator_reason: operator_kill_switch_enabled" in enable_result.stdout

    operator_state = json.loads((tmp_path / "session" / "operator_state.json").read_text(encoding="utf-8"))
    assert operator_state["kill_switch_active"] is True
    assert operator_state["updated_by"] == "operator@example.com"

    events = _read_jsonl(artifacts.events_path)
    enable_event = next(
        event
        for event in reversed(events)
        if event["event_type"] == "elev_op"
        and event["reason"] == "operator_kill_switch_enabled"
    )
    assert enable_event["decision"] == "allow"
    assert enable_event["metadata"]["updated_by"] == "operator@example.com"
    assert events[-1]["event_type"] == "session_close"
    assert events[-1]["reason"] == "session_closed"

    refreshed_status = _run_cli(
        tmp_path,
        "operator",
        "status",
        "--session-dir",
        str(artifacts.session_dir),
        "--charter",
        str(artifacts.contract_path),
    )

    assert refreshed_status.returncode == 0
    assert "kill_switch_active: true" in refreshed_status.stdout
    assert "operator_updated_by: operator@example.com" in refreshed_status.stdout

    disable_result = _run_cli(
        tmp_path,
        "operator",
        "kill-switch",
        "disable",
        "--session-dir",
        str(artifacts.session_dir),
        "--charter",
        str(artifacts.contract_path),
        "--by",
        "operator@example.com",
        "--reason",
        "operator_kill_switch_disabled",
    )

    assert disable_result.returncode == 0
    assert "kill_switch_active: false" in disable_result.stdout
    assert "operator_updated_by: operator@example.com" in disable_result.stdout
    assert "operator_reason: operator_kill_switch_disabled" in disable_result.stdout

    final_events = _read_jsonl(artifacts.events_path)
    disable_event = next(
        event
        for event in reversed(final_events)
        if event["event_type"] == "elev_op"
        and event["reason"] == "operator_kill_switch_disabled"
    )
    assert disable_event["decision"] == "allow"
    assert disable_event["metadata"]["updated_by"] == "operator@example.com"
    assert [event["reason"] for event in final_events if event["event_type"] == "elev_op"] == [
        "operator_kill_switch_enabled",
        "operator_kill_switch_disabled",
    ]
    assert final_events[-1]["event_type"] == "session_close"
    assert final_events[-1]["reason"] == "session_closed"


def test_operator_cli_approval_commands_delegate_to_proxy_methods(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    calls: dict[str, object] = {}

    class FakeProxy:
        def approval_status(self, request_id: str | None) -> dict[str, object]:
            calls["status"] = request_id
            return {
                "request_count": 1,
                "requests": [
                    {
                        "request_id": "req-1",
                        "status": "pending",
                        "required_approver_count": 2,
                        "approval_count": 1,
                        "tool_name": "dangerous.op",
                        "expires_at": "2026-01-01T00:05:00Z",
                        "approver_ids": ["a" * 64],
                        "derived_permit_id": None,
                    }
                ],
            }

        def approve_approval_request(self, request_id: str, approved_by: str) -> dict[str, object]:
            calls["approve"] = (request_id, approved_by)
            return {
                "request_id": request_id,
                "status": "approved",
                "required_approver_count": 2,
                "approval_count": 2,
                "tool_name": "dangerous.op",
                "expires_at": "2026-01-01T00:05:00Z",
                "approver_ids": ["a" * 64, approved_by],
                "derived_permit_id": "permit-1",
            }

        def close(self) -> None:
            calls["closed"] = calls.get("closed", 0) + 1

    fake_proxy = FakeProxy()
    monkeypatch.setattr(operator_cmd, "ensure_session_dir", lambda path: path)
    monkeypatch.setattr(operator_cmd, "_build_proxy", lambda session_dir, contract_path: fake_proxy)

    status_args = argparse.Namespace(
        operator_command="approval",
        approval_action="status",
        request_id="req-1",
        session_dir=str(tmp_path),
        charter=str(tmp_path / "contract.json"),
    )
    approve_args = argparse.Namespace(
        operator_command="approval",
        approval_action="approve",
        request_id="req-1",
        by="b" * 64,
        session_dir=str(tmp_path),
        charter=str(tmp_path / "contract.json"),
    )

    assert operator_cmd.run(status_args) == 0
    status_output = capsys.readouterr().out
    assert calls["status"] == "req-1"
    assert "request_count: 1" in status_output
    assert "request_id: req-1" in status_output
    assert "approval_count: 1/2" in status_output

    assert operator_cmd.run(approve_args) == 0
    approve_output = capsys.readouterr().out
    assert calls["approve"] == ("req-1", "b" * 64)
    assert "status: approved" in approve_output
    assert "derived_permit_id: permit-1" in approve_output
    assert calls["closed"] == 2
