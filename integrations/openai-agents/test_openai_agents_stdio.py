from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

from stipul.writ.proxy.operator_state import save_operator_state

sys.path.insert(0, str(Path(__file__).resolve().parent))

from openai_agents_stdio import (  # noqa: E402
    DEFAULT_SESSION_ID,
    StipulOpenAIAgentsConfig,
    read_events,
    write_demo_contract,
)


def _scenario_root(tmp_path: Path, name: str) -> Path:
    output_dir = os.getenv("STIPUL_OPENAI_AGENTS_OUTPUT_DIR")
    if not output_dir:
        return tmp_path
    root = Path(output_dir) / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _demo_enabled() -> bool:
    return os.getenv("STIPUL_OPENAI_AGENTS_DEMO") == "1"


def test_allowed_safe_read_returns_stable_output_and_writes_evidence(tmp_path: Path) -> None:
    root = _scenario_root(tmp_path, "allowed")
    contract_path = write_demo_contract(root / "contract.json")
    session_dir = root / "session"
    home_dir = root / "home"
    readable_path = root / "allowed.txt"
    readable_path.write_text("hello from test\n", encoding="utf-8")

    server = StipulOpenAIAgentsConfig(
        contract_path=contract_path,
        session_dir=session_dir,
        session_id=DEFAULT_SESSION_ID,
        home_dir=home_dir,
    ).server()

    async def scenario() -> None:
        async with server:
            result = await server.call_tool("filesystem.read", {"path": str(readable_path)})
            assert result.isError is False
            assert result.structuredContent == {
                "ok": True,
                "tool_name": "filesystem.read",
                "path": str(readable_path.resolve()),
                "content": "hello from test\n",
            }

    asyncio.run(scenario())

    events = read_events(session_dir / "events.jsonl")
    assert [(event["event_type"], event["decision"], event["reason"]) for event in events] == [
        ("tool_call", "allow", "risk_class"),
    ]
    assert events[0]["tool_name"] == "filesystem.read"
    assert events[0]["metadata"] == {"ingress": "mcp_gateway"}
    if _demo_enabled():
        print("## Scenario 1: allowed safe read")
        print(
            {
                "is_error": False,
                "structured_content": {
                    "ok": True,
                    "tool_name": "filesystem.read",
                    "path": str(readable_path.resolve()),
                    "content": "hello from test\n",
                },
            }
        )
        print("## Chronicle Events")
        print(events[0])
        print(f"allowed_session_dir={session_dir}")
        print(f"allowed_contract_path={contract_path}")
        print(f"allowed_home_dir={home_dir}")


def test_denied_and_kill_switch_paths_are_structured_and_logged(tmp_path: Path) -> None:
    root = _scenario_root(tmp_path, "denied")
    contract_path = write_demo_contract(root / "contract.json")
    session_dir = root / "session"
    home_dir = root / "home"
    target_path = root / "blocked.txt"
    target_path.write_text("sensitive\n", encoding="utf-8")

    server = StipulOpenAIAgentsConfig(
        contract_path=contract_path,
        session_dir=session_dir,
        session_id=DEFAULT_SESSION_ID,
        home_dir=home_dir,
    ).server()

    async def scenario() -> None:
        async with server:
            denied_write = await server.call_tool(
                "filesystem.write",
                {"path": str(target_path), "content": "rewrite"},
            )
            assert denied_write.isError is True
            assert denied_write.structuredContent == {
                "decision": "deny",
                "reason": "not_in_contract",
                "tool_name": "filesystem.write",
            }

            approval_required = await server.call_tool(
                "filesystem.delete",
                {"path": str(target_path)},
            )
            assert approval_required.isError is True
            assert approval_required.structuredContent == {
                "decision": "deny",
                "reason": "approval_required",
                "tool_name": "filesystem.delete",
            }

            unknown_tool = await server.call_tool(
                "unknown.tool",
                {"path": str(target_path)},
            )
            assert unknown_tool.isError is True
            assert unknown_tool.structuredContent == {
                "decision": "deny",
                "reason": "not_in_contract",
                "tool_name": "unknown.tool",
            }

            save_operator_state(
                session_dir,
                kill_switch_active=True,
                updated_by="operator@example.com",
                reason="operator_kill_switch_enabled",
            )
            kill_switch = await server.call_tool("filesystem.read", {"path": str(target_path)})
            assert kill_switch.isError is True
            assert kill_switch.structuredContent == {
                "decision": "deny",
                "reason": "kill_switch_active",
                "tool_name": "filesystem.read",
            }

    asyncio.run(scenario())

    assert target_path.read_text(encoding="utf-8") == "sensitive\n"

    events = read_events(session_dir / "events.jsonl")
    assert [(event["tool_name"], event["decision"], event["reason"]) for event in events] == [
        ("filesystem.write", "deny", "not_in_contract"),
        ("filesystem.delete", "allow", "approval_request_created"),
        ("filesystem.delete", "deny", "approval_required"),
        ("unknown.tool", "deny", "not_in_contract"),
        ("filesystem.read", "deny", "kill_switch_active"),
    ]
    assert events[0]["metadata"] == {"ingress": "mcp_gateway"}
    assert "approval_context" in events[1]["metadata"]
    assert events[2]["metadata"]["ingress"] == "mcp_gateway"
    assert events[4]["metadata"]["operator_updated_by"] == "operator@example.com"
    assert json.loads((session_dir / "operator_state.json").read_text(encoding="utf-8"))[
        "kill_switch_active"
    ] is True
    if _demo_enabled():
        print("## Scenario 3: approval-gated irreversible action")
        print(
            {
                "is_error": True,
                "structured_content": {
                    "decision": "deny",
                    "reason": "approval_required",
                    "tool_name": "filesystem.delete",
                },
            }
        )
        print("## Chronicle Events")
        print(events[1])
        print(events[2])
        print(f"denied_session_dir={session_dir}")
        print(f"denied_contract_path={contract_path}")
        print(f"denied_home_dir={home_dir}")
