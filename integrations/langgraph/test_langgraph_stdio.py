from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from langchain_core.tools import ToolException

from stipul.writ.proxy.operator_state import save_operator_state

sys.path.insert(0, str(Path(__file__).resolve().parent))

from langgraph_stdio import (  # noqa: E402
    DEFAULT_SESSION_ID,
    StipulLangGraphConfig,
    parse_tool_exception,
    parse_tool_result,
    read_events,
    select_tool,
    write_demo_contract,
)


def _scenario_root(tmp_path: Path, name: str) -> Path:
    output_dir = os.getenv("STIPUL_LANGGRAPH_OUTPUT_DIR")
    if not output_dir:
        return tmp_path
    root = Path(output_dir) / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _demo_enabled() -> bool:
    return os.getenv("STIPUL_LANGGRAPH_DEMO") == "1"


def test_allowed_safe_read_returns_stable_output_and_writes_evidence(tmp_path: Path) -> None:
    root = _scenario_root(tmp_path, "allowed")
    contract_path = write_demo_contract(root / "contract.json")
    session_dir = root / "session"
    home_dir = root / "home"
    readable_path = root / "allowed.txt"
    readable_path.write_text("hello from test\n", encoding="utf-8")

    config = StipulLangGraphConfig(
        contract_path=contract_path,
        session_dir=session_dir,
        session_id=DEFAULT_SESSION_ID,
        home_dir=home_dir,
    )

    async def scenario() -> dict[str, object]:
        tools = await config.get_tools()
        result = await select_tool(tools, "filesystem.read").ainvoke({"path": str(readable_path)})
        return parse_tool_result(result)

    payload = asyncio.run(scenario())

    assert payload == {
        "ok": True,
        "tool_name": "filesystem.read",
        "path": str(readable_path.resolve()),
        "content": "hello from test\n",
    }

    events = read_events(session_dir / "events.jsonl")
    decision_events = [event for event in events if event["decision"] is not None]
    assert [
        (event["event_type"], event["decision"], event["reason"]) for event in decision_events
    ] == [
        ("tool_call", "allow", "risk_class"),
    ]
    assert decision_events[0]["tool_name"] == "filesystem.read"
    assert decision_events[0]["metadata"] == {"ingress": "mcp_gateway"}
    if _demo_enabled():
        print("## Scenario 1: allowed safe read")
        print({"structured_content": payload})
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

    config = StipulLangGraphConfig(
        contract_path=contract_path,
        session_dir=session_dir,
        session_id=DEFAULT_SESSION_ID,
        home_dir=home_dir,
    )

    async def scenario() -> dict[str, object]:
        tools = await config.get_tools()
        tool_map = {tool.name: tool for tool in tools}

        with pytest.raises(ToolException) as denied_write:
            await tool_map["filesystem.write"].ainvoke(
                {"path": str(target_path), "content": "rewrite"}
            )
        assert parse_tool_exception(denied_write.value) == {
            "decision": "deny",
            "reason": "not_in_contract",
            "tool_name": "filesystem.write",
        }

        with pytest.raises(ToolException) as approval_required:
            await tool_map["filesystem.delete"].ainvoke({"path": str(target_path)})
        approval_payload = parse_tool_exception(approval_required.value)
        assert approval_payload == {
            "decision": "deny",
            "reason": "approval_required",
            "tool_name": "filesystem.delete",
        }

        unknown_tool = await config.call_raw_tool("unknown.tool", {"path": str(target_path)})
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

        with pytest.raises(ToolException) as kill_switch:
            await tool_map["filesystem.read"].ainvoke({"path": str(target_path)})
        assert parse_tool_exception(kill_switch.value) == {
            "decision": "deny",
            "reason": "kill_switch_active",
            "tool_name": "filesystem.read",
        }

        return approval_payload

    approval_payload = asyncio.run(scenario())

    assert target_path.read_text(encoding="utf-8") == "sensitive\n"

    events = read_events(session_dir / "events.jsonl")
    decision_events = [event for event in events if event["decision"] is not None]
    assert [(event["tool_name"], event["decision"], event["reason"]) for event in decision_events] == [
        ("filesystem.write", "deny", "not_in_contract"),
        ("filesystem.delete", "allow", "approval_request_created"),
        ("filesystem.delete", "deny", "approval_required"),
        ("unknown.tool", "deny", "not_in_contract"),
        ("filesystem.read", "deny", "kill_switch_active"),
    ]
    assert decision_events[0]["metadata"] == {"ingress": "mcp_gateway"}
    assert "approval_context" in decision_events[1]["metadata"]
    assert decision_events[2]["metadata"]["ingress"] == "mcp_gateway"
    assert decision_events[4]["metadata"]["operator_updated_by"] == "operator@example.com"
    assert json.loads((session_dir / "operator_state.json").read_text(encoding="utf-8"))[
        "kill_switch_active"
    ] is True
    if _demo_enabled():
        print("## Scenario 3: approval-gated irreversible action")
        print({"structured_content": approval_payload})
        print("## Chronicle Events")
        print(events[1])
        print(events[2])
        print(f"denied_session_dir={session_dir}")
        print(f"denied_contract_path={contract_path}")
        print(f"denied_home_dir={home_dir}")
