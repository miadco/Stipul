from __future__ import annotations

from stipul.charter.token.mint import mint_token
from stipul.writ.wrapper.mcp_wrapper import handle_tool_call


def test_wrapper_allows_valid_token(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )

    called = {"count": 0}

    def execute_tool(request):
        called["count"] += 1
        return {"ok": True, "tool": request["tool_name"]}

    result = handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "headers": {"Authorization": f"Bearer {token}"},
        },
        execute_tool,
    )

    assert result == {"ok": True, "tool": "filesystem.write"}
    assert called["count"] == 1


def test_wrapper_missing_token_denies_without_execution():
    called = {"count": 0}

    def execute_tool(_request):
        called["count"] += 1
        return {"ok": True}

    result = handle_tool_call({"tool_name": "filesystem.write", "headers": {}}, execute_tool)

    assert result == {
        "decision": "deny",
        "reason": "missing_token",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0


def test_wrapper_malformed_header_denies_without_execution():
    called = {"count": 0}

    def execute_tool(_request):
        called["count"] += 1
        return {"ok": True}

    result = handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "headers": {"Authorization": "Token abc"},
        },
        execute_tool,
    )

    assert result == {
        "decision": "deny",
        "reason": "invalid_format",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0


def test_wrapper_internal_error_returns_wrapper_error(monkeypatch):
    called = {"count": 0}

    def execute_tool(_request):
        called["count"] += 1
        return {"ok": True}

    def boom(_token, _tool_name):
        raise RuntimeError("boom")

    monkeypatch.setattr("stipul.writ.wrapper.mcp_wrapper.validate_token", boom)

    result = handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "headers": {"Authorization": "Bearer abc"},
        },
        execute_tool,
    )

    assert result == {
        "decision": "deny",
        "reason": "wrapper_error",
        "tool_name": "filesystem.write",
    }
    assert called["count"] == 0
