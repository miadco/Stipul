"""Packaged demo runtime for first-run MCP gateway launches."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp import types


def build_runtime(_proxy: object) -> dict[str, object]:
    """Return a tiny caller-supplied runtime for local/demo gateway use."""
    return {
        "tool_catalog": [
            types.Tool(
                name="demo.echo",
                description="Echo the provided JSON inputs without side effects.",
                inputSchema={
                    "type": "object",
                    "additionalProperties": True,
                },
            )
        ],
        "execute_tool": execute_tool,
    }


def execute_tool(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic echo payload for local/demo use."""
    inputs = request.get("inputs", request.get("input", {}))
    if not isinstance(inputs, dict):
        inputs = {"value": inputs}
    return {
        "ok": True,
        "tool_name": request.get("tool_name", "unknown_tool"),
        "inputs": dict(inputs),
    }


__all__ = ["build_runtime", "execute_tool"]
