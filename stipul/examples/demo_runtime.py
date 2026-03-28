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
                name="file.read",
                description="Read the contents of a file by path",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            types.Tool(
                name="file.write",
                description="Write content to a file by path",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            ),
            types.Tool(
                name="shell.exec",
                description="Execute a shell command",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
        ],
        "execute_tool": execute_tool,
    }


def execute_tool(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic echo payload for local/demo use."""
    inputs = request.get("inputs", request.get("input", {}))
    if not isinstance(inputs, dict):
        inputs = {"value": inputs}
    tool_name = request.get("tool_name", "unknown_tool")
    if tool_name == "file.read":
        path = inputs.get("path", "")
        if not isinstance(path, str):
            path = str(path)
        return {
            "ok": True,
            "tool_name": "file.read",
            "path": path,
            "content": (
                "# Example file contents\n\n"
                "This is a demo file managed by Stipul.\n"
                f"Path: {path}\n"
                "Status: read-only\n"
            ),
        }
    if tool_name == "file.write":
        path = inputs.get("path", "")
        if not isinstance(path, str):
            path = str(path)
        content = inputs.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        return {
            "ok": True,
            "tool_name": "file.write",
            "path": path,
            "bytes_written": len(content),
        }
    if tool_name == "shell.exec":
        command = inputs.get("command", "")
        if not isinstance(command, str):
            command = str(command)
        return {
            "ok": True,
            "tool_name": "shell.exec",
            "command": command,
            "output": "demo: command not executed (sandbox mode)",
        }
    return {
        "ok": True,
        "tool_name": tool_name,
        "inputs": dict(inputs),
    }


__all__ = ["build_runtime", "execute_tool"]
