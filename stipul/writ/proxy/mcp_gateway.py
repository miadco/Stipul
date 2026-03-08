"""Minimal MCP gateway adapter over the existing proxy enforcement path."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import json
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from stipul import __version__


ToolCatalog = Callable[[], Sequence[types.Tool]] | Sequence[types.Tool]


def _result_text(payload: Any) -> str:
    try:
        return json.dumps(payload, indent=2, sort_keys=True)
    except TypeError:
        return str(payload)


def _is_structured_denial(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("decision") == "deny"
        and isinstance(payload.get("reason"), str)
        and isinstance(payload.get("tool_name"), str)
    )


def _to_call_tool_result(payload: Any) -> types.CallToolResult:
    if isinstance(payload, types.CallToolResult):
        return payload

    text_content = types.TextContent(type="text", text=_result_text(payload))
    if isinstance(payload, dict):
        return types.CallToolResult(
            content=[text_content],
            structuredContent=payload,
            isError=_is_structured_denial(payload),
        )

    return types.CallToolResult(
        content=[text_content],
        isError=False,
    )


@dataclass
class MCPGateway:
    """Expose a minimal MCP tool surface over an existing ProxyServer."""

    proxy: Any
    tool_catalog: ToolCatalog
    execute_tool: Callable[[Mapping[str, Any]], Any]
    server_name: str = "stipul-mcp-gateway"
    instructions: str = (
        "Minimal Stipul MCP gateway. Tool calls are enforced by the existing Writ proxy."
    )
    server: Server[Any] = field(init=False)

    def __post_init__(self) -> None:
        self.server = Server(
            self.server_name,
            version=__version__,
            instructions=self.instructions,
        )

        @self.server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return list(self._current_tools())

        @self.server.call_tool()
        async def call_tool(tool_name: str, arguments: dict[str, Any]) -> types.CallToolResult:
            raw_request = {
                "tool_name": tool_name,
                "inputs": arguments or {},
                "metadata": {"ingress": "mcp_gateway"},
            }
            result = self.proxy.handle_tool_call(raw_request, self.execute_tool)
            return _to_call_tool_result(result)

    def _current_tools(self) -> Sequence[types.Tool]:
        if callable(self.tool_catalog):
            return self.tool_catalog()
        return self.tool_catalog

    async def run_stdio(self) -> None:
        """Run the gateway over stdio using the MCP SDK transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


__all__ = ["MCPGateway", "ToolCatalog"]
