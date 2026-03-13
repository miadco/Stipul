from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StdioConnection
from mcp import types

if TYPE_CHECKING:
    from collections.abc import Sequence

    from langchain_core.tools import BaseTool

DEFAULT_SESSION_ID = "11111111-1111-1111-1111-111111111111"
DEFAULT_TOKEN_SECRET = "langgraph-demo-secret"
DEFAULT_RUNTIME_MODULE = "langgraph_stdio"
DEFAULT_AGENT_ID = "agent.langgraph_stdio"
DEFAULT_SERVER_NAME = "stipul"


def integration_dir() -> Path:
    return Path(__file__).resolve().parent


def repo_root() -> Path:
    return integration_dir().parents[1]


def venv_python() -> Path:
    return repo_root() / ".venv" / "bin" / "python"


def runtime_spec() -> str:
    return f"{DEFAULT_RUNTIME_MODULE}:build_runtime"


def _coerce_inputs(request: Mapping[str, Any]) -> dict[str, Any]:
    value = request.get("inputs", request.get("input", {}))
    if isinstance(value, dict):
        return dict(value)
    if value is None:
        return {}
    return {"value": value}


def _required_path(inputs: Mapping[str, Any]) -> Path:
    raw_path = inputs.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("path must be a non-empty string")
    return Path(raw_path).expanduser().resolve()


def _merge_pythonpath(*entries: Path) -> str:
    existing = os.environ.get("PYTHONPATH")
    values = [str(entry) for entry in entries]
    if existing:
        values.append(existing)
    return os.pathsep.join(values)


def build_demo_contract_dict() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "contract_id": "55555555-5555-5555-5555-555555555555",
        "parent_contract_id": None,
        "created_at": "2026-03-10T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "signed_by": None,
        "identity_agent_id": DEFAULT_AGENT_ID,
        "identity_code_sha256": None,
        "allowed_tools": [
            "filesystem.read",
            "filesystem.delete",
        ],
        "never_allow_tools": [
            "shell.exec",
        ],
        "tool_risk_classes": {
            "filesystem.read": "read",
            "filesystem.delete": "irreversible",
        },
        "max_tool_calls": 20,
        "max_net_calls": 5,
        "egress_allowlist": [
            "api.example.com",
        ],
        "approval_quorum": 1,
    }


def write_demo_contract(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_demo_contract_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def read_events(events_path: Path) -> list[dict[str, Any]]:
    if not events_path.exists():
        return []
    return [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def latest_public_key_path(home_dir: Path) -> Path:
    keys_dir = home_dir / ".stipul" / "keys"
    candidates = sorted(keys_dir.glob("runtime_*.pub"))
    if not candidates:
        raise FileNotFoundError(f"No runtime public key found under {keys_dir}")
    return candidates[-1]


def tamper_last_event(events_path: Path) -> None:
    events = read_events(events_path)
    if not events:
        raise ValueError("events.jsonl is empty")
    events[-1]["reason"] = "tampered_reason"
    events_path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def parse_tool_result(result: object) -> dict[str, Any]:
    if not isinstance(result, list) or len(result) != 1:
        raise TypeError(f"Expected one content block, got {result!r}")
    block = result[0]
    if not isinstance(block, dict):
        raise TypeError(f"Expected a dict content block, got {block!r}")
    if block.get("type") != "text":
        raise ValueError(f"Expected a text block, got {block!r}")
    text = block.get("text")
    if not isinstance(text, str):
        raise TypeError(f"Expected text content, got {block!r}")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise TypeError(f"Expected a JSON object payload, got {payload!r}")
    return payload


def parse_tool_exception(exc: BaseException) -> dict[str, Any]:
    payload = json.loads(str(exc))
    if not isinstance(payload, dict):
        raise TypeError(f"Expected a JSON object payload, got {payload!r}")
    return payload


def select_tool(tools: Sequence[BaseTool], name: str) -> BaseTool:
    for tool in tools:
        if tool.name == name:
            return tool
    raise KeyError(f"Tool {name!r} not found in {[tool.name for tool in tools]!r}")


@dataclass(frozen=True)
class StipulLangGraphConfig:
    contract_path: Path
    session_dir: Path
    session_id: str = DEFAULT_SESSION_ID
    home_dir: Path | None = None
    token_secret: str = DEFAULT_TOKEN_SECRET
    control_port: int | None = None
    server_name: str = DEFAULT_SERVER_NAME

    def connection(self) -> StdioConnection:
        launch_home = self.home_dir or (self.session_dir / "home")
        launch_env = {
            "HOME": str(launch_home),
            "PYTHONPATH": _merge_pythonpath(repo_root(), integration_dir()),
            "STIPUL_TOKEN_SECRET": self.token_secret,
        }
        args = [
            "-m",
            "stipul.cli.main",
            "gateway",
            "mcp",
            "--contract",
            str(self.contract_path),
            "--session-dir",
            str(self.session_dir),
            "--session-id",
            self.session_id,
            "--runtime",
            runtime_spec(),
        ]
        if self.control_port is not None:
            args.extend(["--control-port", str(self.control_port)])
        connection: StdioConnection = {
            "transport": "stdio",
            "command": str(venv_python()),
            "args": args,
            "cwd": str(repo_root()),
            "env": launch_env,
        }
        return connection

    def client(self) -> MultiServerMCPClient:
        return MultiServerMCPClient({self.server_name: self.connection()})

    async def get_tools(self) -> list[BaseTool]:
        return await self.client().get_tools(server_name=self.server_name)

    async def call_raw_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        client = self.client()
        async with client.session(self.server_name) as session:
            return await session.call_tool(tool_name, dict(arguments))


def build_runtime(_proxy: object) -> dict[str, object]:
    return {
        "tool_catalog": _tool_catalog(),
        "execute_tool": execute_tool,
    }


def _tool_catalog() -> list[types.Tool]:
    return [
        types.Tool(
            name="filesystem.read",
            description="Read UTF-8 text from a file path.",
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
            name="filesystem.write",
            description="Write UTF-8 text to a file path.",
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
            name="filesystem.delete",
            description="Delete a file path.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
    ]


def execute_tool(request: Mapping[str, Any]) -> dict[str, Any]:
    tool_name = request.get("tool_name", "unknown_tool")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    inputs = _coerce_inputs(request)
    path = _required_path(inputs)

    if tool_name == "filesystem.read":
        content = path.read_text(encoding="utf-8")
        return {
            "ok": True,
            "tool_name": tool_name,
            "path": str(path),
            "content": content,
        }

    if tool_name == "filesystem.write":
        raw_content = inputs.get("content")
        if not isinstance(raw_content, str):
            raise ValueError("content must be a string")
        content = raw_content
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {
            "ok": True,
            "tool_name": tool_name,
            "path": str(path),
            "bytes_written": len(content.encode("utf-8")),
        }

    if tool_name == "filesystem.delete":
        existed = path.exists()
        if existed:
            path.unlink()
        return {
            "ok": True,
            "tool_name": tool_name,
            "path": str(path),
            "deleted": existed,
        }

    return {
        "ok": False,
        "tool_name": tool_name,
        "reason": "runtime_unknown_tool",
    }


__all__ = [
    "DEFAULT_AGENT_ID",
    "DEFAULT_RUNTIME_MODULE",
    "DEFAULT_SERVER_NAME",
    "DEFAULT_SESSION_ID",
    "DEFAULT_TOKEN_SECRET",
    "StipulLangGraphConfig",
    "build_demo_contract_dict",
    "build_runtime",
    "execute_tool",
    "integration_dir",
    "latest_public_key_path",
    "parse_tool_exception",
    "parse_tool_result",
    "read_events",
    "repo_root",
    "runtime_spec",
    "select_tool",
    "tamper_last_event",
    "venv_python",
    "write_demo_contract",
]
