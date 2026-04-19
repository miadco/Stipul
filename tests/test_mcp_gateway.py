from __future__ import annotations

import json
from pathlib import Path

import anyio
from mcp import ClientSession, types
from mcp.shared.memory import (
    create_client_server_memory_streams,
    create_connected_server_and_client_session,
)

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.writ.proxy.server import ProxyServer
from stipul.utils.canonical import compute_prev_hash

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _build_proxy(contract: Contract, events_path: Path) -> ProxyServer:
    events_path.parent.mkdir(parents=True, exist_ok=True)
    keypair = generate_keypair(events_path.parent / ".stipul" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=events_path.parent,
    )
    return ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=_SESSION_ID,
    )


def _make_tool(name: str, description: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=description,
        inputSchema={
            "type": "object",
            "additionalProperties": True,
        },
    )


def _make_contract(
    base_dict: dict[str, object],
    *,
    allowed_tools: list[str],
    never_allow_tools: list[str],
) -> Contract:
    payload = dict(base_dict)
    payload["allowed_tools"] = allowed_tools
    payload["never_allow_tools"] = never_allow_tools
    return Contract.from_dict(payload)


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _assert_session_open(event: dict[str, object], contract: Contract) -> None:
    assert event["event_type"] == "session_open"
    assert event["reason"] == "session_started"
    assert event["prev_hash"] == compute_contract_hash(contract)


def test_mcp_gateway_initialize_and_tools_list_use_caller_catalog(
    tmp_path: Path,
    contract: Contract,
) -> None:
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    catalog = [
        _make_tool("filesystem.write", "Write a file"),
        _make_tool("shell.exec", "Run a shell command"),
    ]
    gateway = proxy.create_mcp_gateway(
        tool_catalog=lambda: catalog,
        execute_tool=lambda _request: {"ok": True},
    )

    async def scenario() -> None:
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            client_read, client_write = client_streams
            server_read, server_write = server_streams

            async with anyio.create_task_group() as tg:
                tg.start_soon(
                    gateway.server.run,
                    server_read,
                    server_write,
                    gateway.server.create_initialization_options(),
                )
                async with ClientSession(client_read, client_write) as session:
                    init = await session.initialize()
                    assert init.serverInfo.name == "stipul-mcp-gateway"
                    assert init.capabilities.tools is not None

                    listed = await session.list_tools()
                    assert [tool.name for tool in listed.tools] == ["filesystem.write"]

                    catalog.append(_make_tool("web.search", "Search the web"))
                    catalog.append(_make_tool("debug.inspect", "Inspect runtime state"))
                    relisted = await session.list_tools()
                    assert [tool.name for tool in relisted.tools] == [
                        "filesystem.write",
                        "web.search",
                    ]

                tg.cancel_scope.cancel()

    try:
        anyio.run(scenario)
    finally:
        proxy.close()


def test_mcp_gateway_tools_list_filters_mixed_catalog_by_charter(
    tmp_path: Path,
    base_dict: dict[str, object],
) -> None:
    contract = _make_contract(
        base_dict,
        allowed_tools=["web.search"],
        never_allow_tools=["shell.exec"],
    )
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    gateway = proxy.create_mcp_gateway(
        tool_catalog=[
            _make_tool("web.search", "Search the web"),
            _make_tool("shell.exec", "Run a shell command"),
            _make_tool("filesystem.write", "Write a file"),
        ],
        execute_tool=lambda _request: {"ok": True},
    )

    async def scenario() -> list[str]:
        async with create_connected_server_and_client_session(gateway.server) as session:
            listed = await session.list_tools()
            return [tool.name for tool in listed.tools]

    try:
        assert anyio.run(scenario) == ["web.search"]
    finally:
        proxy.close()


def test_mcp_gateway_tools_list_hides_never_allow_tool_when_overlap_exists(
    tmp_path: Path,
    base_dict: dict[str, object],
) -> None:
    contract = _make_contract(
        base_dict,
        allowed_tools=["web.search", "shell.exec"],
        never_allow_tools=["shell.exec"],
    )
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    gateway = proxy.create_mcp_gateway(
        tool_catalog=[
            _make_tool("shell.exec", "Run a shell command"),
            _make_tool("web.search", "Search the web"),
        ],
        execute_tool=lambda _request: {"ok": True},
    )

    async def scenario() -> list[str]:
        async with create_connected_server_and_client_session(gateway.server) as session:
            listed = await session.list_tools()
            return [tool.name for tool in listed.tools]

    try:
        assert anyio.run(scenario) == ["web.search"]
    finally:
        proxy.close()


def test_mcp_gateway_tools_list_filters_callable_catalog_after_dynamic_relisting(
    tmp_path: Path,
    base_dict: dict[str, object],
) -> None:
    contract = _make_contract(
        base_dict,
        allowed_tools=["web.search"],
        never_allow_tools=["shell.exec"],
    )
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    catalog = [_make_tool("shell.exec", "Run a shell command")]
    gateway = proxy.create_mcp_gateway(
        tool_catalog=lambda: catalog,
        execute_tool=lambda _request: {"ok": True},
    )

    async def scenario() -> None:
        async with create_connected_server_and_client_session(gateway.server) as session:
            listed = await session.list_tools()
            assert [tool.name for tool in listed.tools] == []

            catalog.append(_make_tool("web.search", "Search the web"))
            relisted = await session.list_tools()
            assert [tool.name for tool in relisted.tools] == ["web.search"]

    try:
        anyio.run(scenario)
    finally:
        proxy.close()


def test_mcp_gateway_tools_list_returns_empty_when_allowed_tools_is_empty(
    tmp_path: Path,
    base_dict: dict[str, object],
) -> None:
    contract = _make_contract(
        base_dict,
        allowed_tools=[],
        never_allow_tools=["shell.exec"],
    )
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    gateway = proxy.create_mcp_gateway(
        tool_catalog=[
            _make_tool("filesystem.write", "Write a file"),
            _make_tool("web.search", "Search the web"),
        ],
        execute_tool=lambda _request: {"ok": True},
    )

    async def scenario() -> list[str]:
        async with create_connected_server_and_client_session(gateway.server) as session:
            listed = await session.list_tools()
            return [tool.name for tool in listed.tools]

    try:
        assert anyio.run(scenario) == []
    finally:
        proxy.close()


def test_mcp_gateway_tools_call_allow_flows_through_proxy_and_logs_authoritative_event(
    tmp_path: Path,
    contract: Contract,
    monkeypatch,
) -> None:
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    seen: dict[str, object] = {}

    def execute_tool(request: dict[str, object]) -> dict[str, object]:
        seen["request"] = request
        headers = request.get("headers", {})
        auth = headers.get("Authorization") if isinstance(headers, dict) else None
        return {
            "ok": True,
            "tool": request["tool_name"],
            "auth_present": isinstance(auth, str) and auth.startswith("Bearer "),
        }

    gateway = proxy.create_mcp_gateway(
        tool_catalog=[_make_tool("filesystem.write", "Write a file")],
        execute_tool=execute_tool,
    )

    async def scenario() -> types.CallToolResult:
        async with create_connected_server_and_client_session(gateway.server) as session:
            await session.list_tools()
            return await session.call_tool(
                "filesystem.write",
                {"path": "out.txt"},
            )

    try:
        result = anyio.run(scenario)
        assert result.isError is False
        assert result.structuredContent == {
            "ok": True,
            "tool": "filesystem.write",
            "auth_present": True,
        }
        request = seen["request"]
        assert isinstance(request, dict)
        assert request["metadata"] == {"ingress": "mcp_gateway"}

        events = _read_events(events_path)
        assert len(events) == 2
        _assert_session_open(events[0], contract)
        assert events[1]["event_type"] == "tool_call"
        assert events[1]["decision"] == "allow"
        assert events[1]["reason"] == "risk_class"
        assert events[1]["metadata"]["ingress"] == "mcp_gateway"
        attestation = proxy.event_logger.last_attestation
        assert attestation is not None
        assert attestation["kind"] == "chronicle_attestation"
        assert attestation["sequence_id"] == events[1]["sequence_id"]
        assert attestation["event_hash"] == compute_prev_hash(events[1])
        assert attestation["signature"] == events[1]["signature"]
        assert not (events_path.parent / "wrapper_log.jsonl").exists()
    finally:
        proxy.close()


def test_mcp_gateway_tools_call_deny_returns_structured_proxy_denial_and_logs_event(
    tmp_path: Path,
    contract: Contract,
) -> None:
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    called = {"count": 0}

    def execute_tool(_request: dict[str, object]) -> dict[str, object]:
        called["count"] += 1
        return {"ok": True}

    gateway = proxy.create_mcp_gateway(
        tool_catalog=[_make_tool("debug.inspect", "Debug inspection tool")],
        execute_tool=execute_tool,
    )

    async def scenario() -> types.CallToolResult:
        async with create_connected_server_and_client_session(gateway.server) as session:
            await session.list_tools()
            return await session.call_tool(
                "debug.inspect",
                {"target": "x"},
            )

    try:
        result = anyio.run(scenario)
        assert result.isError is True
        assert result.structuredContent == {
            "decision": "deny",
            "reason": "not_in_contract",
            "tool_name": "debug.inspect",
        }
        assert called["count"] == 0

        events = _read_events(events_path)
        assert len(events) == 2
        _assert_session_open(events[0], contract)
        assert events[1]["event_type"] == "tool_call"
        assert events[1]["decision"] == "deny"
        assert events[1]["reason"] == "not_in_contract"
        assert events[1]["metadata"]["ingress"] == "mcp_gateway"
        assert not (events_path.parent / "wrapper_log.jsonl").exists()
    finally:
        proxy.close()


def test_mcp_gateway_kill_switch_denies_before_execution_and_logs_gateway_metadata(
    tmp_path: Path,
    contract: Contract,
) -> None:
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    called = {"count": 0}

    def execute_tool(_request: dict[str, object]) -> dict[str, object]:
        called["count"] += 1
        return {"ok": True}

    proxy.set_kill_switch(
        True,
        updated_by="operator@example.com",
        reason="operator_kill_switch_enabled",
    )
    gateway = proxy.create_mcp_gateway(
        tool_catalog=[_make_tool("filesystem.write", "Write a file")],
        execute_tool=execute_tool,
    )

    async def scenario() -> types.CallToolResult:
        async with create_connected_server_and_client_session(gateway.server) as session:
            await session.list_tools()
            return await session.call_tool(
                "filesystem.write",
                {"path": "out.txt"},
            )

    try:
        result = anyio.run(scenario)
        assert result.isError is True
        assert result.structuredContent == {
            "decision": "deny",
            "reason": "kill_switch_active",
            "tool_name": "filesystem.write",
        }
        assert called["count"] == 0

        events = _read_events(events_path)
        assert events[0]["event_type"] == "session_open"
        assert [(event["event_type"], event["decision"], event["reason"]) for event in events[1:]] == [
            ("elev_op", "allow", "operator_kill_switch_enabled"),
            ("tool_call", "deny", "kill_switch_active"),
        ]
        assert events[-1]["metadata"]["ingress"] == "mcp_gateway"
        assert events[-1]["metadata"]["operator_updated_by"] == "operator@example.com"
        assert not (events_path.parent / "wrapper_log.jsonl").exists()
    finally:
        proxy.close()
