from __future__ import annotations

import argparse
import types
from pathlib import Path

import pytest
from mcp import types as mcp_types

from stipul.cli import gateway_cmd
from stipul.cli.io import CLIError
from stipul.examples.echo_runtime import build_runtime as build_echo_runtime


def test_packaged_echo_runtime_factory_is_importable_and_returns_expected_shape() -> None:
    runtime = build_echo_runtime(object())

    assert set(runtime) == {"tool_catalog", "execute_tool"}
    tool_catalog = runtime["tool_catalog"]
    execute_tool = runtime["execute_tool"]
    assert isinstance(tool_catalog, list)
    assert len(tool_catalog) == 1
    assert tool_catalog[0].name == "demo.echo"
    assert callable(execute_tool)
    assert execute_tool(
        {"tool_name": "demo.echo", "inputs": {"message": "hello"}}
    ) == {
        "ok": True,
        "tool_name": "demo.echo",
        "inputs": {"message": "hello"},
    }


def test_gateway_cli_constructs_proxy_and_runs_existing_gateway(monkeypatch, tmp_path: Path) -> None:
    runtime_catalog = [
        mcp_types.Tool(
            name="filesystem.write",
            description="Write a file",
            inputSchema={"type": "object"},
        )
    ]

    def runtime_execute_tool(_request: dict[str, object]) -> dict[str, object]:
        return {"ok": True}

    runtime_module = types.ModuleType("fake_gateway_runtime")

    def build_runtime(proxy: object) -> dict[str, object]:
        return {
            "tool_catalog": runtime_catalog,
            "execute_tool": runtime_execute_tool,
            "proxy": proxy,
        }

    runtime_module.build_runtime = build_runtime

    created: dict[str, object] = {}

    class FakeGateway:
        async def run_stdio(self) -> None:
            created["run_stdio_called"] = True

    class FakeProxy:
        def start_control_sidecar(self, *, port: int) -> str:
            created["control_port"] = port
            return "http://127.0.0.1:43123"

        def create_mcp_gateway(
            self,
            *,
            tool_catalog: object,
            execute_tool: object,
            tool_visibility: str,
        ) -> FakeGateway:
            created["tool_catalog"] = tool_catalog
            created["execute_tool"] = execute_tool
            created["tool_visibility"] = tool_visibility
            return FakeGateway()

        def close(self) -> None:
            created["closed"] = True

    def fake_from_contract_path(
        contract_path: str,
        *,
        session_id: str,
        events_path: Path,
    ) -> FakeProxy:
        created["contract_path"] = contract_path
        created["session_id"] = session_id
        created["events_path"] = events_path
        return FakeProxy()

    def fake_import_module(name: str) -> types.ModuleType:
        assert name == "fake_gateway_runtime"
        return runtime_module

    def fake_anyio_run(fn: object) -> None:
        created["run_target"] = fn

    monkeypatch.setattr(gateway_cmd.ProxyServer, "from_contract_path", fake_from_contract_path)
    monkeypatch.setattr(gateway_cmd.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(gateway_cmd.anyio, "run", fake_anyio_run)

    args = argparse.Namespace(
        charter=str(tmp_path / "contract.yaml"),
        session_dir=str(tmp_path / "session"),
        session_id="11111111-1111-1111-1111-111111111111",
        control_port=None,
        runtime="fake_gateway_runtime:build_runtime",
        tool_visibility="governed",
    )

    result = gateway_cmd.run(args)

    assert result == 0
    assert created["contract_path"] == str(tmp_path / "contract.yaml")
    assert created["session_id"] == "11111111-1111-1111-1111-111111111111"
    assert created["events_path"] == tmp_path / "session" / "events.jsonl"
    assert created["tool_catalog"] is runtime_catalog
    assert created["execute_tool"] is runtime_execute_tool
    assert created["tool_visibility"] == "governed"
    assert getattr(created["run_target"], "__name__", "") == "run_stdio"
    assert created["closed"] is True
    assert "control_port" not in created


def test_gateway_cli_requires_runtime_factory_shape(monkeypatch, tmp_path: Path) -> None:
    runtime_module = types.ModuleType("bad_gateway_runtime")

    def build_runtime(_proxy: object) -> dict[str, object]:
        return {"tool_catalog": []}

    runtime_module.build_runtime = build_runtime

    class FakeProxy:
        def close(self) -> None:
            return None

    monkeypatch.setattr(
        gateway_cmd.ProxyServer,
        "from_contract_path",
        lambda *args, **kwargs: FakeProxy(),
    )
    monkeypatch.setattr(
        gateway_cmd.importlib,
        "import_module",
        lambda name: runtime_module,
    )

    args = argparse.Namespace(
        charter=str(tmp_path / "contract.yaml"),
        session_dir=str(tmp_path / "session"),
        session_id="11111111-1111-1111-1111-111111111111",
        control_port=None,
        runtime="bad_gateway_runtime:build_runtime",
        tool_visibility="allowed",
    )

    with pytest.raises(CLIError, match="missing callable execute_tool"):
        gateway_cmd.run(args)


def test_gateway_cli_optional_control_port_starts_existing_sidecar(monkeypatch, tmp_path: Path) -> None:
    runtime_module = types.ModuleType("fake_gateway_runtime")

    def build_runtime(_proxy: object) -> dict[str, object]:
        return {
            "tool_catalog": [],
            "execute_tool": lambda _request: {"ok": True},
        }

    runtime_module.build_runtime = build_runtime
    created: dict[str, object] = {}

    class FakeGateway:
        async def run_stdio(self) -> None:
            created["run_stdio_called"] = True

    class FakeProxy:
        def start_control_sidecar(self, *, port: int) -> str:
            created["control_port"] = port
            created["control_url"] = f"http://127.0.0.1:{port if port else 43123}"
            return str(created["control_url"])

        def create_mcp_gateway(
            self,
            *,
            tool_catalog: object,
            execute_tool: object,
            tool_visibility: str,
        ) -> FakeGateway:
            created["tool_catalog"] = tool_catalog
            created["execute_tool"] = execute_tool
            created["tool_visibility"] = tool_visibility
            return FakeGateway()

        def close(self) -> None:
            created["closed"] = True

    monkeypatch.setattr(
        gateway_cmd.ProxyServer,
        "from_contract_path",
        lambda *args, **kwargs: FakeProxy(),
    )
    monkeypatch.setattr(
        gateway_cmd.importlib,
        "import_module",
        lambda name: runtime_module,
    )
    monkeypatch.setattr(
        gateway_cmd.anyio,
        "run",
        lambda fn: created.setdefault("run_target", fn),
    )

    args = argparse.Namespace(
        charter=str(tmp_path / "contract.yaml"),
        session_dir=str(tmp_path / "session"),
        session_id="11111111-1111-1111-1111-111111111111",
        control_port=0,
        runtime="fake_gateway_runtime:build_runtime",
        tool_visibility="allowed",
    )

    result = gateway_cmd.run(args)

    assert result == 0
    assert created["control_port"] == 0
    assert str(created["control_url"]).startswith("http://127.0.0.1:")
    assert created["tool_visibility"] == "allowed"
    assert getattr(created["run_target"], "__name__", "") == "run_stdio"
    assert created["closed"] is True
