"""CLI launch surface for MCP gateway mode."""

from __future__ import annotations

import argparse
import importlib
from pathlib import Path
from typing import Any

from stipul.cli.io import CLIError
from stipul.exceptions import ContractValidationError
from stipul.writ.proxy.server import ProxyServer
from stipul.writ.proxy.session_lock import SessionLockError


class _AnyIOProxy:
    def run(self, target: Any) -> Any:
        try:
            import anyio as anyio_module
        except ModuleNotFoundError as exc:
            if exc.name != "anyio":
                raise
            raise CLIError(
                "MCP gateway requires the optional `anyio` dependency. "
                "Install it before using `stipul gateway mcp`.",
                exit_code=3,
            ) from exc
        return anyio_module.run(target)


anyio = _AnyIOProxy()


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "gateway",
        help="Launch the MCP gateway over the existing proxy core",
    )
    gateway_subparsers = parser.add_subparsers(dest="gateway_command")
    gateway_subparsers.required = True

    mcp_parser = gateway_subparsers.add_parser(
        "mcp",
        help="Run the MCP gateway over stdio",
    )
    mcp_parser.add_argument("--contract", required=True)
    mcp_parser.add_argument("--session-dir", required=True)
    mcp_parser.add_argument("--session-id", required=True)
    mcp_parser.add_argument(
        "--control-port",
        type=int,
        help="Start the existing loopback control sidecar on this local port (use 0 for auto)",
    )
    mcp_parser.add_argument(
        "--runtime",
        required=True,
        help="Import path to runtime factory in the form module:callable",
    )
    mcp_parser.set_defaults(handler=run)


def _load_runtime_factory(spec: str) -> Any:
    module_name, sep, attr_name = spec.partition(":")
    if not module_name or not sep or not attr_name:
        raise CLIError(
            "runtime must use the form module:callable",
            exit_code=3,
        )

    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise CLIError(f"runtime module not found: {module_name}", exit_code=3) from exc

    factory = getattr(module, attr_name, None)
    if factory is None:
        raise CLIError(
            f"runtime factory not found: {spec}",
            exit_code=3,
        )
    if not callable(factory):
        raise CLIError(
            f"runtime target is not callable: {spec}",
            exit_code=3,
        )
    return factory


def _load_runtime(spec: str, proxy: ProxyServer) -> tuple[Any, Any]:
    factory = _load_runtime_factory(spec)
    runtime = factory(proxy)
    if not isinstance(runtime, dict):
        raise CLIError(
            "runtime factory must return a dict with tool_catalog and execute_tool",
            exit_code=3,
        )

    tool_catalog = runtime.get("tool_catalog")
    execute_tool = runtime.get("execute_tool")
    if tool_catalog is None:
        raise CLIError("runtime factory missing tool_catalog", exit_code=3)
    if execute_tool is None or not callable(execute_tool):
        raise CLIError("runtime factory missing callable execute_tool", exit_code=3)
    return tool_catalog, execute_tool


def run(args: argparse.Namespace) -> int:
    try:
        control_port = getattr(args, "control_port", None)
        if control_port is not None and control_port < 0:
            raise CLIError("--control-port must be >= 0", exit_code=3)
        session_dir = Path(args.session_dir)
        proxy = ProxyServer.from_contract_path(
            args.contract,
            session_id=args.session_id,
            events_path=session_dir / "events.jsonl",
        )
        try:
            if control_port is not None:
                proxy.start_control_sidecar(port=control_port)
            tool_catalog, execute_tool = _load_runtime(args.runtime, proxy)
            gateway = proxy.create_mcp_gateway(
                tool_catalog=tool_catalog,
                execute_tool=execute_tool,
            )
            anyio.run(gateway.run_stdio)
            return 0
        finally:
            proxy.close()
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, SessionLockError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
