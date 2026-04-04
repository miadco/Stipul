"""Top-level argparse entrypoint for operator tooling."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence
from typing import Any

from stipul.cli.io import CLIError

_COMMAND_MODULES: dict[str, tuple[str, str]] = {
    "demo": (
        "stipul.cli.demo_cmd",
        "Run packaged Stipul demo flows",
    ),
    "init": (
        "stipul.cli.init_cmd",
        "Write a starter Charter policy to disk",
    ),
    "verify": (
        "stipul.cli.verify_cmd",
        "Verify the authoritative signed events stream for a session",
    ),
    "export": (
        "stipul.cli.export_cmd",
        "Export a deterministic evidence bundle from a session directory",
    ),
    "history": (
        "stipul.cli.history_cmd",
        "Render a human-readable timeline from authoritative Chronicle events",
    ),
    "report": (
        "stipul.cli.report_cmd",
        "Render a plain-language report from one Chronicle session",
    ),
    "gateway": (
        "stipul.cli.gateway_cmd",
        "Launch the Writ enforcement proxy as an MCP server",
    ),
    "lint-contract": (
        "stipul.cli.lint_contract_cmd",
        "Lint a Charter policy for operator foot-guns",
    ),
    "operator": (
        "stipul.cli.operator_cmd",
        "Operator kill-switch control",
    ),
    "scan": (
        "stipul.cli.scan_cmd",
        "Run bounded, deterministic scanner checks against a file or directory",
    ),
    "simulate": (
        "stipul.cli.simulate_cmd",
        "Replay an events trace against a Charter policy",
    ),
    "diff": (
        "stipul.cli.diff_cmd",
        "Diff two Charter policies against the same events trace",
    ),
}


def _base_parser() -> tuple[argparse.ArgumentParser, argparse._SubParsersAction[argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(
        prog="stipul",
        description="Stipul operator tooling",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True
    return parser, subparsers


def _load_command_module(command: str) -> Any:
    module_name = _COMMAND_MODULES[command][0]
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise CLIError(
            f"`stipul {command}` requires missing dependency `{exc.name}`.",
            exit_code=3,
        ) from exc


def build_parser(command: str | None = None) -> argparse.ArgumentParser:
    parser, subparsers = _base_parser()
    if command is None:
        for name, (_, help_text) in _COMMAND_MODULES.items():
            subparsers.add_parser(name, help=help_text, add_help=False)
        return parser

    module = _load_command_module(command)
    module.register(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        argv_list = list(argv) if argv is not None else sys.argv[1:]
        if not argv_list:
            parser = build_parser()
            parser.error("a subcommand is required")

        if argv_list[0] in {"-h", "--help"}:
            parser = build_parser()
        else:
            command = argv_list[0]
            if command not in _COMMAND_MODULES:
                parser = build_parser()
            else:
                parser = build_parser(command)

        args = parser.parse_args(argv_list)
        handler = getattr(args, "handler", None)
        if handler is None:
            parser.error("a subcommand is required")
        return int(handler(args))
    except CLIError as exc:
        print(exc.message, file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
