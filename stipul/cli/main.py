"""Top-level argparse entrypoint for operator tooling."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from stipul.cli import diff_cmd, export_cmd, lint_contract_cmd, scan_cmd, simulate_cmd, verify_cmd
from stipul.cli.io import CLIError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stipul",
        description="Stipul operator tooling",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True
    verify_cmd.register(subparsers)
    export_cmd.register(subparsers)
    lint_contract_cmd.register(subparsers)
    scan_cmd.register(subparsers)
    simulate_cmd.register(subparsers)
    diff_cmd.register(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("a subcommand is required")
    try:
        return int(handler(args))
    except CLIError as exc:
        print(exc.message, file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
