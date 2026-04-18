"""Lint-charter command."""

from __future__ import annotations

import argparse
from pathlib import Path

from stipul.cli.io import CLIError
from stipul.cli.io import write_json
from stipul.charter.contract.loader import load_charter
from stipul.charter.contract.lint import ContractLintResult, lint_contract_payload
from stipul.exceptions import ContractValidationError


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "lint-charter",
        help="Lint a Charter policy for operator foot-guns",
    )
    parser.add_argument("--charter", required=True)
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        loaded = load_charter(Path(args.charter))
        lint_result = lint_contract_payload(loaded.payload, loaded.contract)
        human_output = _format_human(lint_result)
        print(human_output)
        if args.json_out:
            write_json(Path(args.json_out), lint_result.to_dict(), pretty=True, sort_keys=True)
        return 1 if lint_result.errors else 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc


def _format_human(result: ContractLintResult) -> str:
    lines = [
        f"Errors: {len(result.errors)}",
        f"Warnings: {len(result.warnings)}",
        f"Info: {len(result.info)}",
    ]
    for issue in result.issues:
        lines.append(f"{issue.severity} {issue.code}: {issue.message}")
    return "\n".join(lines)
