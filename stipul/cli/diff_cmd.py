"""Diff command."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path

from stipul.cli.io import CLIError
from stipul.cli.io import write_json
from stipul.charter.contract.loader import load_charter
from stipul.exceptions import ContractValidationError
from stipul.simulation.simulator import PolicySimulator


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "diff",
        help="Diff two Charter policies against the same events trace",
    )
    parser.add_argument("--events", required=True)
    parser.add_argument("--contract-a", required=True)
    parser.add_argument("--contract-b", required=True)
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        events_path = Path(args.events)
        if not events_path.exists():
            raise CLIError(f"Events file not found: {events_path}", exit_code=3)
        contract_a = load_charter(Path(args.contract_a)).contract
        contract_b = load_charter(Path(args.contract_b)).contract
        simulator = PolicySimulator()
        diff = simulator.diff(events_path, contract_a, contract_b)
        print(simulator.format_diff(diff))
        if args.json_out:
            write_json(Path(args.json_out), asdict(diff), pretty=True, sort_keys=True)
        return 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
