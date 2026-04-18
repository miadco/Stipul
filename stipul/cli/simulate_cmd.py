"""Simulate command."""

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
        "simulate",
        help="Replay an events trace against a Charter policy",
    )
    parser.add_argument("--events", required=True)
    parser.add_argument("--charter", required=True)
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        events_path = Path(args.events)
        if not events_path.exists():
            raise CLIError(f"Events file not found: {events_path}", exit_code=3)
        contract = load_charter(Path(args.charter)).contract
        simulator = PolicySimulator()
        summary = simulator.simulate(events_path, contract)
        print(simulator.format_results(summary))
        if args.json_out:
            write_json(Path(args.json_out), asdict(summary), pretty=True, sort_keys=True)
        return 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
