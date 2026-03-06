"""Simulate command."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path

from agentshield.cli.io import CLIError
from agentshield.cli.io import read_json, write_json
from agentshield.contract.schema import Contract
from agentshield.exceptions import ContractValidationError
from agentshield.simulation.simulator import PolicySimulator


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "simulate",
        help="Replay an events trace against a contract",
    )
    parser.add_argument("--events", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--json-out")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        events_path = Path(args.events)
        if not events_path.exists():
            raise CLIError(f"Events file not found: {events_path}", exit_code=3)
        contract_payload = read_json(Path(args.contract))
        if not isinstance(contract_payload, dict):
            raise CLIError(f"Contract JSON must be an object: {args.contract}", exit_code=3)
        contract = Contract.from_dict(contract_payload)
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
