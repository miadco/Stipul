"""Scan command for bounded, deterministic repository checks."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentshield.cli.io import CLIError, write_json
from agentshield.scanner import MCPScanner, SEVERITY_ORDER, format_scan_report, severity_trips_threshold


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "scan",
        help="Run bounded, deterministic scanner checks against a file or directory",
    )
    parser.add_argument("path")
    parser.add_argument("--json-out")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=list(SEVERITY_ORDER.keys()),
    )
    parser.add_argument("--max-file-bytes", type=int, default=512_000)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        scanner = MCPScanner(max_file_bytes=args.max_file_bytes)
        report = scanner.scan_path(Path(args.path))
        print(format_scan_report(report))
        if args.json_out:
            write_json(Path(args.json_out), report.to_dict(), pretty=True, sort_keys=True)
        return 1 if severity_trips_threshold(report.findings, args.fail_on) else 0
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
