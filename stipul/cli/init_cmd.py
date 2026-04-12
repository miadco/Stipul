"""Init command — write a starter Charter policy to disk."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Iterator

from stipul.cli.io import CLIError


@contextmanager
def _starter_charter_path() -> Iterator[Path]:
    resource = files("stipul.templates").joinpath("starter.yaml")
    with as_file(resource) as path:
        yield Path(path)


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "init",
        help="Write a starter Charter policy to disk",
    )
    parser.add_argument(
        "--output",
        default="charter.yaml",
        help="Destination path (default: charter.yaml)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists",
    )
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists() and not args.force:
        raise CLIError(
            f"Output file already exists: {output}. "
            "Use --force to overwrite or choose a different path.",
            exit_code=1,
        )
    with _starter_charter_path() as charter_path:
        output.write_bytes(charter_path.read_bytes())
    print(f"Wrote starter charter to {output}")
    print(f"Next: edit this Charter at {output} and run: stipul lint-contract {output}")
    return 0
