"""Export command for evidence bundles."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentshield.cli.io import CLIError
from agentshield.cli.io import ensure_session_dir, read_json
from agentshield.contract.schema import Contract
from agentshield.exceptions import ContractValidationError
from agentshield.exporter import export_session_bundle


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "export",
        help="Export a deterministic evidence bundle from a session directory",
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--public-key")
    parser.add_argument("--scan-report")
    parser.add_argument("--redact", action="store_true")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        contract_payload = read_json(Path(args.contract))
        if not isinstance(contract_payload, dict):
            raise CLIError(f"Contract JSON must be an object: {args.contract}", exit_code=3)
        contract = Contract.from_dict(contract_payload)
        public_key_path = Path(args.public_key) if args.public_key else None
        scan_report_path = Path(args.scan_report) if args.scan_report else None
        if public_key_path is not None and not public_key_path.exists():
            raise CLIError(f"Public key file not found: {public_key_path}", exit_code=3)
        if scan_report_path is not None and not scan_report_path.exists():
            raise CLIError(f"Scan report file not found: {scan_report_path}", exit_code=3)

        manifest = export_session_bundle(
            session_dir,
            Path(args.out_dir),
            contract=contract,
            public_key_path=public_key_path,
            scan_report_path=scan_report_path,
            redact=args.redact,
        )
        print(
            "Export complete\n"
            f"Bundle: {Path(args.out_dir)}\n"
            f"Files: {len(manifest['included_files'])}\n"
            f"Top-level SHA256: {manifest['top_level_sha256']}"
        )
        return 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
