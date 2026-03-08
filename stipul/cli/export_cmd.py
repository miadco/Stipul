"""Export command for evidence bundles."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stipul.charter.contract.loader import load_charter
from stipul.cli.io import CLIError
from stipul.cli.io import ensure_session_dir
from stipul.exceptions import ContractValidationError
from stipul.seal.exporter import export_session_bundle
from stipul.seal.rfc3161_anchor import (
    rfc3161_receipt_path,
    timestamp_export_bundle_rfc3161,
)
from stipul.seal.siem_export import SiemExportFilters, export_siem_jsonl, siem_manifest_path


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
    parser.add_argument("--siem-out")
    parser.add_argument("--event-type")
    parser.add_argument("--decision")
    parser.add_argument("--ingress")
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--timestamp-rfc3161")
    parser.set_defaults(handler=run)


def _format_serial_number(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _format_tsa_gen_time(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value.endswith("Z") or value.endswith("+00:00"):
        return value[:-6] + "Z" if value.endswith("+00:00") else value
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        return value
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        loaded = load_charter(Path(args.contract))
        contract = loaded.contract
        public_key_path = Path(args.public_key) if args.public_key else None
        scan_report_path = Path(args.scan_report) if args.scan_report else None
        if public_key_path is not None and not public_key_path.exists():
            raise CLIError(f"Public key file not found: {public_key_path}", exit_code=3)
        if scan_report_path is not None and not scan_report_path.exists():
            raise CLIError(f"Scan report file not found: {scan_report_path}", exit_code=3)
        if args.redact and args.timestamp_rfc3161:
            raise CLIError("--redact is incompatible with --timestamp-rfc3161", exit_code=3)
        if (
            args.siem_out is None
            and any(
                value is not None
                for value in (
                    args.event_type,
                    args.decision,
                    args.ingress,
                    args.since,
                    args.until,
                )
            )
        ):
            raise CLIError("SIEM filters require --siem-out", exit_code=3)

        bundle_dir = Path(args.out_dir)
        manifest = export_session_bundle(
            session_dir,
            bundle_dir,
            contract=contract,
            public_key_path=public_key_path,
            scan_report_path=scan_report_path,
            redact=args.redact,
        )
        siem_output_path = Path(args.siem_out) if args.siem_out else None
        siem_manifest: dict[str, object] | None = None
        if siem_output_path is not None:
            filters = SiemExportFilters.create(
                event_type=args.event_type,
                decision=args.decision,
                ingress=args.ingress,
                since=args.since,
                until=args.until,
            )
            siem_manifest = export_siem_jsonl(
                session_dir,
                siem_output_path,
                filters=filters,
            )
        timestamp_receipt: dict[str, object] | None = None
        if args.timestamp_rfc3161:
            timestamp_receipt = timestamp_export_bundle_rfc3161(
                bundle_dir,
                args.timestamp_rfc3161,
            )
        print(
            "Export complete\n"
            f"Bundle: {bundle_dir}\n"
            f"Files: {len(manifest['included_files'])}\n"
            f"Top-level SHA256: {manifest['top_level_sha256']}"
        )
        if siem_output_path is not None and siem_manifest is not None:
            print(
                f"SIEM JSONL: {siem_output_path}\n"
                f"SIEM manifest: {siem_manifest_path(siem_output_path)}\n"
                f"Source events SHA256: {siem_manifest['source_events_sha256']}"
            )
        if timestamp_receipt is not None:
            output_lines = [
                f"RFC 3161 TSA: {timestamp_receipt['tsa_url']}",
                f"RFC 3161 receipt: {rfc3161_receipt_path(bundle_dir)}",
            ]
            tsa_gen_time = _format_tsa_gen_time(timestamp_receipt.get("tsa_gen_time"))
            if tsa_gen_time is not None:
                output_lines.append(f"TSA generation time: {tsa_gen_time}")
            serial_number = _format_serial_number(timestamp_receipt.get("serial_number"))
            if serial_number is not None:
                output_lines.append(f"TSA serial number: {serial_number}")
            print("\n".join(output_lines))
        return 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
