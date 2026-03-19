"""Thin operator CLI for kill-switch control."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from stipul.cli.io import CLIError, ensure_session_dir
from stipul.exceptions import ContractValidationError
from stipul.writ.proxy.approval_state import ApprovalStateError
from stipul.writ.proxy.operator_state import OperatorStateError
from stipul.writ.proxy.server import ProxyServer
from stipul.writ.proxy.session_lock import SessionLockError

_DEFAULT_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "operator",
        help="Operator kill-switch control",
    )
    operator_subparsers = parser.add_subparsers(dest="operator_command")
    operator_subparsers.required = True

    status_parser = operator_subparsers.add_parser(
        "status",
        help="Show current operator status from the proxy health surface",
    )
    _add_common_proxy_args(status_parser)
    status_parser.set_defaults(handler=run)

    kill_switch_parser = operator_subparsers.add_parser(
        "kill-switch",
        help="Enable or disable the proxy kill switch",
    )
    kill_switch_subparsers = kill_switch_parser.add_subparsers(dest="kill_switch_action")
    kill_switch_subparsers.required = True

    for action, help_text in (
        ("enable", "Enable the kill switch"),
        ("disable", "Disable the kill switch"),
    ):
        action_parser = kill_switch_subparsers.add_parser(action, help=help_text)
        _add_common_proxy_args(action_parser)
        action_parser.add_argument("--by", required=True)
        action_parser.add_argument("--reason", required=True)
        action_parser.set_defaults(handler=run)

    approval_parser = operator_subparsers.add_parser(
        "approval",
        help="Inspect or approve quorum-gated requests",
    )
    approval_subparsers = approval_parser.add_subparsers(dest="approval_action")
    approval_subparsers.required = True

    approval_status_parser = approval_subparsers.add_parser(
        "status",
        help="Show current approval requests",
    )
    _add_common_proxy_args(approval_status_parser)
    approval_status_parser.add_argument("--request-id")
    approval_status_parser.set_defaults(handler=run)

    approval_approve_parser = approval_subparsers.add_parser(
        "approve",
        help="Add an approval to an existing request",
    )
    _add_common_proxy_args(approval_approve_parser)
    approval_approve_parser.add_argument("--request-id", required=True)
    approval_approve_parser.add_argument("--by", required=True)
    approval_approve_parser.set_defaults(handler=run)


def _add_common_proxy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--contract", required=True)


def _read_first_session_id(events_path: Path) -> str | None:
    try:
        with Path(events_path).open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CLIError(
                        f"Invalid JSON in {events_path}: line 1 column {exc.colno}",
                        exit_code=3,
                    ) from exc
                if not isinstance(payload, dict):
                    raise CLIError(f"events.jsonl first record must be a JSON object: {events_path}")
                session_id = payload.get("session_id")
                if not isinstance(session_id, str) or not session_id:
                    raise CLIError(f"events.jsonl first record missing session_id: {events_path}")
                return session_id
    except FileNotFoundError as exc:
        raise CLIError(f"Session directory missing events.jsonl: {events_path.parent}", exit_code=3) from exc
    return None


def _resolve_session_id(session_dir: Path) -> str:
    return _read_first_session_id(session_dir / "events.jsonl") or _DEFAULT_SESSION_ID


def _build_proxy(session_dir: Path, contract_path: Path) -> ProxyServer:
    return ProxyServer.from_contract_path(
        contract_path,
        session_id=_resolve_session_id(session_dir),
        events_path=session_dir / "events.jsonl",
    )


def _status_payload(proxy: ProxyServer) -> dict[str, Any]:
    # Reuse the proxy's read path so CLI status reflects the same authority Writ enforces.
    state = proxy._refresh_operator_state()
    if state is not None:
        proxy.health.update_operator_status(
            kill_switch_active=state.kill_switch_active,
            updated_at=state.updated_at,
            updated_by=state.updated_by,
            reason=state.reason,
        )
    return proxy.health.payload()


def _display_value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _print_status(payload: dict[str, Any]) -> None:
    print(f"status: {_display_value(payload.get('status'))}")
    print(f"kill_switch_active: {_display_value(payload.get('kill_switch_active'))}")
    print(f"operator_updated_at: {_display_value(payload.get('operator_updated_at'))}")
    print(f"operator_updated_by: {_display_value(payload.get('operator_updated_by'))}")
    print(f"operator_reason: {_display_value(payload.get('operator_reason'))}")


def _print_approval_status(payload: dict[str, Any]) -> None:
    requests = payload.get("requests", [])
    if not isinstance(requests, list):
        raise CLIError("approval status payload is malformed", exit_code=3)
    print(f"request_count: {payload.get('request_count', len(requests))}")
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            raise CLIError("approval request entry is malformed", exit_code=3)
        if index:
            print("")
        print(f"request_id: {_display_value(request.get('request_id'))}")
        print(f"status: {_display_value(request.get('status'))}")
        print(
            "approval_count: "
            f"{_display_value(request.get('approval_count'))}/"
            f"{_display_value(request.get('required_approver_count'))}"
        )
        print(f"tool_name: {_display_value(request.get('tool_name'))}")
        print(f"expires_at: {_display_value(request.get('expires_at'))}")
        approver_ids = request.get("approver_ids")
        if isinstance(approver_ids, list):
            approvers_text = ",".join(str(item) for item in approver_ids) or "-"
        else:
            approvers_text = _display_value(approver_ids)
        print(f"approver_ids: {approvers_text}")
        print(f"derived_permit_id: {_display_value(request.get('derived_permit_id'))}")


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        proxy = _build_proxy(session_dir, Path(args.contract))
        try:
            if args.operator_command == "kill-switch":
                proxy.set_kill_switch(
                    args.kill_switch_action == "enable",
                    updated_by=args.by,
                    reason=args.reason,
                )
                _print_status(_status_payload(proxy))
            elif args.operator_command == "approval":
                if args.approval_action == "approve":
                    payload = {
                        "request_count": 1,
                        "requests": [
                            proxy.approve_approval_request(
                                args.request_id,
                                args.by,
                            )
                        ],
                    }
                else:
                    payload = proxy.approval_status(getattr(args, "request_id", None))
                _print_approval_status(payload)
            else:
                _print_status(_status_payload(proxy))
            return 0
        finally:
            proxy.close()
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (
        ApprovalStateError,
        ContractValidationError,
        OperatorStateError,
        SessionLockError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
