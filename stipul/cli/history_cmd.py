"""History command for human-readable Chronicle timelines."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from stipul.chronicle.events.models import CanonicalEvent
from stipul.cli.io import CLIError, read_jsonl

_DECISION_LABELS = {
    "allow": "allowed",
    "deny": "denied",
    "require_approval": "approval required",
}
_TARGET_KEYS = (
    "path",
    "target",
    "filepath",
    "file",
    "filename",
    "egress_target",
    "url",
    "host",
    "destination",
)


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "history",
        help="Render a human-readable timeline from authoritative Chronicle events",
    )
    parser.add_argument(
        "--events",
        default="events.jsonl",
        help="Path to the authoritative events.jsonl file (default: ./events.jsonl)",
    )
    parser.add_argument("--session-id", help="Only show events for one session ID")
    parser.add_argument(
        "--limit",
        type=int,
        help="Show at most the most recent N events after filtering",
    )
    parser.set_defaults(handler=run)


def _load_canonical_events(path: Path) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for record_index, payload in enumerate(read_jsonl(path), start=1):
        try:
            events.append(CanonicalEvent(**payload))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid canonical event in {path}: record {record_index}: {exc}"
            ) from exc
    return events


def _string_field(mapping: dict[str, Any] | None, key: str) -> str | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _approval_context(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    if metadata is None:
        return None
    value = metadata.get("approval_context")
    if isinstance(value, dict):
        return value
    return None


def _request_id(metadata: dict[str, Any] | None) -> str | None:
    approval_context = _approval_context(metadata)
    return _string_field(approval_context, "request_id")


def _target_hint(metadata: dict[str, Any] | None) -> str | None:
    if metadata is None:
        return None
    for key in _TARGET_KEYS:
        value = _string_field(metadata, key)
        if value is not None:
            return value
    approval_context = _approval_context(metadata)
    for key in _TARGET_KEYS:
        value = _string_field(approval_context, key)
        if value is not None:
            return value
    return None


def _reason_text(event: CanonicalEvent) -> str | None:
    reason = event.reason
    if reason == "risk_class":
        return "within allowed risk class"
    if reason == "approval_required":
        return "because approval was required"
    if reason == "approval_quorum_active":
        return "after approval quorum was met"
    if reason == "breakglass_active":
        return "under an active breakglass override"
    if reason == "budget_anomaly":
        return "after unusual budget burn was detected"
    if reason == "budget_exhausted":
        return "because budget was exhausted"
    if reason == "delegation_unavailable":
        return "because delegation validation was unavailable"
    if reason == "exception_permit_active":
        return "under an active exception permit"
    if reason == "kill_switch_active":
        return "because kill switch was active"
    if reason == "not_in_contract":
        return "because the tool was not in the Charter"
    if reason == "not_in_egress_allowlist":
        return "because the target was not in the egress allowlist"
    if reason == "passthrough":
        return "in passthrough mode"
    if reason == "proxy_degraded":
        return "because the proxy was degraded"
    return None


def _format_context_parts(event: CanonicalEvent) -> str:
    metadata = event.metadata
    context_parts: list[str] = []
    request_id = _request_id(metadata)
    if request_id is not None:
        context_parts.append(f"request: {request_id}")
    target_hint = _target_hint(metadata)
    if target_hint is not None:
        context_parts.append(f"target: {target_hint}")

    if event.event_type == "budget_anomaly" and metadata is not None:
        burn_rate = metadata.get("burn_rate")
        if isinstance(burn_rate, (int, float)):
            context_parts.append(f"burn rate: {burn_rate:.2f}x")

    if event.reason == "kill_switch_active" and metadata is not None:
        operator_updated_by = _string_field(metadata, "operator_updated_by")
        if operator_updated_by is not None:
            context_parts.append(f"operator: {operator_updated_by}")

    if not context_parts:
        return ""
    return f" ({'; '.join(context_parts)})"


def _render_elev_op(event: CanonicalEvent) -> str:
    metadata = event.metadata
    request_id = _request_id(metadata)
    if event.tool_name == "__operator__":
        actor = _string_field(metadata, "updated_by") or "operator"
        kill_switch_active = metadata.get("kill_switch_active") if metadata is not None else None
        if kill_switch_active is True:
            return f"Kill switch enabled by {actor}"
        if kill_switch_active is False:
            return f"Kill switch disabled by {actor}"

    if event.reason == "approval_request_created":
        summary = f"Approval request created for {event.tool_name}"
        if request_id is not None:
            summary = f"Approval request {request_id} created for {event.tool_name}"
        return summary

    if event.reason == "approval_request_expired":
        summary = f"Approval request expired for {event.tool_name}"
        if request_id is not None:
            summary = f"Approval request {request_id} expired for {event.tool_name}"
        return summary

    if event.reason == "approval_quorum_active":
        return f"Approval quorum satisfied for {event.tool_name}"

    if event.reason == "breakglass_active":
        return f"Breakglass override allowed {event.tool_name}"

    if event.reason == "exception_permit_active":
        return f"Exception permit allowed {event.tool_name}"

    if event.tool_name == "__proxy__" and event.reason == "circuit_breaker_open":
        return "Circuit breaker opened"
    if event.tool_name == "__proxy__" and event.reason == "circuit_breaker_closed":
        return "Circuit breaker closed"

    decision_label = _DECISION_LABELS[event.decision]
    return f"Elevated operation for {event.tool_name} - {decision_label}"


def _render_event_summary(event: CanonicalEvent) -> str:
    decision_label = _DECISION_LABELS[event.decision]

    if event.event_type == "elev_op":
        return _render_elev_op(event)

    if event.event_type == "budget_exhausted":
        metadata = event.metadata or {}
        dimension = _string_field(metadata, "exhausted_dimension") or "budget"
        return f"Budget exhausted for {dimension.replace('_', ' ')} - {decision_label}"

    if event.event_type == "budget_anomaly":
        metadata = event.metadata or {}
        dimension = _string_field(metadata, "dimension") or "budget"
        return f"Budget anomaly detected for {dimension.replace('_', ' ')} - {decision_label}"

    if event.event_type == "net_call":
        prefix = "Agent made network call via" if event.decision == "allow" else "Agent attempted network call via"
        return f"{prefix} {event.tool_name} - {decision_label}"

    if event.event_type == "write_op":
        prefix = "Agent wrote via" if event.decision == "allow" else "Agent attempted write via"
        return f"{prefix} {event.tool_name} - {decision_label}"

    prefix = "Agent called" if event.decision == "allow" else "Agent attempted"
    return f"{prefix} {event.tool_name} - {decision_label}"


def _format_event_line(event: CanonicalEvent) -> str:
    summary = _render_event_summary(event)
    reason_text = _reason_text(event)
    if reason_text is not None and event.event_type != "elev_op":
        summary = f"{summary} {reason_text}"
    return f"{event.timestamp} {summary}{_format_context_parts(event)}"


def _render_history(events: list[CanonicalEvent], *, session_id: str | None, limit: int | None) -> str:
    filtered = [
        event
        for event in events
        if session_id is None or event.session_id == session_id
    ]
    if limit is not None:
        filtered = filtered[-limit:]

    if not filtered:
        if session_id is not None:
            return f"No events found for session {session_id}."
        return "No events found."

    grouped: dict[str, list[CanonicalEvent]] = {}
    for event in filtered:
        grouped.setdefault(event.session_id, []).append(event)

    lines: list[str] = []
    session_ids = list(grouped)
    for index, grouped_session_id in enumerate(session_ids):
        lines.append(f"Session {grouped_session_id}")
        for event in grouped[grouped_session_id]:
            lines.append(_format_event_line(event))
        if index < len(session_ids) - 1:
            lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        limit = getattr(args, "limit", None)
        if limit is not None and limit <= 0:
            raise CLIError("--limit must be > 0", exit_code=3)
        events = _load_canonical_events(Path(args.events))
        print(_render_history(events, session_id=args.session_id, limit=limit))
        return 0
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
