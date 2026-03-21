"""Session-close summary derived from authoritative events stream."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.utils.canonical import canonical_json_bytes

logger = logging.getLogger("stipul.chronicle.events.summary")

# TODO: add session_close to ReasonCode enum in stipul/models.py


class ChainResult(Protocol):
    status: str
    first_failure_sequence_id: int | None


@dataclass(frozen=True)
class SessionSummary:
    session_id: str
    contract_id: str
    contract_hash: str
    session_start: str
    session_end: str
    duration_seconds: float
    tools_invoked: dict[str, int]
    tools_denied: dict[str, list[str]]
    total_calls: int
    total_allowed: int
    total_denied: int
    total_approval_required: int
    egress_attempted: dict[str, int]
    egress_denied: dict[str, list[str]]
    budget_limit: dict[str, float]
    budget_consumed: dict[str, float]
    budget_remaining: dict[str, float]
    budget_exhausted: bool
    budget_exhaustion_timestamp: str | None
    budget_anomalies_detected: int
    chain_length: int
    chain_integrity: str
    attestations: list[str]
    known_blind_spots: list[str]
    coverage_percentage: float | None = None
    coverage_assessment: str | None = None
    gaps_detected: int = 0
    gap_details: list[dict[str, str]] = field(default_factory=list)
    permit_allows: int = 0
    breakglass_allows: int = 0
    flagged_for_review: bool = False


def _format_zulu(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_parseable_events(events_path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(events_path).open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line %s in events stream", line_number)
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def _resolve_egress_domain(event: dict[str, Any]) -> str:
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        candidate = metadata.get("egress_target")
        if isinstance(candidate, str) and candidate:
            return candidate
        candidate = metadata.get("destination")
        if isinstance(candidate, str) and candidate:
            return candidate
        candidate = metadata.get("domain")
        if isinstance(candidate, str) and candidate:
            return candidate
    tool_name = event.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        return tool_name
    return "unknown_target"


def _chain_integrity_text(chain_result: ChainResult) -> str:
    if chain_result.status == "INTACT":
        return "intact"
    if chain_result.status == "BROKEN" and chain_result.first_failure_sequence_id is not None:
        return f"broken at sequence_id {chain_result.first_failure_sequence_id}"
    return "broken"


def _derive_exhaustion_timestamp(
    events: list[dict[str, Any]],
    tool_limit: float,
    net_limit: float,
) -> str | None:
    tool_running = 0.0
    net_running = 0.0
    for event in sorted(
        events,
        key=lambda item: (
            item.get("sequence_id", 10**18),
            item.get("timestamp", ""),
        ),
    ):
        event_type = event.get("event_type")
        if event_type == "tool_call":
            tool_running += 1.0
            if tool_limit > 0.0 and tool_running >= tool_limit:
                value = event.get("timestamp")
                if isinstance(value, str) and value:
                    return value
        elif event_type == "net_call":
            net_running += 1.0
            if net_limit > 0.0 and net_running >= net_limit:
                value = event.get("timestamp")
                if isinstance(value, str) and value:
                    return value
    return None


def build_summary(
    events_path: Path,
    contract: Contract,
    session_id: str,
    session_start: datetime,
    session_end: datetime,
    chain_result: ChainResult,
    budget_consumed: dict[str, int | float],
    budget_exhaustion_timestamp: str | None = None,
    coverage_fields: dict[str, Any] | None = None,
) -> SessionSummary:
    if session_start.tzinfo is None:
        raise ValueError("session_start must be timezone-aware")
    if session_end.tzinfo is None:
        raise ValueError("session_end must be timezone-aware")

    events = _read_parseable_events(events_path)

    tools_invoked: dict[str, int] = defaultdict(int)
    tools_denied: dict[str, list[str]] = defaultdict(list)
    egress_attempted: dict[str, int] = defaultdict(int)
    egress_denied: dict[str, list[str]] = defaultdict(list)

    total_allowed = 0
    total_denied = 0
    total_approval_required = 0
    gap_detected_sequence_ids: list[int] = []
    budget_anomalies_detected = 0
    permit_allows = 0
    breakglass_allows = 0

    for event in events:
        event_type = event.get("event_type")
        tool_name_raw = event.get("tool_name")
        tool_name = tool_name_raw if isinstance(tool_name_raw, str) and tool_name_raw else "unknown_tool"
        decision = event.get("decision")
        reason_value = event.get("reason")
        reason = reason_value if isinstance(reason_value, str) else "unknown"
        metadata = event.get("metadata")
        metadata_dict = metadata if isinstance(metadata, dict) else None
        sequence_id = event.get("sequence_id")

        if event_type == "tool_call":
            if decision == "allow":
                tools_invoked[tool_name] += 1
                total_allowed += 1
                if reason == "exception_permit_active":
                    permit_allows += 1
                if reason == "breakglass_active":
                    breakglass_allows += 1
            elif decision == "deny":
                tools_denied[tool_name].append(reason)
                total_denied += 1
            elif decision == "require_approval":
                total_approval_required += 1

        if event_type == "net_call":
            domain = _resolve_egress_domain(event)
            egress_attempted[domain] += 1
            if decision == "deny":
                egress_denied[domain].append(reason)

        has_anomaly_subtype = (
            metadata_dict is not None
            and metadata_dict.get("event_subtype") == "budget_anomaly"
        )
        if reason == "budget_anomaly_detected" or has_anomaly_subtype:
            budget_anomalies_detected += 1

        has_gap_subtype = (
            event_type == "write_op"
            and metadata_dict is not None
            and metadata_dict.get("event_subtype") == "gap_detected"
        )
        if reason == "gap_detected" or has_gap_subtype:
            if isinstance(sequence_id, int):
                gap_detected_sequence_ids.append(sequence_id)

    total_calls = total_allowed + total_denied + total_approval_required

    tool_limit = float(contract.max_tool_calls)
    net_limit = float(contract.max_net_calls)
    budget_limit = {"tool_calls": tool_limit, "net_calls": net_limit}
    consumed_tool = float(budget_consumed.get("tool_calls", 0.0))
    consumed_net = float(budget_consumed.get("net_calls", 0.0))
    budget_consumed_normalized = {"tool_calls": consumed_tool, "net_calls": consumed_net}
    budget_remaining = {
        "tool_calls": max(0.0, tool_limit - consumed_tool),
        "net_calls": max(0.0, net_limit - consumed_net),
    }
    budget_exhausted = any(
        budget_limit[name] > 0.0 and budget_remaining[name] == 0.0
        for name in ("tool_calls", "net_calls")
    )

    exhaustion_timestamp = budget_exhaustion_timestamp
    if budget_exhausted and exhaustion_timestamp is None:
        exhaustion_timestamp = _derive_exhaustion_timestamp(events, tool_limit, net_limit)
    if not budget_exhausted:
        exhaustion_timestamp = None

    attestations = [
        f"All tool calls routed through the MCP Proxy were evaluated against signed contract {contract.contract_id}.",
        "This summary is derived from events.jsonl. events.jsonl is the authoritative stream.",
    ]
    if gap_detected_sequence_ids:
        ids_text = ", ".join(str(value) for value in sorted(gap_detected_sequence_ids))
        attestations.append(
            "Server Wrapper coverage gaps detected. "
            f"{len(gap_detected_sequence_ids)} gap_detected events. "
            f"See sequence_ids: [{ids_text}]"
        )
    else:
        attestations.append("No unmanaged credential use detected via Server Wrapper.")

    known_blind_spots = [
        "MCP Proxy does not inspect tool response payloads.",
        "File system writes by the agent process are not monitored.",
        (
            "Only tools behind the Server Wrapper are governed. Direct API calls, "
            "local scripts, browser automation, and SSH are outside scope."
        ),
        (
            "Budget tracking relies on event counts. Resource consumption inside "
            "a tool call is not measured."
        ),
    ]

    coverage_fields = dict(coverage_fields or {})
    coverage_percentage = coverage_fields.get("coverage_percentage")
    coverage_assessment = coverage_fields.get("coverage_assessment")
    gaps_detected = int(coverage_fields.get("gaps_detected", len(gap_detected_sequence_ids)))
    raw_gap_details = coverage_fields.get("gap_details", [])
    gap_details = raw_gap_details if isinstance(raw_gap_details, list) else []
    flagged_for_review = breakglass_allows > 0

    return SessionSummary(
        session_id=session_id,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_start=_format_zulu(session_start),
        session_end=_format_zulu(session_end),
        duration_seconds=max(
            0.0,
            (session_end.astimezone(timezone.utc) - session_start.astimezone(timezone.utc)).total_seconds(),
        ),
        tools_invoked=dict(tools_invoked),
        tools_denied=dict(tools_denied),
        total_calls=total_calls,
        total_allowed=total_allowed,
        total_denied=total_denied,
        total_approval_required=total_approval_required,
        egress_attempted=dict(egress_attempted),
        egress_denied=dict(egress_denied),
        budget_limit=budget_limit,
        budget_consumed=budget_consumed_normalized,
        budget_remaining=budget_remaining,
        budget_exhausted=budget_exhausted,
        budget_exhaustion_timestamp=exhaustion_timestamp,
        budget_anomalies_detected=budget_anomalies_detected,
        chain_length=len(events),
        chain_integrity=_chain_integrity_text(chain_result),
        attestations=attestations,
        known_blind_spots=known_blind_spots,
        coverage_percentage=coverage_percentage,
        coverage_assessment=coverage_assessment,
        gaps_detected=gaps_detected,
        gap_details=gap_details,
        permit_allows=permit_allows,
        breakglass_allows=breakglass_allows,
        flagged_for_review=flagged_for_review,
    )


def summary_to_event(
    summary: SessionSummary,
    *,
    agent_identity: str,
) -> dict[str, Any]:
    """
    Build a logger-ready lifecycle event payload for session close.
    """
    if not isinstance(agent_identity, str) or not agent_identity:
        raise ValueError("agent_identity must be a non-empty string")
    metadata = asdict(summary)

    return {
        "event_type": "session_close",
        "tool_name": None,
        "risk_class": None,
        "decision": None,
        "reason": "session_closed",
        "contract_id": summary.contract_id,
        "agent_identity": agent_identity,
        "input_hash": None,
        "tool_input": None,
        "rule_triggered": None,
        "lifecycle_hash": None,
        "metadata": metadata,
    }


def write_summary_json(summary: SessionSummary, output_path: Path) -> None:
    path = Path(output_path)
    payload = json.dumps(asdict(summary), indent=2, sort_keys=True)
    path.write_text(f"{payload}\n", encoding="utf-8")
