"""Plain-language Chronicle session report."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stipul.chronicle.events.models import CanonicalEvent
from stipul.cli.io import CLIError, ensure_session_dir, read_jsonl
from stipul.cli.verify_cmd import trust_status, verification_exit_code, verify_session
from stipul.exceptions import ContractValidationError

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
_NORMAL_ALLOW_EVENT_TYPE = "tool_call"
_NORMAL_ALLOW_REASON = "risk_class"
_NO_ADDITIONAL_DETAILS = "No additional details recorded for this event type"


@dataclass(frozen=True)
class ToolAttempt:
    event: CanonicalEvent
    grouped_events: tuple[CanonicalEvent, ...]


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "report",
        help="Render a plain-language report from one Chronicle session",
    )
    parser.add_argument("session_dir", help="Path to the session directory")
    parser.set_defaults(handler=run)


def _session_local_input_path(
    *,
    session_dir: Path,
    filename: str,
    label: str,
) -> Path:
    candidate = session_dir / filename
    if not candidate.exists():
        raise CLIError(
            f"Operational error: missing session-local {label}: {candidate}",
            exit_code=2,
        )
    if not candidate.is_file():
        raise CLIError(
            f"Operational error: session-local {label} is not a file: {candidate}",
            exit_code=2,
        )
    return candidate


def _load_canonical_events(path: Path) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for record_index, payload in enumerate(read_jsonl(path), start=1):
        try:
            events.append(CanonicalEvent(**payload))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid canonical event in {path}: record {record_index}: {exc}"
            ) from exc
    if not events:
        raise ValueError(f"No events found in {path}")
    return events


def _string_field(mapping: dict[str, Any] | None, key: str) -> str | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _single_value(events: list[CanonicalEvent], field_name: str) -> str:
    values: set[str] = set()
    for event in events:
        value = getattr(event, field_name)
        if isinstance(value, str) and value:
            values.add(value)
    if len(values) != 1:
        raise ValueError(f"Expected exactly one {field_name} in session events")
    return next(iter(values))


def _session_open_event(events: list[CanonicalEvent]) -> CanonicalEvent | None:
    return next((event for event in events if event.event_type == "session_open"), None)


def _session_close_event(events: list[CanonicalEvent]) -> CanonicalEvent | None:
    for event in reversed(events):
        if event.event_type == "session_close":
            return event
    return None


def _truncate(text: str, *, max_len: int = 40) -> str:
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 3]}..."


def _format_scalar(value: Any, *, quote_strings: bool) -> str | None:
    if isinstance(value, str):
        rendered = _truncate(value.replace("\n", "\\n"))
        return f'"{rendered}"' if quote_strings else rendered
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _tool_input_summary(event: CanonicalEvent) -> str:
    fields: dict[str, Any] | None
    if event.event_type == "tool_call":
        fields = event.tool_input
    elif event.event_type == "net_call" and isinstance(event.metadata, dict):
        fields = event.metadata
    else:
        return _NO_ADDITIONAL_DETAILS
    if fields is None:
        return _NO_ADDITIONAL_DETAILS
    if not fields:
        return "no input fields"

    parts: list[str] = []
    seen: set[str] = set()
    for key in _TARGET_KEYS:
        if key in fields:
            rendered = _format_scalar(fields[key], quote_strings=False)
            if rendered is not None:
                parts.append(f"{key}={rendered}")
                seen.add(key)

    for key, value in fields.items():
        if key in seen:
            continue
        rendered = _format_scalar(value, quote_strings=True)
        if rendered is None:
            continue
        parts.append(f"{key}={rendered}")
        if len(parts) >= 3:
            break

    if parts:
        return ", ".join(parts)

    field_names = ", ".join(sorted(fields.keys())[:3])
    return f"fields: {field_names}"


def _human_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    if reason == "approval_request_created":
        return "approval was requested"
    return reason.replace("_", " ")


def _human_rule(rule: str | None) -> str | None:
    if rule is None:
        return None
    if rule == "risk_class":
        return "risk class policy"
    if rule == "not_allowed":
        return None
    return rule.replace("_", " ")


def _display_tool_name(tool_name: str | None) -> str | None:
    if tool_name is None:
        return None
    if tool_name == "__budget__":
        return "budget control"
    if tool_name == "__operator__":
        return "operator control"
    if tool_name == "__proxy__":
        return "Writ enforcement control"
    return tool_name


def _grouped_note_text() -> str:
    return "Related approval event matched from nearby Chronicle entries."


def _grouped_event_context(event: CanonicalEvent) -> str:
    if event.event_type == "elev_op":
        label = "Approval event"
    else:
        label = event.event_type.replace("_", " ").capitalize()
    reason = _human_reason(event.reason)
    details: list[str] = [f"{label}."]
    if reason is not None:
        details.append(f"Reason: {reason}.")
    details.append(f"(seq {event.sequence_id})")
    return " ".join(details)


def _event_details_text(
    event: CanonicalEvent,
    *,
    include_tool: bool,
    include_reason: bool,
    include_rule: bool,
    include_details: bool,
) -> str:
    parts: list[str] = []
    tool_name = _display_tool_name(event.tool_name)
    if include_tool and tool_name:
        parts.append(f"Tool: {tool_name}.")
    reason = _human_reason(event.reason)
    if include_reason and reason is not None:
        parts.append(f"Reason: {reason}.")
    rule = _human_rule(event.rule_triggered)
    if include_rule and rule is not None:
        parts.append(f"Rule: {rule}.")
    if include_details:
        parts.append(f"Details: {_tool_input_summary(event)}.")
    parts.append(f"(seq {event.sequence_id})")
    return " ".join(parts)


def _tool_input_phrase(event: CanonicalEvent) -> str | None:
    fields = event.tool_input
    if event.event_type == "net_call" and isinstance(event.metadata, dict):
        fields = event.metadata
    if fields is None:
        return None
    summary = _tool_input_summary(event)
    if summary == _NO_ADDITIONAL_DETAILS:
        return None
    if summary == "no input fields":
        return "with no input fields"
    if any(key in fields for key in _TARGET_KEYS):
        return f"on {summary}"
    return f"with {summary}"


def _attempt_sentence(event: CanonicalEvent) -> str:
    tool_name = _display_tool_name(event.tool_name) or "the requested action"
    phrase = _tool_input_phrase(event)
    if phrase is None:
        return f"Attempted {tool_name}."
    return f"Attempted {tool_name} {phrase}."


def _outcome_sentence(event: CanonicalEvent) -> str:
    tool_name = _display_tool_name(event.tool_name) or "The requested action"
    if event.reason == "approval_required" or event.decision == "require_approval":
        return f"{tool_name} was held for approval."
    if event.decision == "deny":
        return f"{tool_name} was denied."
    if event.decision == "allow":
        if event.reason == "risk_class" and event.rule_triggered == "risk_class":
            return f"{tool_name} was allowed under the charter's risk class policy."
        return f"{tool_name} was allowed."
    return f"{tool_name} did not have a recorded outcome."


def _policy_primary_sentence(event: CanonicalEvent) -> str:
    if event.reason == "approval_request_created":
        return "Approval was requested."
    if event.reason == "approval_required" or event.decision == "require_approval":
        return "Approval was required before execution."
    if event.decision == "deny":
        return "A call was denied by policy."
    if event.tool_name == "__budget__":
        return "A budget policy signal was recorded."
    if event.tool_name == "__operator__":
        return "An operator policy event was recorded."
    if event.event_type == "elev_op":
        return "An approval event was recorded."
    return "A policy-significant event was recorded."


def _decision_detail_text(event: CanonicalEvent) -> str:
    if event.decision == "allow" and event.reason == "risk_class" and event.rule_triggered == "risk_class":
        return f"(seq {event.sequence_id})"
    return _event_details_text(
        event,
        include_tool=False,
        include_reason=True,
        include_rule=True,
        include_details=False,
    )


def _decision_label(event: CanonicalEvent) -> str:
    if event.reason == "approval_required":
        return "approval-required"
    if event.decision == "require_approval":
        return "approval-required"
    if event.decision is None:
        return "not recorded"
    return event.decision


def _grouped_context(events: list[CanonicalEvent], index: int) -> tuple[CanonicalEvent, ...]:
    current = events[index]
    if current.event_type != "tool_call" or current.input_hash is None:
        return ()

    grouped: list[CanonicalEvent] = []
    expected_sequence = current.sequence_id - 1
    prior_index = index - 1
    while prior_index >= 0:
        prior = events[prior_index]
        if prior.event_type == "tool_call":
            break
        if prior.sequence_id != expected_sequence:
            break
        if prior.input_hash != current.input_hash:
            break
        grouped.insert(0, prior)
        expected_sequence -= 1
        prior_index -= 1
    return tuple(grouped)


def _build_attempts(events: list[CanonicalEvent]) -> tuple[list[ToolAttempt], dict[int, int]]:
    attempts: list[ToolAttempt] = []
    grouped_to_tool_call: dict[int, int] = {}
    for index, event in enumerate(events):
        if event.event_type not in {"tool_call", "net_call"}:
            continue
        grouped = _grouped_context(events, index)
        for grouped_event in grouped:
            grouped_to_tool_call[grouped_event.sequence_id] = event.sequence_id
        attempts.append(ToolAttempt(event=event, grouped_events=grouped))
    return attempts, grouped_to_tool_call


def _grouped_context_text(attempt: ToolAttempt) -> str | None:
    if not attempt.grouped_events:
        return None
    contexts = " ".join(_grouped_event_context(event) for event in attempt.grouped_events)
    return f"{_grouped_note_text()} {contexts}"


def _render_session_section(events: list[CanonicalEvent]) -> list[str]:
    session_id = _single_value(events, "session_id")
    contract_id = _single_value(events, "contract_id")
    opened = _session_open_event(events)
    closed = _session_close_event(events)
    started = opened.timestamp if opened is not None else "session_open not recorded"
    ended = closed.timestamp if closed is not None else "session_close not recorded"

    return [
        "1. What session is this?",
        f"Session ID: {session_id}",
        f"Charter ID: {contract_id}",
        f"Time range: {started} to {ended}",
    ]


def _render_attempts_section(attempts: list[ToolAttempt]) -> list[str]:
    lines = ["2. What did the agent try to do?"]
    if not attempts:
        lines.append("No tool attempts were recorded.")
        return lines

    for index, attempt in enumerate(attempts, start=1):
        lines.append(f"{index}. {_attempt_sentence(attempt.event)}")
        grouped_text = _grouped_context_text(attempt)
        if grouped_text is not None:
            lines.append(grouped_text)
    return lines


def _render_decisions_section(attempts: list[ToolAttempt]) -> list[str]:
    lines = ["3. What did Stipul decide for each one?"]
    if not attempts:
        lines.append("No tool decisions were recorded.")
        return lines

    for index, attempt in enumerate(attempts, start=1):
        event = attempt.event
        detail = _decision_detail_text(event)
        lines.append(f"{index}. {_outcome_sentence(event)} {detail}")
    return lines


def _is_policy_significant(event: CanonicalEvent) -> bool:
    if event.event_type in {"session_open", "session_close"}:
        return False
    if event.event_type != _NORMAL_ALLOW_EVENT_TYPE:
        return True
    if event.reason != _NORMAL_ALLOW_REASON:
        return True
    return event.decision != "allow"


def _significant_event_line(event: CanonicalEvent, grouped_to_tool_call: dict[int, int]) -> str:
    include_reason = event.reason not in {"approval_request_created", "approval_required"}
    line = (
        f"{_policy_primary_sentence(event)} "
        f"{_event_details_text(event, include_tool=True, include_reason=include_reason, include_rule=True, include_details=True)}"
    )
    grouped_sequence = grouped_to_tool_call.get(event.sequence_id)
    if grouped_sequence is not None:
        line += f" Related attempt: seq {grouped_sequence}."
    return line


def _render_significant_section(
    events: list[CanonicalEvent],
    grouped_to_tool_call: dict[int, int],
) -> list[str]:
    lines = ["4. Did anything policy-significant happen?"]
    significant = [event for event in events if _is_policy_significant(event)]
    if not significant:
        lines.append("No policy-significant events.")
        return lines

    for index, event in enumerate(significant, start=1):
        lines.append(f"{index}. {_significant_event_line(event, grouped_to_tool_call)}")
    return lines


def _chain_detail(chain_result: Any) -> str | None:
    if chain_result.status == "ERROR":
        return chain_result.error or "verification failed"
    if chain_result.status == "BROKEN" and chain_result.failures:
        first = next(
            (
                failure
                for failure in chain_result.failures
                if failure.sequence_id is not None
            ),
            chain_result.failures[0],
        )
        if first.sequence_id is not None:
            return f"first failure at sequence_id {first.sequence_id} ({first.kind}: {first.detail})"
        if first.line_number is not None:
            return f"first failure at line {first.line_number} ({first.kind}: {first.detail})"
        return f"{first.kind}: {first.detail}"
    if chain_result.status == "UNVERIFIABLE":
        if chain_result.verifiable_up_to_sequence_id is not None:
            return f"verifiable up to sequence_id {chain_result.verifiable_up_to_sequence_id}"
        return "chain structure could not be fully verified"
    return None


def _render_trust_section(outcome: Any) -> list[str]:
    chain_result = outcome.chain_result
    seal_result = outcome.seal_result
    trust = trust_status(
        chain_status=chain_result.status,
        seal_status=seal_result.status,
    )

    lines = [
        "5. Can I trust this record?",
        "Fresh verification only.",
        f"Trust: {trust}",
        f"Chain: {chain_result.status}",
        f"Seal: {seal_result.status}",
    ]

    chain_detail = _chain_detail(chain_result)
    if chain_detail is not None:
        lines.append(f"Chain detail: {chain_detail}")
    if seal_result.status != "VALID" and seal_result.error:
        lines.append(f"Seal detail: {seal_result.error}")
    if trust == "REJECTED":
        lines.append("This record does not verify.")

    return lines


def render_report(events: list[CanonicalEvent], outcome: Any) -> str:
    attempts, grouped_to_tool_call = _build_attempts(events)
    sections = [
        _render_session_section(events),
        _render_attempts_section(attempts),
        _render_decisions_section(attempts),
        _render_significant_section(events, grouped_to_tool_call),
        _render_trust_section(outcome),
    ]
    lines: list[str] = []
    for index, section in enumerate(sections):
        lines.extend(section)
        if index < len(sections) - 1:
            lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        session_dir = ensure_session_dir(Path(args.session_dir))
        events = _load_canonical_events(session_dir / "events.jsonl")
        contract_path = _session_local_input_path(
            session_dir=session_dir,
            filename="contract.json",
            label="contract file",
        )
        public_key_path = _session_local_input_path(
            session_dir=session_dir,
            filename="public_key.pem",
            label="public key file",
        )
        outcome = verify_session(
            session_dir,
            contract_path=contract_path,
            public_key_path=public_key_path,
        )
        print(render_report(events, outcome))
        return verification_exit_code(outcome.chain_result, outcome.seal_result)
    except CLIError:
        raise
    except FileNotFoundError as exc:
        raise CLIError(str(exc), exit_code=3) from exc
    except (ContractValidationError, OSError, TypeError, ValueError) as exc:
        raise CLIError(str(exc), exit_code=3) from exc
