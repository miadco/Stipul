"""Derived decisions projection from authoritative events stream."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentshield.events.decisions")


def _required_non_empty_str(event: dict[str, Any], key: str) -> str | None:
    value = event.get(key)
    if isinstance(value, str) and value:
        return value
    logger.warning("Skipping decision-bearing event missing required string field '%s'", key)
    return None


def _is_hex64(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)


@dataclass(frozen=True)
class DecisionRecord:
    sequence_id: int
    event_type: str
    decision: str
    reason: str
    tool_name: str
    contract_id: str
    contract_hash: str


@dataclass(frozen=True)
class DecisionMismatch:
    sequence_id: int
    field: str
    expected: str
    actual: str
    mismatch_type: str  # "missing_decision" | "extra_decision" | "field_mismatch"


@dataclass(frozen=True)
class DecisionVerification:
    is_valid: bool
    expected_count: int
    actual_count: int
    mismatches: list[DecisionMismatch]


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON in events stream at line %s", line_number)
                continue
            if isinstance(payload, dict):
                events.append(payload)
            else:
                logger.warning("Skipping non-object JSON in events stream at line %s", line_number)
    return events


def _decision_record_from_event(event: dict[str, Any]) -> DecisionRecord | None:
    decision = event.get("decision")
    if not isinstance(decision, str) or not decision:
        return None

    sequence_id = event.get("sequence_id")
    if isinstance(sequence_id, bool) or not isinstance(sequence_id, int):
        logger.warning(
            "Skipping decision-bearing event with invalid sequence_id type: %r",
            sequence_id,
        )
        return None

    event_type = _required_non_empty_str(event, "event_type")
    if event_type is None:
        return None
    reason = _required_non_empty_str(event, "reason")
    if reason is None:
        return None
    tool_name = _required_non_empty_str(event, "tool_name")
    if tool_name is None:
        return None
    contract_id = _required_non_empty_str(event, "contract_id")
    if contract_id is None:
        return None
    contract_hash = _required_non_empty_str(event, "contract_hash")
    if contract_hash is None:
        return None
    if not _is_hex64(contract_hash):
        logger.warning("Skipping decision-bearing event with malformed contract_hash")
        return None

    return DecisionRecord(
        sequence_id=sequence_id,
        event_type=event_type,
        decision=decision,
        reason=reason,
        tool_name=tool_name,
        contract_id=contract_id,
        contract_hash=contract_hash,
    )


def _load_decisions(path: Path) -> list[DecisionRecord]:
    decisions: list[DecisionRecord] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON in decisions stream at line %s", line_number)
                continue
            if not isinstance(payload, dict):
                logger.warning("Skipping non-object JSON in decisions stream at line %s", line_number)
                continue

            record = _decision_record_from_event(payload)
            if record is not None:
                decisions.append(record)
    return decisions


def generate_decisions(events_path: Path) -> list[DecisionRecord]:
    """Project decision-bearing events from events.jsonl."""
    records: list[DecisionRecord] = []
    for event in _load_events(events_path):
        record = _decision_record_from_event(event)
        if record is not None:
            records.append(record)
    return records


def write_decisions(decisions: list[DecisionRecord], output_path: Path) -> None:
    """Write projection as canonical JSONL, one record per line."""
    path = Path(output_path)
    lines = [
        json.dumps(asdict(record), sort_keys=True, separators=(",", ":"))
        for record in decisions
    ]
    payload = "".join(f"{line}\n" for line in lines)
    path.write_text(payload, encoding="utf-8")


def verify_decisions(events_path: Path, decisions_path: Path) -> DecisionVerification:
    """Compare decisions projection to expected projection derived from events stream."""
    expected = generate_decisions(events_path)
    actual = _load_decisions(decisions_path) if Path(decisions_path).exists() else []

    expected_by_id = {record.sequence_id: record for record in expected}
    actual_by_id = {record.sequence_id: record for record in actual}

    mismatches: list[DecisionMismatch] = []
    for sequence_id in sorted(expected_by_id):
        if sequence_id not in actual_by_id:
            mismatches.append(
                DecisionMismatch(
                    sequence_id=sequence_id,
                    field="sequence_id",
                    expected="present",
                    actual="missing",
                    mismatch_type="missing_decision",
                )
            )

    for sequence_id in sorted(actual_by_id):
        if sequence_id not in expected_by_id:
            mismatches.append(
                DecisionMismatch(
                    sequence_id=sequence_id,
                    field="sequence_id",
                    expected="missing",
                    actual="present",
                    mismatch_type="extra_decision",
                )
            )

    shared_ids = sorted(set(expected_by_id).intersection(actual_by_id))
    for sequence_id in shared_ids:
        expected_record = asdict(expected_by_id[sequence_id])
        actual_record = asdict(actual_by_id[sequence_id])
        for field in sorted(expected_record.keys()):
            expected_value = expected_record[field]
            actual_value = actual_record[field]
            if expected_value != actual_value:
                mismatches.append(
                    DecisionMismatch(
                        sequence_id=sequence_id,
                        field=field,
                        expected=str(expected_value),
                        actual=str(actual_value),
                        mismatch_type="field_mismatch",
                    )
                )

    return DecisionVerification(
        is_valid=not mismatches,
        expected_count=len(expected),
        actual_count=len(actual),
        mismatches=mismatches,
    )


def regenerate_if_invalid(
    events_path: Path,
    decisions_path: Path,
) -> tuple[DecisionVerification, DecisionVerification]:
    """
    Rebuild decisions file if divergent.

    Returns a tuple of (verification_before, verification_after) so callers can
    inspect resolved mismatches.
    """
    before = verify_decisions(events_path, decisions_path)
    if before.is_valid:
        logger.debug("decisions.jsonl is valid. %s records verified.", before.expected_count)
        return before, before

    regenerated = generate_decisions(events_path)
    write_decisions(regenerated, decisions_path)
    logger.warning(
        "decisions.jsonl diverged from events.jsonl. Regenerated from authoritative source. %s mismatches resolved.",
        len(before.mismatches),
    )
    after = verify_decisions(events_path, decisions_path)
    return before, after
