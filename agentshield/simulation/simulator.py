"""Offline trace replay against contracts using proxy-true projection semantics."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentshield.contract.schema import Contract
from agentshield.proxy.interceptor import intercept


@dataclass(frozen=True)
class SimulationRecord:
    sequence_id: int
    timestamp: str
    tool_name: str
    original_decision: str
    simulated_decision: str
    original_reason: str
    simulated_reason: str
    changed: bool
    explanation: str


@dataclass(frozen=True)
class SimulationSummary:
    total_evaluated: int
    changed_count: int
    records: list[SimulationRecord]


@dataclass(frozen=True)
class DiffRecord:
    sequence_id: int
    timestamp: str
    tool_name: str
    decision_a: str
    decision_b: str
    reason_a: str
    reason_b: str
    changed: bool
    explanation: str


@dataclass(frozen=True)
class DiffSummary:
    total_evaluated: int
    changed_count: int
    records: list[DiffRecord]


class PolicySimulator:
    """Replay tool_call traces through the proxy interceptor."""

    def simulate(self, events_path: Path, contract: Contract) -> SimulationSummary:
        events = self._read_events(events_path)
        records: list[SimulationRecord] = []
        prior_tool_calls = 0
        prior_net_calls = 0

        for event in events:
            event_type = event.get("event_type")
            if event_type == "net_call":
                prior_net_calls += 1
                continue
            if event_type != "tool_call":
                continue

            tool_name = self._string_field(event, "tool_name", default="unknown_tool")
            timestamp = self._string_field(event, "timestamp")
            metadata = event.get("metadata")
            metadata_dict = metadata if isinstance(metadata, dict) else {}
            egress_target = self._metadata_egress_target(metadata_dict)

            raw_request = {
                "tool_name": tool_name,
                "inputs": {"egress_target": egress_target} if egress_target is not None else {},
                "state": {
                    "tool_calls_made": prior_tool_calls,
                    "net_calls_made": prior_net_calls,
                    "current_time": timestamp,
                    "requesting_agent_id": contract.identity_agent_id,
                    "requesting_code_sha256": metadata_dict.get("requesting_code_sha256"),
                    "egress_target": egress_target,
                },
            }
            simulated = intercept(raw_request, contract)
            original_decision = self._string_field(event, "decision", default="unknown")
            original_reason = self._string_field(event, "reason", default="unknown")
            changed = (
                simulated.decision != original_decision
                or simulated.reason != original_reason
            )
            records.append(
                SimulationRecord(
                    sequence_id=self._int_field(event, "sequence_id"),
                    timestamp=timestamp,
                    tool_name=tool_name,
                    original_decision=original_decision,
                    simulated_decision=simulated.decision,
                    original_reason=original_reason,
                    simulated_reason=simulated.reason,
                    changed=changed,
                    explanation=(
                        f"{tool_name}: original {original_decision}/{original_reason}, "
                        f"simulated {simulated.decision}/{simulated.reason}"
                    ),
                )
            )
            prior_tool_calls += 1

        return SimulationSummary(
            total_evaluated=len(records),
            changed_count=sum(1 for record in records if record.changed),
            records=records,
        )

    def diff(self, events_path: Path, contract_a: Contract, contract_b: Contract) -> DiffSummary:
        summary_a = self.simulate(events_path, contract_a)
        summary_b = self.simulate(events_path, contract_b)
        records: list[DiffRecord] = []

        for record_a, record_b in zip(summary_a.records, summary_b.records, strict=True):
            changed = (
                record_a.simulated_decision != record_b.simulated_decision
                or record_a.simulated_reason != record_b.simulated_reason
            )
            if not changed:
                continue
            records.append(
                DiffRecord(
                    sequence_id=record_a.sequence_id,
                    timestamp=record_a.timestamp,
                    tool_name=record_a.tool_name,
                    decision_a=record_a.simulated_decision,
                    decision_b=record_b.simulated_decision,
                    reason_a=record_a.simulated_reason,
                    reason_b=record_b.simulated_reason,
                    changed=True,
                    explanation=(
                        f"{record_a.tool_name}: contract_a {record_a.simulated_decision}/{record_a.simulated_reason}, "
                        f"contract_b {record_b.simulated_decision}/{record_b.simulated_reason}"
                    ),
                )
            )

        return DiffSummary(
            total_evaluated=summary_a.total_evaluated,
            changed_count=len(records),
            records=records,
        )

    @staticmethod
    def format_results(summary: SimulationSummary) -> str:
        lines = [
            "Simulation Results",
            f"Total evaluated: {summary.total_evaluated}",
            f"Changed: {summary.changed_count}",
        ]
        for record in summary.records:
            status = "CHANGED" if record.changed else "UNCHANGED"
            lines.append(
                f"{status} seq={record.sequence_id} tool={record.tool_name} "
                f"{record.original_decision}/{record.original_reason} -> "
                f"{record.simulated_decision}/{record.simulated_reason}"
            )
        return "\n".join(lines)

    @staticmethod
    def format_diff(diff: DiffSummary) -> str:
        lines = [
            "Simulation Diff",
            f"Total evaluated: {diff.total_evaluated}",
            f"Changed: {diff.changed_count}",
        ]
        for record in diff.records:
            lines.append(
                f"CHANGED seq={record.sequence_id} tool={record.tool_name} "
                f"A={record.decision_a}/{record.reason_a} "
                f"B={record.decision_b}/{record.reason_b}"
            )
        return "\n".join(lines)

    @staticmethod
    def _read_events(events_path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with Path(events_path).open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if isinstance(payload, dict):
                    rows.append(payload)
        return rows

    @staticmethod
    def _metadata_egress_target(metadata: dict[str, Any]) -> str | None:
        for key in ("egress_target", "destination"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _string_field(event: dict[str, Any], field: str, *, default: str | None = None) -> str:
        value = event.get(field, default)
        if not isinstance(value, str):
            if default is not None:
                return default
            raise ValueError(f"{field} must be a string")
        return value

    @staticmethod
    def _int_field(event: dict[str, Any], field: str) -> int:
        value = event.get(field)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{field} must be an integer")
        return value


__all__ = [
    "DiffRecord",
    "DiffSummary",
    "PolicySimulator",
    "SimulationRecord",
    "SimulationSummary",
]
