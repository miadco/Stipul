"""Wrapper coverage and proxy bypass detection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True)
class BypassGap:
    tool_name: str
    timestamp: str
    source: Literal["wrapper_only", "proxy_only"]
    context: str


@dataclass(frozen=True)
class CoverageReport:
    total_wrapper_calls: int
    total_proxy_calls: int
    matched_calls: int
    gaps: list[BypassGap]
    coverage_percentage: float
    assessment: str


def _parse_timestamp(field: str, value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 string")
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(iso_value)
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _assessment(coverage_percentage: float) -> str:
    if coverage_percentage == 100.0:
        return "Full"
    if coverage_percentage >= 95.0:
        return "Near-full"
    if coverage_percentage >= 50.0:
        return "Partial"
    return "Low"


class BypassDetector:
    """Compare wrapper-observed calls with proxy tool-call events."""

    def __init__(self, proxy_events_path: Path, wrapper_log_path: Path) -> None:
        self.proxy_events_path = Path(proxy_events_path)
        self.wrapper_log_path = Path(wrapper_log_path)

    def detect(self, session_start: datetime, session_end: datetime) -> CoverageReport:
        session_start_dt = self._ensure_aware("session_start", session_start)
        session_end_dt = self._ensure_aware("session_end", session_end)

        wrapper_rows = [
            row
            for row in _read_jsonl(self.wrapper_log_path)
            if session_start_dt <= _parse_timestamp("timestamp", row["timestamp"]) <= session_end_dt
        ]
        proxy_rows = [
            row
            for row in _read_jsonl(self.proxy_events_path)
            if row.get("event_type") == "tool_call"
            and session_start_dt <= _parse_timestamp("timestamp", row["timestamp"]) <= session_end_dt
        ]

        matched_proxy_indices: set[int] = set()
        matched_calls = 0
        gaps: list[BypassGap] = []

        for wrapper_row in wrapper_rows:
            wrapper_time = _parse_timestamp("timestamp", wrapper_row["timestamp"])
            wrapper_tool = str(wrapper_row.get("tool_name", "unknown_tool"))
            wrapper_hash = wrapper_row.get("input_hash")
            matched_index = None

            for idx, proxy_row in enumerate(proxy_rows):
                if idx in matched_proxy_indices:
                    continue
                if proxy_row.get("tool_name") != wrapper_tool:
                    continue
                if proxy_row.get("input_hash") != wrapper_hash:
                    continue
                proxy_time = _parse_timestamp("timestamp", proxy_row["timestamp"])
                if abs((proxy_time - wrapper_time).total_seconds()) <= 2.0:
                    matched_index = idx
                    break

            if matched_index is None:
                gaps.append(
                    BypassGap(
                        tool_name=wrapper_tool,
                        timestamp=wrapper_row["timestamp"],
                        source="wrapper_only",
                        context=(
                            f"token_valid={wrapper_row.get('token_valid')} "
                            f"execution_result={wrapper_row.get('execution_result')}"
                        ),
                    )
                )
                continue

            matched_proxy_indices.add(matched_index)
            matched_calls += 1

        for idx, proxy_row in enumerate(proxy_rows):
            if idx in matched_proxy_indices:
                continue
            gaps.append(
                BypassGap(
                    tool_name=str(proxy_row.get("tool_name", "unknown_tool")),
                    timestamp=str(proxy_row.get("timestamp")),
                    source="proxy_only",
                    context=(
                        f"decision={proxy_row.get('decision')} "
                        f"reason={proxy_row.get('reason')}"
                    ),
                )
            )

        coverage_percentage = (
            100.0
            if not wrapper_rows
            else (matched_calls / len(wrapper_rows)) * 100.0
        )

        return CoverageReport(
            total_wrapper_calls=len(wrapper_rows),
            total_proxy_calls=len(proxy_rows),
            matched_calls=matched_calls,
            gaps=gaps,
            coverage_percentage=coverage_percentage,
            assessment=_assessment(coverage_percentage),
        )

    @staticmethod
    def emit_gap_events(gaps: list[BypassGap]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for gap in gaps:
            events.append(
                {
                    "event_type": "write_op",
                    "tool_name": gap.tool_name,
                    "risk_class": "irreversible",
                    "decision": "deny",
                    "reason": "gap_detected",
                    "metadata": {
                        "event_subtype": "gap_detected",
                        "gap_source": gap.source,
                        "gap_timestamp": gap.timestamp,
                        "context": gap.context,
                    },
                }
            )
        return events

    @staticmethod
    def to_summary_fields(report: CoverageReport) -> dict[str, Any]:
        return {
            "coverage_percentage": report.coverage_percentage,
            "coverage_assessment": report.assessment,
            "gaps_detected": len(report.gaps),
            "gap_details": [
                {
                    "tool_name": gap.tool_name,
                    "timestamp": gap.timestamp,
                    "source": gap.source,
                    "context": gap.context,
                }
                for gap in report.gaps
            ],
        }

    @staticmethod
    def _ensure_aware(field: str, value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise ValueError(f"{field} must be a datetime")
        if value.tzinfo is None:
            raise ValueError(f"{field} must be timezone-aware")
        return value.astimezone(timezone.utc)


__all__ = ["BypassDetector", "BypassGap", "CoverageReport"]
