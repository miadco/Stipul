from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.decisions import (
    DecisionRecord,
    generate_decisions,
    regenerate_if_invalid,
    verify_decisions,
    write_decisions,
)
from stipul.chronicle.events.summary import build_summary, summary_to_event, write_summary_json
from stipul.utils.canonical import canonical_json_bytes

try:
    from hypothesis import given
    from hypothesis import strategies as st

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False


@dataclass
class _Chain:
    status: str
    first_failure_sequence_id: int | None = None


def test_generate_decisions_filters_correctly(make_test_events: Callable[[list[dict[str, Any]]], Path]) -> None:
    events_path = make_test_events(
        [
            {"decision": "allow"},
            {"decision": ""},
            {"drop_decision": True},
            {"decision": "deny"},
        ]
    )
    projected = generate_decisions(events_path)
    assert [record.sequence_id for record in projected] == [1, 4]


def test_generate_decisions_extracts_only_seven_fields(
    make_test_events: Callable[[list[dict[str, Any]]], Path]
) -> None:
    events_path = make_test_events([{"decision": "allow"}])
    projected = generate_decisions(events_path)
    assert len(projected) == 1
    assert set(projected[0].__dict__.keys()) == {
        "sequence_id",
        "event_type",
        "decision",
        "reason",
        "tool_name",
        "contract_id",
        "contract_hash",
    }


def test_generate_decisions_skips_missing_contract_hash(
    make_test_events: Callable[[list[dict[str, Any]]], Path]
) -> None:
    events_path = make_test_events(
        [
            {"decision": "allow", "contract_hash": "a" * 64},
            {"decision": "deny", "contract_hash": ""},
        ]
    )
    projected = generate_decisions(events_path)
    assert [record.sequence_id for record in projected] == [1]


def test_write_decisions_canonical_json_sorted_keys(tmp_path: Path) -> None:
    decisions_path = tmp_path / "decisions.jsonl"
    write_decisions(
        [
            DecisionRecord(
                sequence_id=1,
                event_type="tool_call",
                decision="allow",
                reason="risk_class",
                tool_name="tool.default",
                contract_id="contract-123",
                contract_hash="a" * 64,
            )
        ],
        decisions_path,
    )
    first = json.loads(decisions_path.read_text(encoding="utf-8").splitlines()[0])
    assert list(first.keys()) == sorted(first.keys())


def test_verify_decisions_valid(make_test_events: Callable[[list[dict[str, Any]]], Path], tmp_path: Path) -> None:
    events_path = make_test_events([{"decision": "allow"}, {"decision": "deny"}])
    decisions_path = tmp_path / "decisions.jsonl"
    write_decisions(generate_decisions(events_path), decisions_path)

    result = verify_decisions(events_path, decisions_path)
    assert result.is_valid is True
    assert result.mismatches == []


def test_verify_decisions_missing_record(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    tmp_path: Path,
) -> None:
    events_path = make_test_events([{"decision": "allow"}, {"decision": "deny"}])
    decisions_path = tmp_path / "decisions.jsonl"
    write_decisions(generate_decisions(events_path)[:1], decisions_path)

    result = verify_decisions(events_path, decisions_path)
    assert result.is_valid is False
    assert len(result.mismatches) == 1
    mismatch = result.mismatches[0]
    assert mismatch.sequence_id == 2
    assert mismatch.mismatch_type == "missing_decision"


def test_verify_decisions_extra_record(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    tmp_path: Path,
) -> None:
    events_path = make_test_events([{"decision": "allow"}])
    decisions_path = tmp_path / "decisions.jsonl"
    records = generate_decisions(events_path) + [
        DecisionRecord(
            sequence_id=999,
            event_type="tool_call",
            decision="allow",
            reason="risk_class",
            tool_name="tool.extra",
            contract_id="contract-123",
            contract_hash="a" * 64,
        )
    ]
    write_decisions(records, decisions_path)

    result = verify_decisions(events_path, decisions_path)
    assert result.is_valid is False
    assert len(result.mismatches) == 1
    assert result.mismatches[0].mismatch_type == "extra_decision"


def test_verify_decisions_field_mismatch(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    tmp_path: Path,
) -> None:
    events_path = make_test_events([{"decision": "allow"}])
    decisions_path = tmp_path / "decisions.jsonl"
    bad = generate_decisions(events_path)[0]
    write_decisions(
        [
            DecisionRecord(
                sequence_id=bad.sequence_id,
                event_type=bad.event_type,
                decision=bad.decision,
                reason="tampered",
                tool_name=bad.tool_name,
                contract_id=bad.contract_id,
                contract_hash=bad.contract_hash,
            )
        ],
        decisions_path,
    )

    result = verify_decisions(events_path, decisions_path)
    assert result.is_valid is False
    assert any(
        mismatch.mismatch_type == "field_mismatch" and mismatch.field == "reason"
        for mismatch in result.mismatches
    )


def test_regenerate_if_invalid_fixes_file_and_logs_warning(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    events_path = make_test_events([{"decision": "allow"}, {"decision": "deny"}])
    decisions_path = tmp_path / "decisions.jsonl"
    write_decisions(generate_decisions(events_path)[:1], decisions_path)

    with caplog.at_level("WARNING"):
        before, after = regenerate_if_invalid(events_path, decisions_path)

    assert before.is_valid is False
    assert after.is_valid is True
    assert "Regenerated from authoritative source" in caplog.text


def test_regenerate_if_valid_does_not_rewrite_file(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    tmp_path: Path,
) -> None:
    events_path = make_test_events([{"decision": "allow"}])
    decisions_path = tmp_path / "decisions.jsonl"
    write_decisions(generate_decisions(events_path), decisions_path)
    before_hash = hashlib.sha256(decisions_path.read_bytes()).hexdigest()

    before, after = regenerate_if_invalid(events_path, decisions_path)
    after_hash = hashlib.sha256(decisions_path.read_bytes()).hexdigest()

    assert before.is_valid is True
    assert after.is_valid is True
    assert before_hash == after_hash


def test_build_summary_tool_statistics(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events(
        [
            {"event_type": "tool_call", "tool_name": "tool.a", "decision": "allow"},
            {"event_type": "tool_call", "tool_name": "tool.a", "decision": "deny", "reason": "not_allowed"},
            {
                "event_type": "tool_call",
                "tool_name": "tool.b",
                "decision": "require_approval",
                "reason": "approval_required",
            },
        ]
    )
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 3.0, "net_calls": 0.0},
    )
    assert summary.tools_invoked == {"tool.a": 1}
    assert summary.tools_denied == {"tool.a": ["not_allowed"]}
    assert summary.total_allowed == 1
    assert summary.total_denied == 1
    assert summary.total_approval_required == 1
    assert summary.total_calls == 3


def test_build_summary_egress_statistics_uses_metadata_priority(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events(
        [
            {
                "event_type": "net_call",
                "tool_name": "fallback",
                "metadata": {"egress_target": "egress.example", "destination": "ignored.example"},
                "decision": "allow",
            },
            {
                "event_type": "net_call",
                "tool_name": "fallback",
                "metadata": {"destination": "dest.example", "domain": "ignored.example"},
                "decision": "deny",
                "reason": "not_in_egress_allowlist",
            },
            {
                "event_type": "net_call",
                "tool_name": "fallback",
                "metadata": {"domain": "domain.example"},
                "decision": "allow",
            },
            {
                "event_type": "net_call",
                "tool_name": "fallback.only",
                "metadata": None,
                "decision": "allow",
            },
        ]
    )
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 0.0, "net_calls": 4.0},
    )
    assert summary.egress_attempted == {
        "egress.example": 1,
        "dest.example": 1,
        "domain.example": 1,
        "fallback.only": 1,
    }
    assert summary.egress_denied == {"dest.example": ["not_in_egress_allowlist"]}


def test_build_summary_budget_fields_exhaustion_and_timestamp(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events(
        [{"event_type": "tool_call", "decision": "allow"} for _ in range(contract.max_tool_calls)]
        + [{"event_type": "net_call", "decision": "allow"}]
    )
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={
            "tool_calls": float(contract.max_tool_calls),
            "net_calls": 1.0,
        },
    )
    assert summary.budget_exhausted is True
    assert summary.budget_exhaustion_timestamp is not None
    assert summary.budget_remaining["tool_calls"] == 0.0


def test_build_summary_budget_no_exhaustion(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call", "decision": "allow"}])
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    assert summary.budget_exhausted is False
    assert summary.budget_exhaustion_timestamp is None


def test_build_summary_anomaly_count_reason_or_metadata(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events(
        [
            {"event_type": "write_op", "reason": "budget_anomaly_detected"},
            {"event_type": "write_op", "metadata": {"event_subtype": "budget_anomaly"}},
            {
                "event_type": "write_op",
                "reason": "budget_anomaly_detected",
                "metadata": {"event_subtype": "budget_anomaly"},
            },
        ]
    )
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 0.0, "net_calls": 0.0},
    )
    assert summary.budget_anomalies_detected == 3


def test_build_summary_chain_integrity_intact_and_broken(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    common_kwargs = dict(
        events_path=events_path,
        contract=contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    intact = build_summary(chain_result=_Chain(status="INTACT"), **common_kwargs)
    broken = build_summary(chain_result=_Chain(status="BROKEN", first_failure_sequence_id=7), **common_kwargs)
    fallback = build_summary(chain_result=_Chain(status="ERROR"), **common_kwargs)
    assert intact.chain_integrity == "intact"
    assert broken.chain_integrity == "broken at sequence_id 7"
    assert fallback.chain_integrity == "broken"


def test_build_summary_attestations_gap_detected_behavior(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    with_gap = make_test_events(
        [{"event_type": "write_op", "reason": "gap_detected"}, {"event_type": "tool_call"}]
    )
    without_gap = make_test_events([{"event_type": "tool_call"}])

    summary_gap = build_summary(
        with_gap,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    summary_no_gap = build_summary(
        without_gap,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    assert any("coverage gaps detected" in item for item in summary_gap.attestations)
    assert not any("No unmanaged credential use" in item for item in summary_gap.attestations)
    assert any("No unmanaged credential use" in item for item in summary_no_gap.attestations)


def test_summary_to_event_format_and_no_reserved_fields(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    event = summary_to_event(summary, agent_identity="b" * 64)
    assert event["event_type"] == "write_op"
    assert event["decision"] == "allow"
    assert event["reason"] == "session_close"
    assert event["tool_name"] == "session_summary"
    assert event["risk_class"] == "read"
    assert event["contract_id"] == summary.contract_id
    assert event["agent_identity"] == "b" * 64
    expected_input_hash = hashlib.sha256(canonical_json_bytes(event["metadata"])).hexdigest()
    assert event["input_hash"] == expected_input_hash
    for key in ("sequence_id", "timestamp", "prev_hash", "signature"):
        assert key not in event


def test_duration_seconds_correct(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(seconds=123)
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=start,
        session_end=end,
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    assert summary.duration_seconds == 123.0


def test_write_summary_json_format_pretty(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
    tmp_path: Path,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    output = tmp_path / "summary.json"
    write_summary_json(summary, output)
    raw = output.read_text(encoding="utf-8")
    assert "\n  " in raw
    parsed = json.loads(raw)
    assert parsed["session_id"] == "session-123"


def test_naive_session_start_raises(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    with pytest.raises(ValueError, match="session_start must be timezone-aware"):
        build_summary(
            events_path,
            contract,
            session_id="session-123",
            session_start=datetime(2026, 1, 1),
            session_end=datetime(2026, 1, 1, tzinfo=timezone.utc),
            chain_result=_Chain(status="INTACT"),
            budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
        )


def test_naive_session_end_raises(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    with pytest.raises(ValueError, match="session_end must be timezone-aware"):
        build_summary(
            events_path,
            contract,
            session_id="session-123",
            session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            session_end=datetime(2026, 1, 1),
            chain_result=_Chain(status="INTACT"),
            budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
        )


def test_summary_includes_contract_hash(
    make_test_events: Callable[[list[dict[str, Any]]], Path],
    contract,
) -> None:
    events_path = make_test_events([{"event_type": "tool_call"}])
    summary = build_summary(
        events_path,
        contract,
        session_id="session-123",
        session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        chain_result=_Chain(status="INTACT"),
        budget_consumed={"tool_calls": 1.0, "net_calls": 0.0},
    )
    assert summary.contract_hash == compute_contract_hash(contract)


if HYPOTHESIS_AVAILABLE:

    @given(
        decisions=st.lists(
            st.sampled_from(["allow", "deny", "require_approval"]),
            min_size=1,
            max_size=50,
        )
    )
    def test_prop_total_calls_balance(
        decisions: list[str],
        make_test_events: Callable[[list[dict[str, Any]]], Path],
        contract,
    ) -> None:
        events_path = make_test_events(
            [{"event_type": "tool_call", "decision": decision} for decision in decisions]
        )
        summary = build_summary(
            events_path,
            contract,
            session_id="session-123",
            session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            chain_result=_Chain(status="INTACT"),
            budget_consumed={"tool_calls": float(len(decisions)), "net_calls": 0.0},
        )
        assert summary.total_calls == (
            summary.total_allowed + summary.total_denied + summary.total_approval_required
        )


    @given(
        tool_limit=st.floats(min_value=1.0, max_value=1000.0, allow_infinity=False, allow_nan=False),
        net_limit=st.floats(min_value=1.0, max_value=1000.0, allow_infinity=False, allow_nan=False),
        tool_used=st.floats(min_value=0.0, max_value=1000.0, allow_infinity=False, allow_nan=False),
        net_used=st.floats(min_value=0.0, max_value=1000.0, allow_infinity=False, allow_nan=False),
    )
    def test_prop_budget_remaining_plus_consumed_equals_limit(
        tool_limit: float,
        net_limit: float,
        tool_used: float,
        net_used: float,
        make_test_events: Callable[[list[dict[str, Any]]], Path],
        contract,
    ) -> None:
        events_path = make_test_events([{"event_type": "tool_call"}])
        adjusted_contract = contract.__class__(
            schema_version=contract.schema_version,
            contract_id=contract.contract_id,
            parent_contract_id=contract.parent_contract_id,
            created_at=contract.created_at,
            expires_at=contract.expires_at,
            signed_by=contract.signed_by,
            identity_agent_id=contract.identity_agent_id,
            identity_code_sha256=contract.identity_code_sha256,
            allowed_tools=contract.allowed_tools,
            never_allow_tools=contract.never_allow_tools,
            tool_risk_classes=contract.tool_risk_classes,
            max_tool_calls=int(tool_limit),
            max_net_calls=int(net_limit),
            egress_allowlist=contract.egress_allowlist,
        )
        consumed = {
            "tool_calls": min(tool_used, float(adjusted_contract.max_tool_calls)),
            "net_calls": min(net_used, float(adjusted_contract.max_net_calls)),
        }
        summary = build_summary(
            events_path,
            adjusted_contract,
            session_id="session-123",
            session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            chain_result=_Chain(status="INTACT"),
            budget_consumed=consumed,
        )
        assert summary.budget_remaining["tool_calls"] + summary.budget_consumed["tool_calls"] == pytest.approx(
            float(adjusted_contract.max_tool_calls)
        )
        assert summary.budget_remaining["net_calls"] + summary.budget_consumed["net_calls"] == pytest.approx(
            float(adjusted_contract.max_net_calls)
        )


    @given(decision_count=st.integers(min_value=1, max_value=50))
    def test_prop_known_blind_spots_never_empty(
        decision_count: int,
        make_test_events: Callable[[list[dict[str, Any]]], Path],
        contract,
    ) -> None:
        events_path = make_test_events(
            [{"event_type": "tool_call", "decision": "allow"} for _ in range(decision_count)]
        )
        summary = build_summary(
            events_path,
            contract,
            session_id="session-123",
            session_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            session_end=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            chain_result=_Chain(status="INTACT"),
            budget_consumed={"tool_calls": float(decision_count), "net_calls": 0.0},
        )
        assert len(summary.known_blind_spots) >= 1
