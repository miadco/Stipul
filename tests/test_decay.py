from __future__ import annotations

import logging
from dataclasses import fields
from datetime import datetime, timedelta, timezone

import pytest

from agentshield.budget.decay import DecayAlert, DecayDetector

try:
    from hypothesis import assume, given, settings
    from hypothesis import strategies as st

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False

SESSION_START = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
TTL = 600
BUDGET = {"tool_calls": 100.0, "net_calls": 50.0}


def _build_detector(ttl: int | None = TTL) -> DecayDetector:
    return DecayDetector(
        budget_limit=BUDGET,
        ttl=ttl,
        session_start=SESSION_START,
    )


def test_decay_alert_fields_and_alias() -> None:
    assert [field.name for field in fields(DecayAlert)] == [
        "triggered_dimension",
        "spend_fraction",
        "time_fraction",
        "burn_rate",
        "projected_exhaustion_seconds",
        "current_spend",
        "budget_limit",
    ]

    decay_module = __import__("agentshield.budget.decay", fromlist=["DecayAnomaly"])
    assert decay_module.DecayAnomaly is DecayAlert

    detector = _build_detector()
    alert = detector.check_burn_rate(
        current_spend={"tool_calls": 81.0, "net_calls": 0.0},
        current_time=SESSION_START + timedelta(seconds=60),
    )
    assert isinstance(alert, DecayAlert)


def test_init_rejects_naive_session_start() -> None:
    with pytest.raises(ValueError, match="session_start must be UTC-aware"):
        DecayDetector(
            budget_limit=BUDGET,
            ttl=TTL,
            session_start=datetime(2024, 1, 1, 0, 0, 0),
        )


def test_init_rejects_non_positive_ttl() -> None:
    with pytest.raises(ValueError, match="ttl must be a positive integer"):
        DecayDetector(budget_limit=BUDGET, ttl=0, session_start=SESSION_START)

    with pytest.raises(ValueError, match="ttl must be a positive integer"):
        DecayDetector(budget_limit=BUDGET, ttl=-1, session_start=SESSION_START)


def test_init_logs_warning_when_ttl_none(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        DecayDetector(budget_limit=BUDGET, ttl=None, session_start=SESSION_START)

    assert "No TTL set on contract, budget decay detection disabled." in caplog.text


def test_check_burn_rate_returns_none_when_ttl_none() -> None:
    detector = DecayDetector(budget_limit=BUDGET, ttl=None, session_start=SESSION_START)
    result = detector.check_burn_rate(
        current_spend={"tool_calls": 99.0, "net_calls": 49.0},
        current_time=SESSION_START + timedelta(seconds=60),
    )
    assert result is None


def test_check_burn_rate_rejects_naive_current_time() -> None:
    detector = _build_detector()
    with pytest.raises(ValueError, match="current_time must be UTC-aware"):
        detector.check_burn_rate(
            current_spend={"tool_calls": 99.0, "net_calls": 49.0},
            current_time=datetime(2024, 1, 1, 0, 1, 0),
        )


def test_check_burn_rate_returns_none_outside_open_window() -> None:
    detector = _build_detector()
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 99.0, "net_calls": 49.0},
            current_time=SESSION_START,
        )
        is None
    )
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 99.0, "net_calls": 49.0},
            current_time=SESSION_START - timedelta(seconds=1),
        )
        is None
    )
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 99.0, "net_calls": 49.0},
            current_time=SESSION_START + timedelta(seconds=TTL),
        )
        is None
    )
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 99.0, "net_calls": 49.0},
            current_time=SESSION_START + timedelta(seconds=TTL + 1),
        )
        is None
    )


def test_strict_threshold_boundaries_do_not_trigger() -> None:
    detector = _build_detector()
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 80.0, "net_calls": 0.0},
            current_time=SESSION_START + timedelta(seconds=60),
        )
        is None
    )
    assert (
        detector.check_burn_rate(
            current_spend={"tool_calls": 90.0, "net_calls": 0.0},
            current_time=SESSION_START + timedelta(seconds=120),
        )
        is None
    )


def test_single_dimension_anomaly_detected_with_expected_values() -> None:
    detector = _build_detector()
    current_time = (SESSION_START + timedelta(seconds=60)).astimezone(
        timezone(timedelta(hours=2))
    )
    alert = detector.check_burn_rate(
        current_spend={"tool_calls": 81.0, "net_calls": 0.0},
        current_time=current_time,
    )
    assert alert is not None
    assert alert.triggered_dimension == "tool_calls"
    assert alert.spend_fraction == pytest.approx(0.81)
    assert alert.time_fraction == pytest.approx(0.1)
    assert alert.burn_rate == pytest.approx(8.1)
    assert alert.projected_exhaustion_seconds > 0


def test_zero_budget_dimension_is_skipped() -> None:
    detector = DecayDetector(
        budget_limit={"tool_calls": 0.0, "net_calls": 100.0},
        ttl=TTL,
        session_start=SESSION_START,
    )
    alert = detector.check_burn_rate(
        current_spend={"tool_calls": 999.0, "net_calls": 90.0},
        current_time=SESSION_START + timedelta(seconds=60),
    )
    assert alert is not None
    assert alert.triggered_dimension == "net_calls"


def test_highest_burn_rate_candidate_is_selected() -> None:
    detector = DecayDetector(
        budget_limit={"tool_calls": 100.0, "net_calls": 200.0},
        ttl=1000,
        session_start=SESSION_START,
    )
    # time_fraction = 0.15
    # tool burn = (85/100)/0.15 = 5.666...
    # net burn = (190/200)/0.15 = 6.333...
    alert = detector.check_burn_rate(
        current_spend={"tool_calls": 85.0, "net_calls": 190.0},
        current_time=SESSION_START + timedelta(seconds=150),
    )
    assert alert is not None
    assert alert.triggered_dimension == "net_calls"


def test_to_event_payload_contains_required_fields_and_inf_message() -> None:
    detector = _build_detector()
    alert = DecayAlert(
        triggered_dimension="tool_calls",
        spend_fraction=0.9,
        time_fraction=0.1,
        burn_rate=0.0,
        projected_exhaustion_seconds=float("inf"),
        current_spend={"tool_calls": 90.0},
        budget_limit={"tool_calls": 100.0},
    )

    payload = detector.to_event_payload(alert)

    assert payload["event_subtype"] == "budget_anomaly"
    assert payload["message"]
    assert "tool_calls" in payload["message"]
    assert "unknown (burn rate is zero)" in payload["message"]


if HYPOTHESIS_AVAILABLE:

    @settings(max_examples=200)
    @given(
        ttl=st.integers(min_value=1, max_value=10_000),
        tool_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        tool_spend=st.floats(
            min_value=0.0,
            max_value=2_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_spend=st.floats(
            min_value=0.0,
            max_value=2_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        offset_fraction=st.one_of(
            st.floats(
                min_value=-1.0,
                max_value=0.0,
                allow_nan=False,
                allow_infinity=False,
            ),
            st.floats(
                min_value=1.0,
                max_value=2.0,
                allow_nan=False,
                allow_infinity=False,
            ),
        ),
    )
    def test_prop_open_window_outside_returns_none(
        ttl: int,
        tool_budget: float,
        net_budget: float,
        tool_spend: float,
        net_spend: float,
        offset_fraction: float,
    ) -> None:
        detector = DecayDetector(
            budget_limit={"tool_calls": tool_budget, "net_calls": net_budget},
            ttl=ttl,
            session_start=SESSION_START,
        )
        current_time = SESSION_START + timedelta(seconds=float(ttl) * offset_fraction)
        result = detector.check_burn_rate(
            current_spend={"tool_calls": tool_spend, "net_calls": net_spend},
            current_time=current_time,
        )
        assert result is None


    @settings(max_examples=200)
    @given(
        ttl=st.integers(min_value=1, max_value=10_000),
        tool_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        tool_spend=st.floats(
            min_value=0.0,
            max_value=2_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_spend=st.floats(
            min_value=0.0,
            max_value=2_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        time_fraction=st.floats(
            min_value=1e-6,
            max_value=0.999999,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    def test_prop_alert_satisfies_strict_thresholds(
        ttl: int,
        tool_budget: float,
        net_budget: float,
        tool_spend: float,
        net_spend: float,
        time_fraction: float,
    ) -> None:
        detector = DecayDetector(
            budget_limit={"tool_calls": tool_budget, "net_calls": net_budget},
            ttl=ttl,
            session_start=SESSION_START,
        )
        current_time = SESSION_START + timedelta(seconds=float(ttl) * time_fraction)
        alert = detector.check_burn_rate(
            current_spend={"tool_calls": tool_spend, "net_calls": net_spend},
            current_time=current_time,
        )
        if alert is None:
            return
        assert alert.spend_fraction > 0.8
        assert alert.time_fraction < 0.2


    @settings(max_examples=200)
    @given(
        ttl=st.integers(min_value=1, max_value=10_000),
        tool_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_budget=st.floats(
            min_value=1.0,
            max_value=1_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        tool_fraction=st.floats(
            min_value=0.800001,
            max_value=2.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        net_fraction=st.floats(
            min_value=0.800001,
            max_value=2.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        time_fraction=st.floats(
            min_value=1e-6,
            max_value=0.199999,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    def test_prop_highest_burn_rate_selected_with_tolerance(
        ttl: int,
        tool_budget: float,
        net_budget: float,
        tool_fraction: float,
        net_fraction: float,
        time_fraction: float,
    ) -> None:
        assume(tool_budget > 0 and net_budget > 0)
        detector = DecayDetector(
            budget_limit={"tool_calls": tool_budget, "net_calls": net_budget},
            ttl=ttl,
            session_start=SESSION_START,
        )
        tool_spend = tool_budget * tool_fraction
        net_spend = net_budget * net_fraction
        current_time = SESSION_START + timedelta(seconds=float(ttl) * time_fraction)
        alert = detector.check_burn_rate(
            current_spend={"tool_calls": tool_spend, "net_calls": net_spend},
            current_time=current_time,
        )
        assert alert is not None

        burn_tool = (tool_spend / tool_budget) / time_fraction
        burn_net = (net_spend / net_budget) / time_fraction
        max_burn = max(burn_tool, burn_net)
        assert alert.burn_rate >= max_burn - 1e-9

        if abs(burn_tool - burn_net) > 1e-9:
            expected = "tool_calls" if burn_tool > burn_net else "net_calls"
            assert alert.triggered_dimension == expected
        else:
            assert alert.triggered_dimension in {"tool_calls", "net_calls"}


    @settings(max_examples=200)
    @given(
        spend_fraction=st.floats(
            min_value=0.0,
            max_value=2.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        time_fraction=st.floats(
            min_value=1e-6,
            max_value=0.999999,
            allow_nan=False,
            allow_infinity=False,
        ),
        burn_rate=st.floats(
            min_value=0.0,
            max_value=10_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        projected_exhaustion_seconds=st.floats(
            min_value=0.0,
            max_value=10_000_000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        triggered_dimension=st.sampled_from(["tool_calls", "net_calls"]),
    )
    def test_prop_to_event_payload_has_subtype_and_dimension(
        spend_fraction: float,
        time_fraction: float,
        burn_rate: float,
        projected_exhaustion_seconds: float,
        triggered_dimension: str,
    ) -> None:
        detector = _build_detector()
        alert = DecayAlert(
            triggered_dimension=triggered_dimension,
            spend_fraction=spend_fraction,
            time_fraction=time_fraction,
            burn_rate=burn_rate,
            projected_exhaustion_seconds=projected_exhaustion_seconds,
            current_spend={"tool_calls": 1.0, "net_calls": 1.0},
            budget_limit={"tool_calls": 1.0, "net_calls": 1.0},
        )
        payload = detector.to_event_payload(alert)
        assert payload["event_subtype"] == "budget_anomaly"
        assert triggered_dimension in payload["message"]
