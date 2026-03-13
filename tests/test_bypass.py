from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from stipul.writ.detection.bypass import BypassDetector, BypassGap, CoverageReport
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.writ.proxy.server import ProxyServer
from stipul.chronicle.signing.keys import generate_keypair
from stipul.charter.token.mint import mint_token
from stipul.writ.wrapper.mcp_wrapper import handle_tool_call

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _dt(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def test_wrapper_writes_wrapper_log_jsonl(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    wrapper_log_path = tmp_path / "wrapper_log.jsonl"
    monkeypatch.setenv("STIPUL_WRAPPER_LOG_PATH", str(wrapper_log_path))

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="11111111-1111-1111-1111-111111111111",
        contract_id="2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f",
    )

    result = handle_tool_call(
        {
            "tool_name": "filesystem.write",
            "inputs": {"path": "out.txt"},
            "headers": {"Authorization": f"Bearer {token}"},
        },
        lambda request: {"ok": True, "tool": request["tool_name"]},
    )

    assert result == {"ok": True, "tool": "filesystem.write"}
    lines = wrapper_log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["tool_name"] == "filesystem.write"
    assert payload["token_valid"] is True
    assert payload["token_error"] is None
    assert payload["execution_result"] == "success"
    assert len(payload["input_hash"]) == 64


def test_detect_full_coverage(tmp_path: Path):
    proxy_path = tmp_path / "events.jsonl"
    wrapper_path = tmp_path / "wrapper_log.jsonl"
    _write_jsonl(
        proxy_path,
        [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "decision": "allow",
                "reason": "risk_class",
            }
        ],
    )
    _write_jsonl(
        wrapper_path,
        [
            {
                "timestamp": "2026-01-01T00:00:02Z",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "token_valid": True,
                "token_error": None,
                "execution_result": "success",
            }
        ],
    )

    report = BypassDetector(proxy_path, wrapper_path).detect(_dt(2026, 1, 1), _dt(2026, 1, 1, 0, 1, 0))

    assert report.total_wrapper_calls == 1
    assert report.total_proxy_calls == 1
    assert report.matched_calls == 1
    assert report.gaps == []
    assert report.coverage_percentage == 100.0
    assert report.assessment == "Full"


def test_detect_wrapper_only_gap(tmp_path: Path):
    proxy_path = tmp_path / "events.jsonl"
    wrapper_path = tmp_path / "wrapper_log.jsonl"
    _write_jsonl(proxy_path, [])
    _write_jsonl(
        wrapper_path,
        [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "token_valid": True,
                "token_error": None,
                "execution_result": "success",
            }
        ],
    )

    report = BypassDetector(proxy_path, wrapper_path).detect(_dt(2026, 1, 1), _dt(2026, 1, 1, 0, 1, 0))

    assert len(report.gaps) == 1
    assert report.gaps[0].source == "wrapper_only"
    assert report.assessment == "Low"


def test_detect_proxy_only_gap(tmp_path: Path):
    proxy_path = tmp_path / "events.jsonl"
    wrapper_path = tmp_path / "wrapper_log.jsonl"
    _write_jsonl(
        proxy_path,
        [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "decision": "allow",
                "reason": "risk_class",
            }
        ],
    )
    _write_jsonl(wrapper_path, [])

    report = BypassDetector(proxy_path, wrapper_path).detect(_dt(2026, 1, 1), _dt(2026, 1, 1, 0, 1, 0))

    assert len(report.gaps) == 1
    assert report.gaps[0].source == "proxy_only"
    assert report.coverage_percentage == 100.0
    assert report.assessment == "Full"


def test_detect_timestamp_tolerance(tmp_path: Path):
    proxy_path = tmp_path / "events.jsonl"
    wrapper_path = tmp_path / "wrapper_log.jsonl"
    _write_jsonl(
        proxy_path,
        [
            {
                "timestamp": "2026-01-01T00:00:03Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "decision": "allow",
                "reason": "risk_class",
            },
            {
                "timestamp": "2026-01-01T00:00:06Z",
                "event_type": "tool_call",
                "tool_name": "filesystem.write",
                "input_hash": "b" * 64,
                "decision": "allow",
                "reason": "risk_class",
            },
        ],
    )
    _write_jsonl(
        wrapper_path,
        [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "tool_name": "filesystem.write",
                "input_hash": "a" * 64,
                "token_valid": True,
                "token_error": None,
                "execution_result": "success",
            },
            {
                "timestamp": "2026-01-01T00:00:03Z",
                "tool_name": "filesystem.write",
                "input_hash": "b" * 64,
                "token_valid": True,
                "token_error": None,
                "execution_result": "success",
            },
        ],
    )

    report = BypassDetector(proxy_path, wrapper_path).detect(_dt(2026, 1, 1), _dt(2026, 1, 1, 0, 1, 0))

    assert report.matched_calls == 1
    assert len(report.gaps) == 2


def test_detect_empty_wrapper_log_returns_full_coverage(tmp_path: Path):
    proxy_path = tmp_path / "events.jsonl"
    wrapper_path = tmp_path / "wrapper_log.jsonl"
    _write_jsonl(proxy_path, [])

    report = BypassDetector(proxy_path, wrapper_path).detect(_dt(2026, 1, 1), _dt(2026, 1, 1, 0, 1, 0))

    assert report.total_wrapper_calls == 0
    assert report.coverage_percentage == 100.0
    assert report.assessment == "Full"


def test_emit_gap_events_and_summary_fields():
    gaps = [
        BypassGap(
            tool_name="filesystem.write",
            timestamp="2026-01-01T00:00:01Z",
            source="wrapper_only",
            context="token_valid=True execution_result=success",
        )
    ]

    events = BypassDetector.emit_gap_events(gaps)
    assert events == [
        {
            "event_type": "write_op",
            "tool_name": "filesystem.write",
            "risk_class": "irreversible",
            "decision": "deny",
            "reason": "gap_detected",
            "metadata": {
                "event_subtype": "gap_detected",
                "gap_source": "wrapper_only",
                "gap_timestamp": "2026-01-01T00:00:01Z",
                "context": "token_valid=True execution_result=success",
            },
        }
    ]

    report = CoverageReport(
        total_wrapper_calls=2,
        total_proxy_calls=1,
        matched_calls=1,
        gaps=gaps,
        coverage_percentage=50.0,
        assessment="Partial",
    )
    summary_fields = BypassDetector.to_summary_fields(report)

    assert summary_fields == {
        "coverage_percentage": 50.0,
        "coverage_assessment": "Partial",
        "gaps_detected": 1,
        "gap_details": [
            {
                "tool_name": "filesystem.write",
                "timestamp": "2026-01-01T00:00:01Z",
                "source": "wrapper_only",
                "context": "token_valid=True execution_result=success",
            }
        ],
    }


def test_detect_real_wrapper_and_proxy_match_with_canonical_hashing(tmp_path: Path, monkeypatch, contract):
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")
    wrapper_log_path = tmp_path / "wrapper_log.jsonl"
    monkeypatch.setenv("STIPUL_WRAPPER_LOG_PATH", str(wrapper_log_path))
    events_path = tmp_path / "events.jsonl"
    keypair = generate_keypair(tmp_path / ".stipul" / "keys")
    proxy = ProxyServer(
        contract=contract,
        event_logger=EventLogger(
            store=EventStore(events_path),
            session_id=_SESSION_ID,
            contract_id=contract.contract_id,
            contract_hash=compute_contract_hash(contract),
            signing_key=keypair,
            state_dir=tmp_path,
        ),
        session_id=_SESSION_ID,
        state_dir=tmp_path,
    )
    captured: dict[str, object] = {}

    def forward_from_proxy(request):
        captured["request"] = request
        return {"ok": True}

    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt"}},
        forward_from_proxy,
    )
    assert response == {"ok": True}

    wrapper_result = handle_tool_call(
        captured["request"],  # type: ignore[arg-type]
        lambda request: {"ok": True, "tool": request["tool_name"]},
    )
    assert wrapper_result == {"ok": True, "tool": "filesystem.write"}

    wrapper_rows = [json.loads(line) for line in wrapper_log_path.read_text(encoding="utf-8").splitlines() if line]
    wrapper_rows[0]["timestamp"] = wrapper_rows[0]["timestamp"].replace("Z", "+00:00")
    _write_jsonl(wrapper_log_path, wrapper_rows)

    report = BypassDetector(events_path, wrapper_log_path).detect(
        _dt(2025, 1, 1),
        _dt(2099, 1, 1),
    )

    assert report.total_wrapper_calls == 1
    assert report.total_proxy_calls == 1
    assert report.matched_calls == 1
    assert report.coverage_percentage == 100.0
    assert report.assessment == "Full"
