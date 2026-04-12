from __future__ import annotations

import json
from http.client import HTTPConnection, HTTPResponse
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.signing.keys import generate_keypair
from stipul.writ.proxy.server import ProxyServer

_SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _build_proxy(contract: Contract, events_path: Path) -> ProxyServer:
    events_path.parent.mkdir(parents=True, exist_ok=True)
    keypair = generate_keypair(events_path.parent / ".stipul" / "keys")
    logger = EventLogger(
        store=EventStore(events_path),
        session_id=_SESSION_ID,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        signing_key=keypair,
        state_dir=events_path.parent,
    )
    return ProxyServer(
        contract=contract,
        event_logger=logger,
        session_id=_SESSION_ID,
    )


def _request_json(
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    url = urlsplit(base_url)
    body = None
    headers: dict[str, str] = {}
    if payload is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        headers["Content-Type"] = "application/json"

    connection = HTTPConnection(url.hostname, url.port, timeout=2.0)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw_body = response.read().decode("utf-8")
    finally:
        connection.close()

    decoded = json.loads(raw_body) if raw_body else {}
    assert isinstance(decoded, dict)
    return response.status, decoded


def _request_raw(
    base_url: str,
    method: str,
    path: str,
) -> tuple[HTTPResponse, str]:
    url = urlsplit(base_url)
    connection = HTTPConnection(url.hostname, url.port, timeout=2.0)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
    finally:
        connection.close()

    class _RawResponse:
        def __init__(self, status: int, headers: dict[str, str]) -> None:
            self.status = status
            self.headers = headers

        def getheader(self, name: str, default: str | None = None) -> str | None:
            return self.headers.get(name.lower(), default)

    return _RawResponse(status, headers), body


def _read_events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_control_sidecar_serves_status_and_toggle_endpoints(tmp_path: Path, contract: Contract) -> None:
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)

    try:
        base_url = proxy.start_control_sidecar(port=0)
        parsed = urlsplit(base_url)

        assert parsed.scheme == "http"
        assert parsed.hostname == "127.0.0.1"
        assert parsed.port is not None and parsed.port > 0

        page_response, page_body = _request_raw(base_url, "GET", "/")
        assert page_response.status == 200
        assert page_response.getheader("Content-Type") == "text/html; charset=utf-8"
        assert "Local operator surface, loopback only." in page_body
        assert "/operator/status" in page_body
        assert "/operator/kill-switch/enable" in page_body
        assert "/operator/kill-switch/disable" in page_body

        status_code, health = _request_json(base_url, "GET", "/health")
        assert status_code == 200
        assert health["status"] == "healthy"
        assert health["kill_switch_active"] is False
        assert health["operator_updated_at"] is None
        assert health["operator_updated_by"] is None
        assert health["operator_reason"] is None

        status_code, operator_status = _request_json(base_url, "GET", "/operator/status")
        assert status_code == 200
        assert operator_status == {
            "kill_switch_active": False,
            "operator_updated_at": None,
            "operator_updated_by": None,
            "operator_reason": None,
        }

        status_code, enabled = _request_json(
            base_url,
            "POST",
            "/operator/kill-switch/enable",
            {"by": "operator@example.com", "reason": "operator_kill_switch_enabled"},
        )
        assert status_code == 200
        assert enabled["kill_switch_active"] is True
        assert enabled["operator_updated_by"] == "operator@example.com"
        assert enabled["operator_reason"] == "operator_kill_switch_enabled"
        assert proxy.health.payload()["operator_updated_by"] == "operator@example.com"

        # Clear the in-memory health fields to prove the next HTTP read refreshes from proxy state.
        proxy.health.update_operator_status(
            kill_switch_active=False,
            updated_at=None,
            updated_by=None,
            reason=None,
        )

        status_code, refreshed = _request_json(base_url, "GET", "/operator/status")
        assert status_code == 200
        assert refreshed["kill_switch_active"] is True
        assert refreshed["operator_updated_by"] == "operator@example.com"
        assert refreshed["operator_reason"] == "operator_kill_switch_enabled"

        status_code, disabled = _request_json(
            base_url,
            "POST",
            "/operator/kill-switch/disable",
            {"by": "operator@example.com", "reason": "operator_kill_switch_disabled"},
        )
        assert status_code == 200
        assert disabled["kill_switch_active"] is False
        assert disabled["operator_updated_by"] == "operator@example.com"
        assert disabled["operator_reason"] == "operator_kill_switch_disabled"

        events = _read_events(events_path)
        assert events[0]["event_type"] == "session_open"
        assert [(event["event_type"], event["decision"], event["reason"]) for event in events[1:]] == [
            ("elev_op", "allow", "operator_kill_switch_enabled"),
            ("elev_op", "allow", "operator_kill_switch_disabled"),
        ]
        assert events[1]["metadata"]["updated_by"] == "operator@example.com"
        assert events[2]["metadata"]["updated_by"] == "operator@example.com"
    finally:
        proxy.close()


def test_proxy_close_stops_control_sidecar_cleanly(tmp_path: Path, contract: Contract) -> None:
    events_path = tmp_path / "session" / "events.jsonl"
    proxy = _build_proxy(contract, events_path)
    base_url = proxy.start_control_sidecar(port=0)

    status_code, _ = _request_json(base_url, "GET", "/health")
    assert status_code == 200

    proxy.close()

    with pytest.raises(OSError):
        _request_json(base_url, "GET", "/health")
