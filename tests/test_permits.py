from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agentshield.contract.schema import Contract
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.models import CanonicalEvent
from agentshield.permits import (
    PermitManager,
    PermitScopeError,
    PermitTTLError,
)

_SESSION_ID = "11111111-1111-1111-1111-111111111111"
_REQUESTED_BY = "a" * 64
_APPROVED_BY = "b" * 64
_SECRET = b"permit-secret"


def _dt(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _build_manager(contract: Contract) -> PermitManager:
    return PermitManager(contract=contract, secret=_SECRET, session_id=_SESSION_ID)


def _event(
    contract: Contract,
    *,
    tool_name: str,
    timestamp: str,
    reason: str,
    decision: str = "allow",
    event_type: str = "tool_call",
) -> CanonicalEvent:
    return CanonicalEvent(
        sequence_id=1,
        timestamp=timestamp,
        session_id=_SESSION_ID,
        event_type=event_type,
        tool_name=tool_name,
        risk_class="write",
        decision=decision,
        reason=reason,
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        agent_identity="c" * 64,
        input_hash="d" * 64,
        key_id="deadbeef",
        algorithm="ed25519",
        key_created_at="2026-01-01T00:00:00Z",
        prev_hash="0" * 64,
        signature=base64.b64encode(b"signature").decode("ascii"),
    )


def test_create_request_validates_inputs_and_normalizes_order(contract):
    manager = _build_manager(contract)

    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["filesystem.write", "web.search", "filesystem.write"],
        permitted_destinations=["api.example.com", "api.example.com", ".trusted.example"],
        reason="Need a temporary write exception",
        requested_ttl=60,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )

    assert request.permitted_tools == ("filesystem.write", "web.search")
    assert request.permitted_destinations == (".trusted.example", "api.example.com")
    assert request.contract_hash == compute_contract_hash(contract)


def test_create_request_rejects_empty_tools(contract):
    manager = _build_manager(contract)

    with pytest.raises(ValueError, match="permitted_tools"):
        manager.create_request(
            requested_by_hex64=_REQUESTED_BY,
            permitted_tools=[],
            permitted_destinations=[],
            reason="Need a permit",
            requested_ttl=60,
            session_id=_SESSION_ID,
            requested_at=_dt(2026, 1, 1),
        )


def test_create_request_rejects_never_allow_tool(contract):
    manager = _build_manager(contract)

    with pytest.raises(ValueError, match="never_allow_tools"):
        manager.create_request(
            requested_by_hex64=_REQUESTED_BY,
            permitted_tools=["shell.exec"],
            permitted_destinations=[],
            reason="Need shell",
            requested_ttl=60,
            session_id=_SESSION_ID,
            requested_at=_dt(2026, 1, 1),
        )


def test_create_request_accepts_known_tool_from_risk_map_only(base_dict):
    payload = copy.deepcopy(base_dict)
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    contract = Contract.from_dict(payload)
    manager = _build_manager(contract)

    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["debug.inspect"],
        permitted_destinations=[],
        reason="Need a temporary debug tool permit",
        requested_ttl=60,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )

    assert request.permitted_tools == ("debug.inspect",)


def test_approve_request_allows_narrowing_and_rejects_widening(contract):
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["filesystem.write", "web.search"],
        permitted_destinations=["api.example.com", ".trusted.example"],
        reason="Need a temporary permit",
        requested_ttl=300,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )

    permit = manager.approve_request(
        request,
        approved_by_hex64=_APPROVED_BY,
        granted_tools=["web.search"],
        granted_destinations=["api.example.com"],
        granted_ttl=120,
        approved_at=_dt(2026, 1, 1, 0, 5, 0),
    )

    assert permit.granted_tools == ("web.search",)
    assert permit.granted_destinations == ("api.example.com",)

    with pytest.raises(PermitScopeError, match="subset"):
        manager.approve_request(
            request,
            approved_by_hex64=_APPROVED_BY,
            granted_tools=["filesystem.write", "new.tool"],
            approved_at=_dt(2026, 1, 1, 0, 5, 0),
        )


def test_approve_request_rejects_never_allow_tool_even_if_request_was_tampered(contract):
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["web.search"],
        permitted_destinations=[],
        reason="Need a search permit",
        requested_ttl=60,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )
    tampered = replace(request, permitted_tools=("shell.exec", "web.search"))

    with pytest.raises(PermitScopeError, match="never_allow_tools"):
        manager.approve_request(
            tampered,
            approved_by_hex64=_APPROVED_BY,
            granted_tools=["shell.exec"],
            approved_at=_dt(2026, 1, 1, 0, 1, 0),
        )


def test_approve_request_ttl_cannot_exceed_remaining_contract_lifetime(base_dict):
    payload = copy.deepcopy(base_dict)
    payload["expires_at"] = "2026-01-01T00:00:10Z"
    contract = Contract.from_dict(payload)
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["web.search"],
        permitted_destinations=[],
        reason="Need a short permit",
        requested_ttl=10,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )

    with pytest.raises(PermitTTLError, match="remaining contract lifetime"):
        manager.approve_request(
            request,
            approved_by_hex64=_APPROVED_BY,
            granted_ttl=3,
            approved_at=_dt(2026, 1, 1, 0, 0, 8),
        )


def test_validate_permit_accepts_valid_and_rejects_tampered_expired_and_mismatched(contract):
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["filesystem.write"],
        permitted_destinations=["api.example.com"],
        reason="Need write access",
        requested_ttl=120,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )
    permit = manager.approve_request(
        request,
        approved_by_hex64=_APPROVED_BY,
        approved_at=_dt(2026, 1, 1, 0, 5, 0),
    )

    valid = manager.validate_permit(
        permit,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    )
    assert valid.valid is True
    assert valid.reason == "valid"

    tampered = replace(permit, signature=base64.b64encode(b"tampered").decode("ascii"))
    assert manager.validate_permit(
        tampered,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    ) == manager.validate_permit(
        tampered,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    )
    assert manager.validate_permit(
        tampered,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    ).reason == "invalid_signature"
    assert manager.validate_permit(
        permit,
        current_time=_dt(2026, 1, 1, 0, 7, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    ).reason == "expired"
    assert manager.validate_permit(
        permit,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id="22222222-2222-2222-2222-222222222222",
        contract_hash=compute_contract_hash(contract),
        session_id=_SESSION_ID,
    ).reason == "contract_id_mismatch"
    assert manager.validate_permit(
        permit,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash="f" * 64,
        session_id=_SESSION_ID,
    ).reason == "contract_hash_mismatch"
    assert manager.validate_permit(
        permit,
        current_time=_dt(2026, 1, 1, 0, 5, 1),
        contract_id=contract.contract_id,
        contract_hash=compute_contract_hash(contract),
        session_id="22222222-2222-2222-2222-222222222222",
    ).reason == "session_id_mismatch"


def test_check_tool_against_permit_supports_egress_and_never_raises(contract):
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["filesystem.write"],
        permitted_destinations=["api.example.com"],
        reason="Need write access",
        requested_ttl=120,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )
    permit = manager.approve_request(
        request,
        approved_by_hex64=_APPROVED_BY,
        approved_at=_dt(2026, 1, 1, 0, 5, 0),
    )

    assert manager.check_tool_against_permit(
        permit,
        "filesystem.write",
        _dt(2026, 1, 1, 0, 5, 1),
        contract.contract_id,
        compute_contract_hash(contract),
        _SESSION_ID,
    )
    assert manager.check_tool_against_permit(
        permit,
        "filesystem.write",
        _dt(2026, 1, 1, 0, 5, 1),
        contract.contract_id,
        compute_contract_hash(contract),
        _SESSION_ID,
        egress_target="api.example.com",
    )
    assert not manager.check_tool_against_permit(
        permit,
        "filesystem.write",
        _dt(2026, 1, 1, 0, 5, 1),
        contract.contract_id,
        compute_contract_hash(contract),
        _SESSION_ID,
        egress_target=".trusted.example",
    )
    assert not manager.check_tool_against_permit(
        permit,
        "shell.exec",
        _dt(2026, 1, 1, 0, 5, 1),
        contract.contract_id,
        compute_contract_hash(contract),
        _SESSION_ID,
    )
    assert not manager.check_tool_against_permit(
        replace(permit, signature="not-base64-needed-for-bool-check"),
        "filesystem.write",
        _dt(2026, 1, 1, 0, 5, 1),
        contract.contract_id,
        compute_contract_hash(contract),
        _SESSION_ID,
    )


def test_build_usage_summary_counts_only_matching_exception_permit_events(contract):
    manager = _build_manager(contract)
    request = manager.create_request(
        requested_by_hex64=_REQUESTED_BY,
        permitted_tools=["filesystem.write", "web.search"],
        permitted_destinations=["api.example.com"],
        reason="Need a short permit",
        requested_ttl=120,
        session_id=_SESSION_ID,
        requested_at=_dt(2026, 1, 1),
    )
    permit = manager.approve_request(
        request,
        approved_by_hex64=_APPROVED_BY,
        approved_at=_dt(2026, 1, 1, 0, 5, 0),
    )

    events = [
        _event(
            contract,
            tool_name="filesystem.write",
            timestamp="2026-01-01T00:05:10Z",
            reason="exception_permit_active",
        ),
        _event(
            contract,
            tool_name="web.search",
            timestamp="2026-01-01T00:05:20Z",
            reason="exception_permit_active",
        ),
        _event(
            contract,
            tool_name="filesystem.write",
            timestamp="2026-01-01T00:05:30Z",
            reason="risk_class",
        ),
        _event(
            contract,
            tool_name="filesystem.write",
            timestamp="2026-01-01T00:07:01Z",
            reason="exception_permit_active",
        ),
    ]

    summary = manager.build_usage_summary(permit, events)

    assert summary.permit_id == permit.permit_id
    assert summary.total_matching_allows == 2
    assert summary.tools_used == {"filesystem.write": 1, "web.search": 1}
    assert summary.window_start == permit.approved_at
    assert summary.window_end == permit.expires_at
