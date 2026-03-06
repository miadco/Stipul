"""JIT permit creation, approval, and validation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from uuid import UUID, uuid4

from agentshield.contract.schema import Contract
from agentshield.contract.utils import compute_contract_hash
from agentshield.events.models import CanonicalEvent
from agentshield.utils.canonical import canonical_json_bytes

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PERMIT_SECRET_ENV = "AGENTSHIELD_PERMIT_SECRET"  # nosec B105


class PermitScopeError(Exception):
    """Raised when a permit request or approval widens scope."""


class PermitTTLError(Exception):
    """Raised when a permit TTL exceeds an allowed bound."""


@dataclass(frozen=True)
class ExceptionRequest:
    request_id: str
    requested_by: str
    requested_at: str
    contract_id: str
    contract_hash: str
    session_id: str
    permitted_tools: tuple[str, ...]
    permitted_destinations: tuple[str, ...]
    reason: str
    requested_ttl: int


@dataclass(frozen=True)
class ExceptionPermit:
    permit_id: str
    request_id: str
    approved_by: str
    approved_at: str
    contract_id: str
    contract_hash: str
    session_id: str
    granted_tools: tuple[str, ...]
    granted_destinations: tuple[str, ...]
    granted_ttl: int
    expires_at: str
    signature: str


@dataclass(frozen=True)
class PermitValidation:
    valid: bool
    reason: str | None


@dataclass(frozen=True)
class PermitUsageSummary:
    permit_id: str
    tools_used: dict[str, int]
    total_matching_allows: int
    window_start: str
    window_end: str


def _normalize_uuid(field: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUID string")
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"{field} must be a valid UUID string") from exc


def _normalize_hex64(field: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        raise ValueError(f"{field} must be a 64-character hexadecimal string")
    return value.lower()


def _normalize_reason(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("reason must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError("reason must not be empty")
    if len(normalized) > 500:
        raise ValueError("reason must be at most 500 characters")
    return normalized


def _normalize_positive_int(field: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _ensure_aware(field: str, value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError(f"{field} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _format_zulu(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_zulu(field: str, value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 UTC string")
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(iso_value)
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _normalize_items(field: str, values: Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        raise ValueError(f"{field} must be an iterable of strings, not a string")
    normalized: set[str] = set()
    for idx, value in enumerate(values):
        if not isinstance(value, str):
            raise ValueError(f"{field}[{idx}] must be a string")
        item = value.strip()
        if not item:
            raise ValueError(f"{field}[{idx}] must not be empty")
        normalized.add(item)
    return tuple(sorted(normalized))


def _permit_signature_payload(permit: ExceptionPermit) -> dict[str, Any]:
    return {
        "contract_id": permit.contract_id,
        "contract_hash": permit.contract_hash,
        "session_id": permit.session_id,
        "request_id": permit.request_id,
        "permit_id": permit.permit_id,
        "approved_by": permit.approved_by,
        "approved_at": permit.approved_at,
        "granted_tools": list(permit.granted_tools),
        "granted_destinations": list(permit.granted_destinations),
        "granted_ttl": permit.granted_ttl,
        "expires_at": permit.expires_at,
    }


def _sign_payload(payload: dict[str, Any], secret: bytes) -> str:
    digest = hmac.new(secret, canonical_json_bytes(payload), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def load_permit_secret() -> bytes:
    """Load the proxy-side permit validation secret from the environment."""
    secret = os.getenv(PERMIT_SECRET_ENV)
    if not secret:
        raise ValueError(f"Missing required environment variable: {PERMIT_SECRET_ENV}")
    return secret.encode("utf-8")


class PermitManager:
    """Manage request/approval flow for expiring JIT permits."""

    def __init__(self, contract: Contract, secret: bytes, session_id: str) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")
        self.contract = contract
        self.secret = secret
        self.session_id = _normalize_uuid("session_id", session_id)
        self.contract_hash = compute_contract_hash(contract)

    def create_request(
        self,
        requested_by_hex64: str,
        permitted_tools: Iterable[str],
        permitted_destinations: Iterable[str] | None,
        reason: str,
        requested_ttl: int,
        session_id: str,
        *,
        requested_at: datetime | None = None,
    ) -> ExceptionRequest:
        requested_by = _normalize_hex64("requested_by_hex64", requested_by_hex64)
        normalized_session_id = _normalize_uuid("session_id", session_id)
        if normalized_session_id != self.session_id:
            raise ValueError("session_id must match PermitManager session_id")

        tools = _normalize_items("permitted_tools", permitted_tools)
        if not tools:
            raise ValueError("permitted_tools must not be empty")
        for tool in tools:
            if tool in self.contract.never_allow_tools:
                raise ValueError(f"tool '{tool}' is in never_allow_tools and is not permit-eligible")
            if tool not in self.contract.allowed_tools and tool not in self.contract.tool_risk_classes:
                raise ValueError(f"tool '{tool}' is unknown to the contract")

        destinations = _normalize_items("permitted_destinations", permitted_destinations)
        normalized_reason = _normalize_reason(reason)
        ttl = _normalize_positive_int("requested_ttl", requested_ttl)
        requested_at_dt = _ensure_aware("requested_at", requested_at)

        return ExceptionRequest(
            request_id=str(uuid4()),
            requested_by=requested_by,
            requested_at=_format_zulu(requested_at_dt),
            contract_id=self.contract.contract_id,
            contract_hash=self.contract_hash,
            session_id=self.session_id,
            permitted_tools=tools,
            permitted_destinations=destinations,
            reason=normalized_reason,
            requested_ttl=ttl,
        )

    def approve_request(
        self,
        request: ExceptionRequest,
        approved_by_hex64: str,
        granted_tools: Iterable[str] | None = None,
        granted_destinations: Iterable[str] | None = None,
        granted_ttl: int | None = None,
        *,
        approved_at: datetime | None = None,
    ) -> ExceptionPermit:
        approved_by = _normalize_hex64("approved_by_hex64", approved_by_hex64)
        if request.contract_id != self.contract.contract_id:
            raise PermitScopeError("request contract_id does not match PermitManager contract")
        if request.contract_hash != self.contract_hash:
            raise PermitScopeError("request contract_hash does not match PermitManager contract")
        if request.session_id != self.session_id:
            raise PermitScopeError("request session_id does not match PermitManager session")

        tools = request.permitted_tools if granted_tools is None else _normalize_items(
            "granted_tools", granted_tools
        )
        destinations = (
            request.permitted_destinations
            if granted_destinations is None
            else _normalize_items("granted_destinations", granted_destinations)
        )
        ttl = request.requested_ttl if granted_ttl is None else _normalize_positive_int(
            "granted_ttl", granted_ttl
        )

        if not tools:
            raise PermitScopeError("granted_tools must not be empty")
        if not set(tools).issubset(request.permitted_tools):
            raise PermitScopeError("granted_tools must be a subset of requested tools")
        if not set(destinations).issubset(request.permitted_destinations):
            raise PermitScopeError(
                "granted_destinations must be a subset of requested destinations"
            )
        if ttl > request.requested_ttl:
            raise PermitTTLError("granted_ttl must not exceed requested_ttl")
        for tool in tools:
            if tool in self.contract.never_allow_tools:
                raise PermitScopeError(f"tool '{tool}' is in never_allow_tools")

        approved_at_dt = _ensure_aware("approved_at", approved_at)
        remaining = (self.contract.expires_at - approved_at_dt).total_seconds()
        if remaining <= 0:
            raise PermitTTLError("contract is already expired at approval time")
        if ttl > int(remaining):
            raise PermitTTLError("granted_ttl exceeds remaining contract lifetime")

        expires_at = approved_at_dt + timedelta(seconds=ttl)
        unsigned_permit = ExceptionPermit(
            permit_id=str(uuid4()),
            request_id=request.request_id,
            approved_by=approved_by,
            approved_at=_format_zulu(approved_at_dt),
            contract_id=self.contract.contract_id,
            contract_hash=self.contract_hash,
            session_id=self.session_id,
            granted_tools=tuple(sorted(set(tools))),
            granted_destinations=tuple(sorted(set(destinations))),
            granted_ttl=ttl,
            expires_at=_format_zulu(expires_at),
            signature="",
        )
        signature = _sign_payload(_permit_signature_payload(unsigned_permit), self.secret)
        return ExceptionPermit(
            permit_id=unsigned_permit.permit_id,
            request_id=unsigned_permit.request_id,
            approved_by=unsigned_permit.approved_by,
            approved_at=unsigned_permit.approved_at,
            contract_id=unsigned_permit.contract_id,
            contract_hash=unsigned_permit.contract_hash,
            session_id=unsigned_permit.session_id,
            granted_tools=unsigned_permit.granted_tools,
            granted_destinations=unsigned_permit.granted_destinations,
            granted_ttl=unsigned_permit.granted_ttl,
            expires_at=unsigned_permit.expires_at,
            signature=signature,
        )

    def validate_permit(
        self,
        permit: ExceptionPermit,
        current_time: datetime,
        contract_id: str,
        contract_hash: str,
        session_id: str,
    ) -> PermitValidation:
        current_time_dt = _ensure_aware("current_time", current_time)
        expected_payload = _permit_signature_payload(permit)
        expected_signature = _sign_payload(expected_payload, self.secret)
        if not hmac.compare_digest(permit.signature, expected_signature):
            return PermitValidation(valid=False, reason="invalid_signature")

        if current_time_dt >= _parse_zulu("expires_at", permit.expires_at):
            return PermitValidation(valid=False, reason="expired")

        normalized_contract_id = _normalize_uuid("contract_id", contract_id)
        if normalized_contract_id != permit.contract_id:
            return PermitValidation(valid=False, reason="contract_id_mismatch")

        normalized_contract_hash = _normalize_hex64("contract_hash", contract_hash)
        if normalized_contract_hash != permit.contract_hash:
            return PermitValidation(valid=False, reason="contract_hash_mismatch")

        normalized_session_id = _normalize_uuid("session_id", session_id)
        if normalized_session_id != permit.session_id:
            return PermitValidation(valid=False, reason="session_id_mismatch")

        return PermitValidation(valid=True, reason="valid")

    def check_tool_against_permit(
        self,
        permit: ExceptionPermit,
        tool_name: str,
        current_time: datetime,
        contract_id: str,
        contract_hash: str,
        session_id: str,
        *,
        egress_target: str | None = None,
    ) -> bool:
        try:
            if not isinstance(tool_name, str) or not tool_name:
                return False
            if tool_name in self.contract.never_allow_tools:
                return False
            validation = self.validate_permit(
                permit,
                current_time=current_time,
                contract_id=contract_id,
                contract_hash=contract_hash,
                session_id=session_id,
            )
            if not validation.valid:
                return False
            if tool_name not in permit.granted_tools:
                return False
            if egress_target is not None:
                if not permit.granted_destinations:
                    return False
                return egress_target in permit.granted_destinations
            return True
        except Exception:
            return False

    def build_usage_summary(
        self,
        permit: ExceptionPermit,
        events: list[CanonicalEvent],
    ) -> PermitUsageSummary:
        window_start = _parse_zulu("approved_at", permit.approved_at)
        window_end = _parse_zulu("expires_at", permit.expires_at)
        tools_used: dict[str, int] = {}
        total = 0

        for event in events:
            event_time = _parse_zulu("timestamp", event.timestamp)
            if not (window_start <= event_time < window_end):
                continue
            if event.event_type != "tool_call":
                continue
            if event.decision != "allow":
                continue
            if event.reason != "exception_permit_active":
                continue
            if event.tool_name not in permit.granted_tools:
                continue
            tools_used[event.tool_name] = tools_used.get(event.tool_name, 0) + 1
            total += 1

        return PermitUsageSummary(
            permit_id=permit.permit_id,
            tools_used=tools_used,
            total_matching_allows=total,
            window_start=permit.approved_at,
            window_end=permit.expires_at,
        )


__all__ = [
    "ExceptionPermit",
    "ExceptionRequest",
    "PERMIT_SECRET_ENV",
    "PermitManager",
    "PermitScopeError",
    "PermitTTLError",
    "PermitUsageSummary",
    "PermitValidation",
    "load_permit_secret",
]
