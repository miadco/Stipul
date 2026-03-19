"""Signed delegation-chain primitives for proxy-side validation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping
from uuid import UUID

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.charter.permits import load_permit_secret
from stipul.utils.canonical import canonical_json_bytes

DEFAULT_MAX_DELEGATION_CHAIN_DEPTH = 3

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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


def _normalize_actor(field: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > 500:
        raise ValueError(f"{field} must be at most 500 characters")
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


def _normalize_items(field: str, values: Iterable[str] | None, *, allow_empty: bool) -> tuple[str, ...]:
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
    if not allow_empty and not normalized:
        raise ValueError(f"{field} must not be empty")
    return tuple(sorted(normalized))


def _is_base64(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return False
    return True


def _signature_payload(grant: "DelegationGrant") -> dict[str, Any]:
    return {
        "parent_actor": grant.parent_actor,
        "delegated_actor": grant.delegated_actor,
        "issued_at": grant.issued_at,
        "expires_at": grant.expires_at,
        "contract_id": grant.contract_id,
        "contract_hash": grant.contract_hash,
        "session_id": grant.session_id,
        "scope_tools": list(grant.scope_tools),
        "scope_destinations": list(grant.scope_destinations),
    }


def _sign_payload(payload: dict[str, Any], secret: bytes) -> str:
    digest = hmac.new(secret, canonical_json_bytes(payload), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


@dataclass(frozen=True)
class DelegationGrant:
    parent_actor: str
    delegated_actor: str
    issued_at: str
    expires_at: str
    contract_id: str
    contract_hash: str
    session_id: str
    scope_tools: tuple[str, ...]
    scope_destinations: tuple[str, ...]
    signature: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DelegationGrant":
        if not isinstance(payload, Mapping):
            raise ValueError("delegation grant must be an object")
        parent_actor = _normalize_actor("parent_actor", payload.get("parent_actor"))
        delegated_actor = _normalize_actor("delegated_actor", payload.get("delegated_actor"))
        issued_at = _format_zulu(_parse_zulu("issued_at", payload.get("issued_at")))
        expires_at = _format_zulu(_parse_zulu("expires_at", payload.get("expires_at")))
        contract_id = _normalize_uuid("contract_id", payload.get("contract_id"))
        contract_hash = _normalize_hex64("contract_hash", payload.get("contract_hash"))
        session_id = _normalize_uuid("session_id", payload.get("session_id"))
        scope_tools = _normalize_items("scope_tools", payload.get("scope_tools"), allow_empty=False)
        scope_destinations = _normalize_items(
            "scope_destinations",
            payload.get("scope_destinations"),
            allow_empty=True,
        )
        signature = payload.get("signature")
        if not _is_base64(signature):
            raise ValueError("signature must be valid base64")
        return cls(
            parent_actor=parent_actor,
            delegated_actor=delegated_actor,
            issued_at=issued_at,
            expires_at=expires_at,
            contract_id=contract_id,
            contract_hash=contract_hash,
            session_id=session_id,
            scope_tools=scope_tools,
            scope_destinations=scope_destinations,
            signature=signature,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_actor": self.parent_actor,
            "delegated_actor": self.delegated_actor,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "contract_id": self.contract_id,
            "contract_hash": self.contract_hash,
            "session_id": self.session_id,
            "scope_tools": list(self.scope_tools),
            "scope_destinations": list(self.scope_destinations),
            "signature": self.signature,
        }


@dataclass(frozen=True)
class DelegationValidation:
    valid: bool
    reason: str
    chain_depth: int
    parent_actor: str | None
    delegated_actor: str | None
    expires_at: str | None
    scope_tools: tuple[str, ...]
    scope_destinations: tuple[str, ...]

    def as_metadata(self) -> dict[str, Any]:
        context: dict[str, Any] = {
            "chain_depth": self.chain_depth,
            "scope_tools": list(self.scope_tools),
            "scope_destinations": list(self.scope_destinations),
            "validation_reason": self.reason,
        }
        if self.parent_actor is not None:
            context["parent_actor"] = self.parent_actor
        if self.delegated_actor is not None:
            context["delegated_actor"] = self.delegated_actor
        if self.expires_at is not None:
            context["expires_at"] = self.expires_at
        return {"delegation_context": context}


class DelegationManager:
    """Create and validate contract-bound delegation chains."""

    def __init__(
        self,
        contract: Contract,
        secret: bytes,
        session_id: str,
        *,
        max_chain_depth: int = DEFAULT_MAX_DELEGATION_CHAIN_DEPTH,
    ) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")
        self.contract = contract
        self.secret = secret
        self.session_id = _normalize_uuid("session_id", session_id)
        self.contract_hash = compute_contract_hash(contract)
        self.max_chain_depth = _normalize_positive_int("max_chain_depth", max_chain_depth)

    @classmethod
    def from_env(
        cls,
        contract: Contract,
        session_id: str,
        *,
        max_chain_depth: int = DEFAULT_MAX_DELEGATION_CHAIN_DEPTH,
    ) -> "DelegationManager":
        return cls(
            contract=contract,
            secret=load_permit_secret(),
            session_id=session_id,
            max_chain_depth=max_chain_depth,
        )

    def create_grant(
        self,
        *,
        parent_actor: str,
        delegated_actor: str,
        scope_tools: Iterable[str],
        scope_destinations: Iterable[str] | None,
        ttl: int,
        session_id: str,
        issued_at: datetime | None = None,
    ) -> DelegationGrant:
        normalized_parent = _normalize_actor("parent_actor", parent_actor)
        normalized_delegated = _normalize_actor("delegated_actor", delegated_actor)
        normalized_session_id = _normalize_uuid("session_id", session_id)
        if normalized_session_id != self.session_id:
            raise ValueError("session_id must match DelegationManager session_id")

        tools = _normalize_items("scope_tools", scope_tools, allow_empty=False)
        for tool in tools:
            if tool in self.contract.never_allow_tools:
                raise ValueError(f"tool '{tool}' is in never_allow_tools and is not delegatable")
            if tool not in self.contract.allowed_tools and tool not in self.contract.tool_risk_classes:
                raise ValueError(f"tool '{tool}' is unknown to the contract")

        destinations = _normalize_items("scope_destinations", scope_destinations, allow_empty=True)
        normalized_ttl = _normalize_positive_int("ttl", ttl)
        issued_at_dt = _ensure_aware("issued_at", issued_at)
        remaining = (self.contract.expires_at - issued_at_dt).total_seconds()
        if remaining <= 0:
            raise ValueError("contract is already expired at delegation time")
        if normalized_ttl > int(remaining):
            raise ValueError("ttl exceeds remaining contract lifetime")

        unsigned = DelegationGrant(
            parent_actor=normalized_parent,
            delegated_actor=normalized_delegated,
            issued_at=_format_zulu(issued_at_dt),
            expires_at=_format_zulu(issued_at_dt + timedelta(seconds=normalized_ttl)),
            contract_id=self.contract.contract_id,
            contract_hash=self.contract_hash,
            session_id=self.session_id,
            scope_tools=tools,
            scope_destinations=destinations,
            signature="",
        )
        signature = _sign_payload(_signature_payload(unsigned), self.secret)
        return DelegationGrant(
            parent_actor=unsigned.parent_actor,
            delegated_actor=unsigned.delegated_actor,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            contract_id=unsigned.contract_id,
            contract_hash=unsigned.contract_hash,
            session_id=unsigned.session_id,
            scope_tools=unsigned.scope_tools,
            scope_destinations=unsigned.scope_destinations,
            signature=signature,
        )

    def validate_chain(
        self,
        chain: Iterable[DelegationGrant | Mapping[str, Any]],
        *,
        current_time: datetime,
        contract_id: str,
        contract_hash: str,
        session_id: str,
        expected_delegated_actor: str,
        tool_name: str,
        egress_target: str | None = None,
    ) -> DelegationValidation:
        current_time_dt = _ensure_aware("current_time", current_time)
        expected_contract_id = _normalize_uuid("contract_id", contract_id)
        expected_contract_hash = _normalize_hex64("contract_hash", contract_hash)
        expected_session_id = _normalize_uuid("session_id", session_id)
        expected_actor = _normalize_actor("expected_delegated_actor", expected_delegated_actor)

        try:
            normalized_chain = self._normalize_chain(chain)
        except ValueError:
            return DelegationValidation(
                valid=False,
                reason="delegation_malformed",
                chain_depth=0,
                parent_actor=None,
                delegated_actor=expected_actor,
                expires_at=None,
                scope_tools=(),
                scope_destinations=(),
            )

        depth = len(normalized_chain)
        if depth == 0:
            return DelegationValidation(
                valid=False,
                reason="delegation_malformed",
                chain_depth=0,
                parent_actor=None,
                delegated_actor=expected_actor,
                expires_at=None,
                scope_tools=(),
                scope_destinations=(),
            )
        if depth > self.max_chain_depth:
            root = normalized_chain[0].parent_actor
            leaf = normalized_chain[-1].delegated_actor
            return DelegationValidation(
                valid=False,
                reason="delegation_depth_exceeded",
                chain_depth=depth,
                parent_actor=root,
                delegated_actor=leaf,
                expires_at=normalized_chain[-1].expires_at,
                scope_tools=normalized_chain[-1].scope_tools,
                scope_destinations=normalized_chain[-1].scope_destinations,
            )

        current_parent = self.contract.identity_agent_id
        effective_tools: set[str] | None = None
        effective_destinations: set[str] | None = None
        earliest_expiry: datetime | None = None

        for grant in normalized_chain:
            if not self._signature_valid(grant):
                return DelegationValidation(
                    valid=False,
                    reason="delegation_invalid_signature",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )
            if grant.contract_id != expected_contract_id or grant.contract_hash != expected_contract_hash:
                return DelegationValidation(
                    valid=False,
                    reason="delegation_contract_mismatch",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )
            if grant.session_id != expected_session_id:
                return DelegationValidation(
                    valid=False,
                    reason="delegation_session_mismatch",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )
            if grant.parent_actor != current_parent:
                return DelegationValidation(
                    valid=False,
                    reason="delegation_chain_invalid",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )

            expires_at_dt = _parse_zulu("expires_at", grant.expires_at)
            if current_time_dt >= expires_at_dt:
                return DelegationValidation(
                    valid=False,
                    reason="delegation_expired",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )

            if tool_name not in grant.scope_tools:
                return DelegationValidation(
                    valid=False,
                    reason="delegation_scope_mismatch",
                    chain_depth=depth,
                    parent_actor=normalized_chain[0].parent_actor,
                    delegated_actor=grant.delegated_actor,
                    expires_at=grant.expires_at,
                    scope_tools=grant.scope_tools,
                    scope_destinations=grant.scope_destinations,
                )
            if egress_target is not None:
                if not grant.scope_destinations or egress_target not in grant.scope_destinations:
                    return DelegationValidation(
                        valid=False,
                        reason="delegation_scope_mismatch",
                        chain_depth=depth,
                        parent_actor=normalized_chain[0].parent_actor,
                        delegated_actor=grant.delegated_actor,
                        expires_at=grant.expires_at,
                        scope_tools=grant.scope_tools,
                        scope_destinations=grant.scope_destinations,
                    )

            current_parent = grant.delegated_actor
            effective_tools = set(grant.scope_tools) if effective_tools is None else effective_tools.intersection(
                grant.scope_tools
            )
            if grant.scope_destinations:
                if effective_destinations is None:
                    effective_destinations = set(grant.scope_destinations)
                else:
                    effective_destinations = effective_destinations.intersection(grant.scope_destinations)
            elif effective_destinations is None:
                effective_destinations = set()
            earliest_expiry = expires_at_dt if earliest_expiry is None else min(earliest_expiry, expires_at_dt)

        if normalized_chain[-1].delegated_actor != expected_actor:
            return DelegationValidation(
                valid=False,
                reason="delegation_actor_mismatch",
                chain_depth=depth,
                parent_actor=normalized_chain[0].parent_actor,
                delegated_actor=normalized_chain[-1].delegated_actor,
                expires_at=normalized_chain[-1].expires_at,
                scope_tools=tuple(sorted(effective_tools or ())),
                scope_destinations=tuple(sorted(effective_destinations or ())),
            )

        return DelegationValidation(
            valid=True,
            reason="valid",
            chain_depth=depth,
            parent_actor=normalized_chain[0].parent_actor,
            delegated_actor=normalized_chain[-1].delegated_actor,
            expires_at=_format_zulu(earliest_expiry) if earliest_expiry is not None else None,
            scope_tools=tuple(sorted(effective_tools or ())),
            scope_destinations=tuple(sorted(effective_destinations or ())),
        )

    @staticmethod
    def _normalize_chain(
        chain: Iterable[DelegationGrant | Mapping[str, Any]],
    ) -> list[DelegationGrant]:
        if isinstance(chain, (str, bytes, Mapping)):
            raise ValueError("delegation_chain must be a list")
        normalized: list[DelegationGrant] = []
        for item in chain:
            if isinstance(item, DelegationGrant):
                normalized.append(item)
                continue
            normalized.append(DelegationGrant.from_dict(item))
        return normalized

    def _signature_valid(self, grant: DelegationGrant) -> bool:
        expected_signature = _sign_payload(_signature_payload(grant), self.secret)
        return hmac.compare_digest(grant.signature, expected_signature)


__all__ = [
    "DEFAULT_MAX_DELEGATION_CHAIN_DEPTH",
    "DelegationGrant",
    "DelegationManager",
    "DelegationValidation",
]
