"""Canonical event types for the Event Stream."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

_ALLOWED_EVENT_TYPES = {
    "tool_call",
    "net_call",
    "write_op",
    "elev_op",
    "budget_exhausted",
    "budget_anomaly",
}
_ALLOWED_RISK_CLASSES = {"read", "write", "irreversible", "exfil-risk"}
_ALLOWED_DECISIONS = {"allow", "deny", "require_approval"}
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX8_RE = re.compile(r"^[0-9a-fA-F]{8}$")


def _is_utc_timestamp(value: str) -> bool:
    if "T" not in value:
        return False
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return False
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


@dataclass
class CanonicalEvent:
    sequence_id: int
    timestamp: str
    session_id: str
    event_type: str
    tool_name: str
    risk_class: str
    decision: str
    reason: str
    contract_id: str
    contract_hash: str
    agent_identity: str
    input_hash: str
    key_id: str
    algorithm: str
    key_created_at: str
    prev_hash: str
    signature: str
    prev_unsigned_terminal_hash: str | None = None
    prev_chain_terminal_hash: str | None = None
    prev_session_id: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.sequence_id, bool) or not isinstance(self.sequence_id, int):
            raise ValueError("sequence_id must be an integer")
        if self.sequence_id <= 0:
            raise ValueError("sequence_id must be > 0")

        if not isinstance(self.timestamp, str) or not _is_utc_timestamp(self.timestamp):
            raise ValueError("timestamp must be ISO 8601 UTC")
        if not isinstance(self.key_created_at, str) or not _is_utc_timestamp(self.key_created_at):
            raise ValueError("key_created_at must be ISO 8601 UTC")

        if self.event_type not in _ALLOWED_EVENT_TYPES:
            raise ValueError(f"invalid event_type '{self.event_type}'")
        if self.risk_class not in _ALLOWED_RISK_CLASSES:
            raise ValueError(f"invalid risk_class '{self.risk_class}'")
        if self.decision not in _ALLOWED_DECISIONS:
            raise ValueError(f"invalid decision '{self.decision}'")

        if not isinstance(self.tool_name, str) or not self.tool_name:
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("reason must be a non-empty string")

        try:
            UUID(self.session_id)
        except Exception as exc:
            raise ValueError("session_id must be a UUID") from exc

        try:
            UUID(self.contract_id)
        except Exception as exc:
            raise ValueError("contract_id must be a UUID") from exc

        if not _HEX64_RE.fullmatch(self.contract_hash):
            raise ValueError("contract_hash must be 64-char hex SHA-256")
        if not _HEX64_RE.fullmatch(self.agent_identity):
            raise ValueError("agent_identity must be 64-char hex hash")
        if not _HEX64_RE.fullmatch(self.input_hash):
            raise ValueError("input_hash must be 64-char hex SHA-256")
        if not _HEX8_RE.fullmatch(self.key_id):
            raise ValueError("key_id must be 8-char hex")
        if self.algorithm != "ed25519":
            raise ValueError("algorithm must be 'ed25519'")
        if not _HEX64_RE.fullmatch(self.prev_hash):
            raise ValueError("prev_hash must be 64-char hex SHA-256")

        if not isinstance(self.signature, str) or not self.signature:
            raise ValueError("signature must be a non-empty base64 string")
        try:
            base64.b64decode(self.signature.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError("signature must be valid base64") from exc

        if self.prev_unsigned_terminal_hash is not None and not _HEX64_RE.fullmatch(
            self.prev_unsigned_terminal_hash
        ):
            raise ValueError("prev_unsigned_terminal_hash must be 64-char hex SHA-256")

        chain_hash_present = self.prev_chain_terminal_hash is not None
        chain_session_present = self.prev_session_id is not None
        if chain_hash_present != chain_session_present:
            raise ValueError(
                "prev_chain_terminal_hash and prev_session_id must be present together or absent together"
            )
        if self.prev_chain_terminal_hash is not None and not _HEX64_RE.fullmatch(
            self.prev_chain_terminal_hash
        ):
            raise ValueError("prev_chain_terminal_hash must be 64-char hex SHA-256")
        if self.prev_session_id is not None:
            try:
                UUID(self.prev_session_id)
            except Exception as exc:
                raise ValueError("prev_session_id must be a UUID") from exc
        if self.metadata is not None and not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dictionary when present")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "sequence_id": self.sequence_id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "risk_class": self.risk_class,
            "decision": self.decision,
            "reason": self.reason,
            "contract_id": self.contract_id,
            "contract_hash": self.contract_hash,
            "agent_identity": self.agent_identity,
            "input_hash": self.input_hash,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "key_created_at": self.key_created_at,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
        }
        if self.prev_unsigned_terminal_hash is not None:
            payload["prev_unsigned_terminal_hash"] = self.prev_unsigned_terminal_hash
        if self.prev_chain_terminal_hash is not None:
            payload["prev_chain_terminal_hash"] = self.prev_chain_terminal_hash
        if self.prev_session_id is not None:
            payload["prev_session_id"] = self.prev_session_id
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        return {key: payload[key] for key in sorted(payload)}
