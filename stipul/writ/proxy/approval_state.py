"""Atomic persistence for quorum approval requests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from stipul.utils.canonical import canonical_json_bytes

_APPROVAL_STATE_FILENAME = "approval_state.json"
_ALLOWED_STATUSES = {"pending", "approved", "expired"}


class ApprovalStateError(RuntimeError):
    """Raised when approval_state.json is missing required fields or malformed."""


def _is_utc_timestamp(value: str) -> bool:
    if not isinstance(value, str) or "T" not in value:
        return False
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return False
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


@dataclass(frozen=True)
class ApprovalRecord:
    approved_by: str
    approved_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
        }


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    status: str
    tool_name: str
    input_hash: str
    egress_target: str | None
    requesting_agent_id: str
    session_id: str
    contract_id: str
    contract_hash: str
    required_approver_count: int
    approvals: tuple[ApprovalRecord, ...]
    expires_at: str
    derived_permit: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "status": self.status,
            "tool_name": self.tool_name,
            "input_hash": self.input_hash,
            "egress_target": self.egress_target,
            "requesting_agent_id": self.requesting_agent_id,
            "session_id": self.session_id,
            "contract_id": self.contract_id,
            "contract_hash": self.contract_hash,
            "required_approver_count": self.required_approver_count,
            "approvals": [approval.to_dict() for approval in self.approvals],
            "expires_at": self.expires_at,
            "derived_permit": self.derived_permit,
        }
        return payload


@dataclass(frozen=True)
class ApprovalState:
    requests: dict[str, ApprovalRequest]

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": {
                request_id: request.to_dict()
                for request_id, request in sorted(self.requests.items())
            }
        }


def _validate_approval_record(payload: object) -> ApprovalRecord:
    if not isinstance(payload, dict):
        raise ApprovalStateError("approval_state.json approval record must be an object")
    approved_by = payload.get("approved_by")
    approved_at = payload.get("approved_at")
    if not isinstance(approved_by, str) or not approved_by:
        raise ApprovalStateError("approval_state.json missing valid approved_by")
    if not isinstance(approved_at, str) or not _is_utc_timestamp(approved_at):
        raise ApprovalStateError("approval_state.json missing valid approved_at")
    return ApprovalRecord(
        approved_by=approved_by,
        approved_at=approved_at,
    )


def _validate_approval_request(payload: object) -> ApprovalRequest:
    if not isinstance(payload, dict):
        raise ApprovalStateError("approval_state.json request entry must be an object")

    request_id = payload.get("request_id")
    status = payload.get("status")
    tool_name = payload.get("tool_name")
    input_hash = payload.get("input_hash")
    egress_target = payload.get("egress_target")
    requesting_agent_id = payload.get("requesting_agent_id")
    session_id = payload.get("session_id")
    contract_id = payload.get("contract_id")
    contract_hash = payload.get("contract_hash")
    required_approver_count = payload.get("required_approver_count")
    approvals_payload = payload.get("approvals")
    expires_at = payload.get("expires_at")
    derived_permit = payload.get("derived_permit")

    if not isinstance(request_id, str) or not request_id:
        raise ApprovalStateError("approval_state.json missing valid request_id")
    if status not in _ALLOWED_STATUSES:
        raise ApprovalStateError("approval_state.json missing valid status")
    if not isinstance(tool_name, str) or not tool_name:
        raise ApprovalStateError("approval_state.json missing valid tool_name")
    if not isinstance(input_hash, str) or not input_hash:
        raise ApprovalStateError("approval_state.json missing valid input_hash")
    if egress_target is not None and (not isinstance(egress_target, str) or not egress_target):
        raise ApprovalStateError("approval_state.json has invalid egress_target")
    if not isinstance(requesting_agent_id, str) or not requesting_agent_id:
        raise ApprovalStateError("approval_state.json missing valid requesting_agent_id")
    if not isinstance(session_id, str) or not session_id:
        raise ApprovalStateError("approval_state.json missing valid session_id")
    if not isinstance(contract_id, str) or not contract_id:
        raise ApprovalStateError("approval_state.json missing valid contract_id")
    if not isinstance(contract_hash, str) or not contract_hash:
        raise ApprovalStateError("approval_state.json missing valid contract_hash")
    if (
        isinstance(required_approver_count, bool)
        or not isinstance(required_approver_count, int)
        or required_approver_count <= 0
    ):
        raise ApprovalStateError("approval_state.json missing valid required_approver_count")
    if not isinstance(approvals_payload, list):
        raise ApprovalStateError("approval_state.json missing valid approvals")
    if not isinstance(expires_at, str) or not _is_utc_timestamp(expires_at):
        raise ApprovalStateError("approval_state.json missing valid expires_at")
    if derived_permit is not None and not isinstance(derived_permit, dict):
        raise ApprovalStateError("approval_state.json has invalid derived_permit")

    approvals = tuple(_validate_approval_record(item) for item in approvals_payload)
    return ApprovalRequest(
        request_id=request_id,
        status=status,
        tool_name=tool_name,
        input_hash=input_hash,
        egress_target=egress_target,
        requesting_agent_id=requesting_agent_id,
        session_id=session_id,
        contract_id=contract_id,
        contract_hash=contract_hash,
        required_approver_count=required_approver_count,
        approvals=approvals,
        expires_at=expires_at,
        derived_permit=dict(derived_permit) if derived_permit is not None else None,
    )


def _validate_state_fields(payload: object) -> ApprovalState:
    if not isinstance(payload, dict):
        raise ApprovalStateError("approval_state.json must contain a JSON object")

    requests_payload = payload.get("requests", {})
    if not isinstance(requests_payload, dict):
        raise ApprovalStateError("approval_state.json requests must be an object")

    requests: dict[str, ApprovalRequest] = {}
    for request_id, request_payload in requests_payload.items():
        if not isinstance(request_id, str) or not request_id:
            raise ApprovalStateError("approval_state.json request keys must be non-empty strings")
        request = _validate_approval_request(request_payload)
        if request.request_id != request_id:
            raise ApprovalStateError("approval_state.json request key mismatch")
        requests[request_id] = request

    return ApprovalState(requests=requests)


def save_approval_state(state_dir: Path, state: ApprovalState) -> ApprovalState:
    if not isinstance(state, ApprovalState):
        raise TypeError("state must be ApprovalState")

    path = Path(state_dir) / _APPROVAL_STATE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{_APPROVAL_STATE_FILENAME}.tmp"
    tmp_path.write_bytes(canonical_json_bytes(state.to_dict()) + b"\n")
    os.replace(tmp_path, path)
    return state


def load_approval_state(state_dir: Path) -> ApprovalState:
    path = Path(state_dir) / _APPROVAL_STATE_FILENAME
    if not path.exists():
        return ApprovalState(requests={})

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ApprovalStateError("approval_state.json is malformed JSON") from exc

    return _validate_state_fields(payload)


__all__ = [
    "ApprovalRecord",
    "ApprovalRequest",
    "ApprovalState",
    "ApprovalStateError",
    "load_approval_state",
    "save_approval_state",
]
