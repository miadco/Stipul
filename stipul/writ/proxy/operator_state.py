"""Persistence for operator-controlled proxy state."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from stipul.utils.canonical import canonical_json_bytes

_OPERATOR_STATE_FILENAME = "operator_state.json"


class OperatorStateError(RuntimeError):
    """Raised when operator_state.json is missing required fields or malformed."""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
class OperatorState:
    kill_switch_active: bool
    updated_at: str
    updated_by: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kill_switch_active": self.kill_switch_active,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "reason": self.reason,
        }


def _validate_state_fields(payload: object) -> OperatorState:
    if not isinstance(payload, dict):
        raise OperatorStateError("operator_state.json must contain a JSON object")

    kill_switch_active = payload.get("kill_switch_active")
    updated_at = payload.get("updated_at")
    updated_by = payload.get("updated_by")
    reason = payload.get("reason")

    if not isinstance(kill_switch_active, bool):
        raise OperatorStateError("operator_state.json missing valid kill_switch_active")
    if not isinstance(updated_at, str) or not _is_utc_timestamp(updated_at):
        raise OperatorStateError("operator_state.json missing valid updated_at")
    if not isinstance(updated_by, str) or not updated_by:
        raise OperatorStateError("operator_state.json missing valid updated_by")
    if not isinstance(reason, str) or not reason:
        raise OperatorStateError("operator_state.json missing valid reason")

    return OperatorState(
        kill_switch_active=kill_switch_active,
        updated_at=updated_at,
        updated_by=updated_by,
        reason=reason,
    )


def save_operator_state(
    state_dir: Path,
    *,
    kill_switch_active: bool,
    updated_by: str,
    reason: str,
) -> OperatorState:
    if not isinstance(kill_switch_active, bool):
        raise TypeError("kill_switch_active must be a bool")
    if not isinstance(updated_by, str) or not updated_by:
        raise ValueError("updated_by must be a non-empty string")
    if not isinstance(reason, str) or not reason:
        raise ValueError("reason must be a non-empty string")

    state = OperatorState(
        kill_switch_active=kill_switch_active,
        updated_at=_utcnow_iso(),
        updated_by=updated_by,
        reason=reason,
    )
    path = Path(state_dir) / _OPERATOR_STATE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{_OPERATOR_STATE_FILENAME}.tmp"
    tmp_path.write_bytes(canonical_json_bytes(state.to_dict()) + b"\n")
    os.replace(tmp_path, path)
    return state


def load_operator_state(state_dir: Path) -> OperatorState | None:
    path = Path(state_dir) / _OPERATOR_STATE_FILENAME
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise OperatorStateError("operator_state.json is malformed JSON") from exc

    return _validate_state_fields(payload)
