"""Session head sidecar for O(1) restart chain continuity."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentshield.utils.canonical import canonical_json_bytes, compute_prev_hash

_LOGGER = logging.getLogger(__name__)
_SESSION_HEAD_FILENAME = "session_head.json"


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_session_head(state_dir: Path, event: dict[str, Any]) -> None:
    """Atomically persist the last written event hash and sequence metadata."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    path = Path(state_dir) / _SESSION_HEAD_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{_SESSION_HEAD_FILENAME}.tmp"

    payload = {
        "session_id": event.get("session_id"),
        "sequence_id": event.get("sequence_id"),
        "event_hash": compute_prev_hash(event),
        "written_at": _now_iso_utc(),
    }
    tmp_path.write_bytes(canonical_json_bytes(payload) + b"\n")
    os.replace(tmp_path, path)


def read_session_head(state_dir: Path) -> dict[str, Any] | None:
    """Return parsed session head payload, or None when absent/invalid."""
    path = Path(state_dir) / _SESSION_HEAD_FILENAME
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _LOGGER.warning("Malformed session_head.json; starting fresh chain.")
        return None

    if not isinstance(payload, dict):
        _LOGGER.warning("Malformed session_head.json; starting fresh chain.")
        return None

    session_id = payload.get("session_id")
    sequence_id = payload.get("sequence_id")
    event_hash = payload.get("event_hash")
    written_at = payload.get("written_at")
    if (
        not isinstance(session_id, str)
        or not session_id
        or isinstance(sequence_id, bool)
        or not isinstance(sequence_id, int)
        or sequence_id <= 0
        or not isinstance(event_hash, str)
        or len(event_hash) != 64
        or any(ch not in "0123456789abcdefABCDEF" for ch in event_hash)
        or not isinstance(written_at, str)
        or not written_at
    ):
        _LOGGER.warning("Malformed session_head.json; starting fresh chain.")
        return None

    return payload
