"""Session Seal builder for authoritative Chronicle evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

SEAL_FILENAME = "seal.json"
_SEAL_KIND = "session_seal"
_SEAL_VERSION = 1


def seal_path(session_dir: str | Path) -> Path:
    return Path(session_dir) / SEAL_FILENAME


def build_session_seal(
    attestation: dict[str, Any],
    events_path: str | Path,
) -> dict[str, Any]:
    """Build a deterministic Seal payload bound to authoritative Chronicle evidence."""
    if not isinstance(attestation, dict):
        raise TypeError("attestation must be a dictionary")

    resolved_events_path = Path(events_path)
    if not resolved_events_path.exists():
        raise FileNotFoundError(f"authoritative events file not found: {resolved_events_path}")

    session_id = _required_non_empty_str(attestation, "session_id")
    contract_id = _required_non_empty_str(attestation, "contract_id")
    contract_hash = _required_lower_hex(attestation, "contract_hash", length=64)
    terminal_event_hash = _required_lower_hex(attestation, "event_hash", length=64)
    terminal_sequence_id = _required_positive_int(attestation, "sequence_id")
    terminal_timestamp = _required_non_empty_str(attestation, "timestamp")
    key_id = _required_lower_hex(attestation, "key_id", length=8)
    algorithm = _required_non_empty_str(attestation, "algorithm")
    key_created_at = _required_non_empty_str(attestation, "key_created_at")

    return {
        "algorithm": algorithm,
        "contract_hash": contract_hash,
        "contract_id": contract_id,
        "events_sha256": hashlib.sha256(resolved_events_path.read_bytes()).hexdigest(),
        "key_created_at": key_created_at,
        "key_id": key_id,
        "kind": _SEAL_KIND,
        "session_id": session_id,
        "terminal_event_hash": terminal_event_hash,
        "terminal_sequence_id": terminal_sequence_id,
        "terminal_timestamp": terminal_timestamp,
        "version": _SEAL_VERSION,
    }


def write_seal(path: str | Path, seal: dict[str, Any]) -> None:
    if not isinstance(seal, dict):
        raise TypeError("seal must be a dictionary")

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.parent / f"{output_path.name}.tmp"
    payload = json.dumps(seal, indent=2, sort_keys=True)
    tmp_path.write_text(f"{payload}\n", encoding="utf-8")
    os.replace(tmp_path, output_path)


def _required_non_empty_str(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _required_lower_hex(payload: dict[str, Any], field: str, *, length: int) -> str:
    value = _required_non_empty_str(payload, field).lower()
    if len(value) != length or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field} must be a {length}-character lowercase hex string")
    return value


def _required_positive_int(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


__all__ = ["SEAL_FILENAME", "build_session_seal", "seal_path", "write_seal"]
