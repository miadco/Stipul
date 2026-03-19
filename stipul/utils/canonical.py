"""Canonical serialization helpers for hashing and signing."""

from __future__ import annotations

import hashlib
import json
from typing import Any

CANONICAL_JSON_SORT_KEYS = True
CANONICAL_JSON_SEPARATORS: tuple[str, str] = (",", ":")


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    """
    Return canonical UTF-8 JSON bytes for a dictionary payload.

    Canonical serialization rule: sorted keys, compact separators, UTF-8 bytes.
    This is the single serialization authority for hashing and signing paths.
    """
    if not isinstance(obj, dict):
        raise TypeError("canonical_json_bytes expects a dictionary")
    return json.dumps(
        obj,
        sort_keys=CANONICAL_JSON_SORT_KEYS,
        separators=CANONICAL_JSON_SEPARATORS,
    ).encode("utf-8")


def canonical_event_payload(event: dict[str, Any]) -> bytes:
    """Return canonical signing payload bytes for an event without `signature`."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    payload = {key: value for key, value in event.items() if key != "signature"}
    return canonical_json_bytes(payload)


def compute_prev_hash(event: dict[str, Any]) -> str:
    """Return SHA-256 hex of full canonical event payload (includes signature)."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    return hashlib.sha256(canonical_json_bytes(event)).hexdigest()


def sha256_hex_for_json(value: dict[str, Any]) -> str:
    """Hash canonical JSON representation with SHA-256 (hex digest)."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
