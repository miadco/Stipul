"""Signing helpers for Event Stream records."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stipul.utils.canonical import canonical_event_payload, compute_prev_hash


def sign_event(event: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Sign canonical event payload and return base64-encoded signature."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be Ed25519PrivateKey")

    signature = private_key.sign(canonical_event_payload(event))
    return base64.b64encode(signature).decode("ascii")


__all__ = ["sign_event", "canonical_event_payload", "compute_prev_hash"]
