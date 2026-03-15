"""Signing helpers for session Seal artifacts."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stipul.utils.canonical import canonical_json_bytes


def canonical_seal_payload(seal: dict[str, Any]) -> bytes:
    """Return canonical signing payload bytes for a Seal without `signature`."""
    if not isinstance(seal, dict):
        raise TypeError("seal must be a dictionary")
    payload = {key: value for key, value in seal.items() if key != "signature"}
    return canonical_json_bytes(payload)


def sign_seal(seal: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Sign canonical Seal payload and return a base64 signature."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be Ed25519PrivateKey")

    signature = private_key.sign(canonical_seal_payload(seal))
    return base64.b64encode(signature).decode("ascii")


__all__ = ["canonical_seal_payload", "sign_seal"]
