"""Token Gate minting."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from stipul.utils.canonical import canonical_json_bytes

_TOKEN_SECRET_ENV = "STIPUL_TOKEN_SECRET"  # nosec B105


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _token_secret() -> str:
    secret = os.getenv(_TOKEN_SECRET_ENV)
    if not secret:
        raise ValueError(f"Missing required environment variable: {_TOKEN_SECRET_ENV}")
    return secret


def _signature_hex(payload_bytes: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def mint_token(
    tool_name: str,
    scope: str,
    ttl: int,
    session_id: str,
    contract_id: str,
) -> str:
    """Mint a signed authorization token for the Server Wrapper."""
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(scope, str) or not scope:
        raise ValueError("scope must be a non-empty string")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    if not isinstance(contract_id, str) or not contract_id:
        raise ValueError("contract_id must be a non-empty string")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl must be a positive integer")

    iat = int(time.time())
    payload: dict[str, Any] = {
        "tool": tool_name,
        "scope": scope,
        "session_id": session_id,
        "contract_id": contract_id,
        "iat": iat,
        "exp": iat + ttl,
        "nonce": secrets.token_hex(16),
    }

    payload_bytes = canonical_json_bytes(payload)
    signature_hex = _signature_hex(payload_bytes, _token_secret())
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature_hex.encode('ascii'))}"
