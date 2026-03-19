"""Token Gate validation.

Replay within TTL window is an accepted risk in Week 2. Tokens embed a nonce
but the wrapper does not maintain a seen-nonce store. A captured token can be
replayed until expiry. Mitigation: keep TTL short. Full one-time-use enforcement
is deferred to Week 4 Bypass Detector.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from stipul.charter.token.mint import _TOKEN_SECRET_ENV
from stipul.utils.canonical import canonical_json_bytes

_REASON_INVALID_FORMAT = "invalid_format"
_REASON_INVALID_SIGNATURE = "invalid_signature"
_REASON_EXPIRED = "expired"
_REASON_WRONG_TOOL = "wrong_tool"
_REASON_MISSING = "missing_token"

_EXPECTED_PAYLOAD_FIELDS = {
    "tool",
    "scope",
    "session_id",
    "contract_id",
    "iat",
    "exp",
    "nonce",
}


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _signature_hex(payload_bytes: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def _utc_now_epoch() -> int:
    return int(time.time())


def _has_valid_shape(payload: dict[str, Any]) -> bool:
    if set(payload.keys()) != _EXPECTED_PAYLOAD_FIELDS:
        return False
    if not isinstance(payload["tool"], str) or not payload["tool"]:
        return False
    if not isinstance(payload["scope"], str) or not payload["scope"]:
        return False
    if not isinstance(payload["session_id"], str) or not payload["session_id"]:
        return False
    if not isinstance(payload["contract_id"], str) or not payload["contract_id"]:
        return False
    if isinstance(payload["iat"], bool) or not isinstance(payload["iat"], int):
        return False
    if isinstance(payload["exp"], bool) or not isinstance(payload["exp"], int):
        return False
    if not isinstance(payload["nonce"], str) or not payload["nonce"]:
        return False
    return True


def validate_token(token: str | None, tool_name: str) -> tuple[bool, str]:
    """Validate a wrapper authorization token for a specific tool name."""
    if token is None or (isinstance(token, str) and token.strip() == ""):
        return False, _REASON_MISSING
    if not isinstance(token, str):
        return False, _REASON_INVALID_FORMAT

    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False, _REASON_INVALID_FORMAT

    payload_b64, signature_b64 = parts
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload_obj = json.loads(payload_bytes.decode("utf-8"))
        signature_hex = _b64url_decode(signature_b64).decode("ascii")
    except Exception:
        return False, _REASON_INVALID_FORMAT

    if not isinstance(payload_obj, dict) or not _has_valid_shape(payload_obj):
        return False, _REASON_INVALID_FORMAT

    secret = os.getenv(_TOKEN_SECRET_ENV)
    if not secret:
        return False, _REASON_INVALID_SIGNATURE

    canonical_payload = canonical_json_bytes(payload_obj)
    expected_signature_hex = _signature_hex(canonical_payload, secret)
    if not hmac.compare_digest(signature_hex, expected_signature_hex):
        return False, _REASON_INVALID_SIGNATURE

    if _utc_now_epoch() >= payload_obj["exp"]:
        return False, _REASON_EXPIRED

    if payload_obj["tool"] != tool_name:
        return False, _REASON_WRONG_TOOL

    return True, "valid"
