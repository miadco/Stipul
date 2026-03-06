from __future__ import annotations

import base64
import json
import re

from stipul.charter.token.mint import mint_token
from stipul.charter.token.validate import validate_token


def _decode_payload(token: str) -> dict:
    payload_b64 = token.split(".", 1)[0]
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + pad)
    return json.loads(payload_bytes.decode("utf-8"))


def test_valid_token_round_trip(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )

    is_valid, reason = validate_token(token, "filesystem.write")
    assert is_valid is True
    assert reason == "valid"


def test_minted_token_contains_nonce_field(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )
    payload = _decode_payload(token)

    assert "nonce" in payload
    assert isinstance(payload["nonce"], str)
    assert re.fullmatch(r"[0-9a-f]{32}", payload["nonce"]) is not None


def test_missing_token_returns_missing_token():
    is_valid, reason = validate_token(None, "filesystem.write")
    assert is_valid is False
    assert reason == "missing_token"


def test_wrong_tool_returns_wrong_tool(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )

    is_valid, reason = validate_token(token, "web.search")
    assert is_valid is False
    assert reason == "wrong_tool"


def test_tampered_token_returns_invalid_signature(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )
    payload = _decode_payload(token)
    payload["nonce"] = "0" * 32

    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    tampered_payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    tampered = f"{tampered_payload}.{token.split('.', 1)[1]}"

    is_valid, reason = validate_token(tampered, "filesystem.write")
    assert is_valid is False
    assert reason == "invalid_signature"


def test_expired_token_returns_expired(monkeypatch, contract):
    monkeypatch.setenv("AGENTSHIELD_TOKEN_SECRET", "test-secret")

    token = mint_token(
        tool_name="filesystem.write",
        scope="tool.execute",
        ttl=60,
        session_id="session-1",
        contract_id=contract.contract_id,
    )
    payload = _decode_payload(token)

    monkeypatch.setattr("stipul.charter.token.validate._utc_now_epoch", lambda: payload["exp"])

    is_valid, reason = validate_token(token, "filesystem.write")
    assert is_valid is False
    assert reason == "expired"
