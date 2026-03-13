"""Server Wrapper token-validation shim."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from stipul.charter.token.validate import validate_token
from stipul.utils.canonical import canonical_json_bytes


DecisionError = dict[str, str]
_WRAPPER_LOG_PATH_ENV = "STIPUL_WRAPPER_LOG_PATH"
_WRAPPER_ERROR_REASON = "wrapper_error"


def _deny(reason: str, tool_name: str) -> DecisionError:
    return {
        "decision": "deny",
        "reason": reason,
        "tool_name": tool_name,
    }


def _extract_tool_name(raw_request: Mapping[str, Any]) -> str | None:
    tool_name = raw_request.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        return tool_name
    return None


def _extract_bearer_token(headers: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    if headers is None:
        return None, "missing_token"

    auth_value: Any = None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "authorization":
            auth_value = value
            break

    if auth_value is None:
        return None, "missing_token"
    if not isinstance(auth_value, str):
        return None, "invalid_format"

    parts = auth_value.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        return None, "invalid_format"

    return parts[1], None


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_inputs(raw_request: Mapping[str, Any]) -> dict[str, Any]:
    value = raw_request.get("inputs", raw_request.get("input", {}))
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return {"value": value}


def _input_hash(raw_request: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(_extract_inputs(raw_request))).hexdigest()


def _wrapper_log_path() -> Path | None:
    raw_path = os.getenv(_WRAPPER_LOG_PATH_ENV)
    if not raw_path:
        return None
    return Path(raw_path)


def _log_wrapper_call(
    raw_request: Mapping[str, Any],
    *,
    tool_name: str,
    token_valid: bool,
    token_error: str | None,
    execution_result: str,
) -> None:
    path = _wrapper_log_path()
    if path is None:
        return

    payload = {
        "timestamp": _now_iso_utc(),
        "tool_name": tool_name,
        "input_hash": _input_hash(raw_request),
        "token_valid": token_valid,
        "token_error": token_error,
        "execution_result": execution_result,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    except Exception:
        return


def handle_tool_call(
    raw_request: Mapping[str, Any],
    execute_tool: Callable[[Mapping[str, Any]], Any],
) -> Any | DecisionError:
    """Validate wrapper token and forward only if valid."""
    tool_name = _extract_tool_name(raw_request) or "unknown_tool"
    token_valid = False

    try:
        token, extract_reason = _extract_bearer_token(raw_request.get("headers"))
        if extract_reason is not None:
            _log_wrapper_call(
                raw_request,
                tool_name=tool_name,
                token_valid=False,
                token_error=extract_reason,
                execution_result="rejected",
            )
            return _deny(extract_reason, tool_name)

        is_valid, reason = validate_token(token, tool_name)
        if not is_valid:
            _log_wrapper_call(
                raw_request,
                tool_name=tool_name,
                token_valid=False,
                token_error=reason,
                execution_result="rejected",
            )
            return _deny(reason, tool_name)

        token_valid = True
        result = execute_tool(raw_request)
        _log_wrapper_call(
            raw_request,
            tool_name=tool_name,
            token_valid=True,
            token_error=None,
            execution_result="success",
        )
        return result
    except Exception:
        _log_wrapper_call(
            raw_request,
            tool_name=tool_name,
            token_valid=token_valid,
            token_error=_WRAPPER_ERROR_REASON,
            execution_result="error",
        )
        return _deny(_WRAPPER_ERROR_REASON, tool_name)
