"""Server Wrapper token-validation shim."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from agentshield.token.validate import validate_token


DecisionError = dict[str, str]


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


def handle_tool_call(
    raw_request: Mapping[str, Any],
    execute_tool: Callable[[Mapping[str, Any]], Any],
) -> Any | DecisionError:
    """Validate wrapper token and forward only if valid."""
    tool_name = _extract_tool_name(raw_request) or "unknown_tool"

    try:
        token, extract_reason = _extract_bearer_token(raw_request.get("headers"))
        if extract_reason is not None:
            return _deny(extract_reason, tool_name)

        is_valid, reason = validate_token(token, tool_name)
        if not is_valid:
            return _deny(reason, tool_name)

        return execute_tool(raw_request)
    except Exception:
        return _deny("wrapper_error", tool_name)
