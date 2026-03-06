"""Tool-call interception and policy projection for the MCP Proxy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from stipul.charter.contract.schema import Contract
from stipul.charter.engine.policy import RuntimeState, evaluate
from stipul.models import RiskClass
from stipul.utils.canonical import canonical_json_bytes


@dataclass
class InterceptResult:
    tool_name: str
    input_hash: str
    decision: str
    reason: str
    risk_class: str


def _risk_to_wire(risk: RiskClass) -> str:
    if risk == RiskClass.exfil_risk:
        return "exfil-risk"
    return str(risk.value)


def _reason_code(rule_triggered: str) -> str:
    if rule_triggered in {"budget_tool_calls", "budget_net_calls"}:
        return "budget_exhausted"
    if rule_triggered == "egress_not_allowed":
        return "not_in_egress_allowlist"
    return rule_triggered


def _input_hash(inputs: Any) -> str:
    if isinstance(inputs, dict):
        payload = inputs
    else:
        payload = {"value": inputs}
    return sha256(canonical_json_bytes(payload)).hexdigest()


def _parse_current_time(raw: Any) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            raise ValueError("current_time must be timezone-aware")
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        iso_value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        parsed = datetime.fromisoformat(iso_value)
        if parsed.tzinfo is None:
            raise ValueError("current_time must be timezone-aware")
        return parsed.astimezone(timezone.utc)
    raise ValueError("current_time must be datetime or ISO 8601 string")


def _fallback(tool_name: str, input_hash: str, reason: str) -> InterceptResult:
    return InterceptResult(
        tool_name=tool_name,
        input_hash=input_hash,
        decision="deny",
        reason=reason,
        risk_class="write",
    )


def intercept(raw_request: dict[str, Any], contract: Contract) -> InterceptResult:
    """Build an interception decision for a raw proxy request."""
    if not isinstance(raw_request, dict):
        return _fallback("unknown_tool", _input_hash({}), "malformed_request")

    try:
        tool_name = raw_request["tool_name"]
        if not isinstance(tool_name, str) or not tool_name:
            return _fallback("unknown_tool", _input_hash({}), "malformed_request")

        inputs = raw_request.get("inputs", raw_request.get("input", {}))
        if inputs is None:
            inputs = {}
        input_hash = _input_hash(inputs)
    except Exception:
        return _fallback("unknown_tool", _input_hash({}), "malformed_request")

    if tool_name not in contract.allowed_tools:
        return InterceptResult(
            tool_name=tool_name,
            input_hash=input_hash,
            decision="deny",
            reason="not_in_contract",
            risk_class="write",
        )

    state_raw = raw_request.get("state", {})
    if state_raw is None:
        state_raw = {}
    if not isinstance(state_raw, dict):
        return _fallback(tool_name, input_hash, "malformed_request")

    try:
        state = RuntimeState(
            tool_calls_made=int(state_raw.get("tool_calls_made", 0)),
            net_calls_made=int(state_raw.get("net_calls_made", 0)),
            current_time=_parse_current_time(state_raw.get("current_time")),
            requesting_agent_id=str(
                state_raw.get("requesting_agent_id", contract.identity_agent_id)
            ),
            egress_target=state_raw.get("egress_target"),
            requesting_code_sha256=state_raw.get("requesting_code_sha256"),
        )
    except Exception:
        return _fallback(tool_name, input_hash, "malformed_request")

    policy_result = evaluate(contract, tool_name, state)

    return InterceptResult(
        tool_name=tool_name,
        input_hash=input_hash,
        decision=policy_result.decision,
        reason=_reason_code(policy_result.rule_triggered),
        risk_class=_risk_to_wire(policy_result.risk_class),
    )
