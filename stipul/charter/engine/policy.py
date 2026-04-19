"""Pure policy decision engine.

RuntimeState is defined here and belongs here. It is policy-layer input, not a
shared model. Do not relocate to models.py. Week 3 imports RuntimeState from
policy.py directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from stipul.charter.contract.schema import Contract
from stipul.models import PolicyDecision, RiskClass
from stipul.writ.proxy.egress import is_egress_allowed


@dataclass
class RuntimeState:
    """Runtime inputs for pure policy evaluation."""

    tool_calls_made: int
    net_calls_made: int
    current_time: datetime
    requesting_agent_id: str
    egress_target: str | None
    invalid_egress_target: bool = False
    requesting_code_sha256: str | None = None


def _resolve_risk_class(contract: Contract, tool_name: str) -> RiskClass:
    return contract.tool_risk_classes.get(tool_name, RiskClass.write)


def evaluate(
    contract: Contract,
    tool_name: str,
    state: RuntimeState,
) -> PolicyDecision:
    """Evaluate a tool invocation against the contract and runtime state."""
    risk_class = _resolve_risk_class(contract, tool_name)

    if state.current_time >= contract.expires_at:
        return PolicyDecision(
            decision="deny",
            reason=(
                "Contract expired at "
                f"{contract.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            ),
            risk_class=risk_class,
            rule_triggered="expired",
        )

    if state.requesting_agent_id != contract.identity_agent_id:
        return PolicyDecision(
            decision="deny",
            reason=(
                "Agent ID mismatch: "
                f"expected '{contract.identity_agent_id}', got '{state.requesting_agent_id}'"
            ),
            risk_class=risk_class,
            rule_triggered="identity_mismatch",
        )

    if contract.identity_code_sha256 is not None:
        if state.requesting_code_sha256 is None:
            return PolicyDecision(
                decision="deny",
                reason="Code identity missing for contract requiring code_sha256",
                risk_class=risk_class,
                rule_triggered="code_identity_missing",
            )
        if state.requesting_code_sha256 != contract.identity_code_sha256:
            return PolicyDecision(
                decision="deny",
                reason=(
                    "Code SHA-256 mismatch: "
                    f"expected '{contract.identity_code_sha256}', "
                    f"got '{state.requesting_code_sha256}'"
                ),
                risk_class=risk_class,
                rule_triggered="code_identity_mismatch",
            )

    if tool_name in contract.never_allow_tools:
        return PolicyDecision(
            decision="deny",
            reason=f"Tool '{tool_name}' is permanently prohibited",
            risk_class=risk_class,
            rule_triggered="never_allow_tools",
        )

    if tool_name not in contract.allowed_tools:
        return PolicyDecision(
            decision="deny",
            reason=f"Tool '{tool_name}' is not in allowed_tools",
            risk_class=risk_class,
            rule_triggered="not_allowed",
        )

    if state.invalid_egress_target:
        return PolicyDecision(
            decision="deny",
            reason="Egress target is invalid or unparsable",
            risk_class=risk_class,
            rule_triggered="invalid_egress_target",
        )

    if state.tool_calls_made >= contract.max_tool_calls:
        return PolicyDecision(
            decision="deny",
            reason=(
                "Tool call budget exhausted: "
                f"{state.tool_calls_made}/{contract.max_tool_calls} calls used"
            ),
            risk_class=risk_class,
            rule_triggered="budget_tool_calls",
        )

    is_network_call = (
        state.egress_target is not None or risk_class == RiskClass.exfil_risk
    )
    if is_network_call and state.net_calls_made >= contract.max_net_calls:
        return PolicyDecision(
            decision="deny",
            reason=(
                "Network call budget exhausted: "
                f"{state.net_calls_made}/{contract.max_net_calls} calls used"
            ),
            risk_class=risk_class,
            rule_triggered="budget_net_calls",
        )

    if state.egress_target is not None:
        if not is_egress_allowed(state.egress_target, contract.egress_allowlist):
            return PolicyDecision(
                decision="deny",
                reason=(
                    f"Egress target '{state.egress_target}' "
                    "is not in the allowlist"
                ),
                risk_class=risk_class,
                rule_triggered="egress_not_allowed",
            )

    if risk_class == RiskClass.read:
        return PolicyDecision(
            decision="allow",
            reason=f"Tool '{tool_name}' allowed (risk: read)",
            risk_class=risk_class,
            rule_triggered="risk_class",
        )
    if risk_class == RiskClass.write:
        return PolicyDecision(
            decision="allow",
            reason=f"Tool '{tool_name}' allowed (risk: write)",
            risk_class=risk_class,
            rule_triggered="risk_class",
        )
    if risk_class == RiskClass.irreversible:
        return PolicyDecision(
            decision="require_approval",
            reason=f"Tool '{tool_name}' requires approval (risk: irreversible)",
            risk_class=risk_class,
            rule_triggered="risk_class",
        )
    if risk_class == RiskClass.exfil_risk:
        return PolicyDecision(
            decision="require_approval",
            reason=f"Tool '{tool_name}' requires approval (risk: exfil_risk)",
            risk_class=risk_class,
            rule_triggered="risk_class",
        )

    return PolicyDecision(
        decision="deny",
        reason=f"Tool '{tool_name}' denied by default (no rule matched)",
        risk_class=risk_class,
        rule_triggered="default_deny",
    )
