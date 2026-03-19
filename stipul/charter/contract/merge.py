"""Hierarchical contract merge logic."""

from __future__ import annotations

from datetime import datetime

from stipul.charter.contract.schema import Contract
from stipul.exceptions import ContractMergeViolation
from stipul.models import RiskClass

RISK_SEVERITY: dict[RiskClass, int] = {
    RiskClass.read: 0,
    RiskClass.write: 1,
    RiskClass.irreversible: 2,
    RiskClass.exfil_risk: 3,
}


def _format_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def merge(parent: Contract, child: Contract) -> Contract:
    """Merge child restrictions into parent permissions."""
    violations: list[str] = []

    # 0. schema_version
    if child.schema_version != parent.schema_version:
        violations.append(
            "schema_version: "
            f"child '{child.schema_version}' differs from parent '{parent.schema_version}'"
        )
    merged_schema_version = parent.schema_version

    # 1. created_at monotonicity
    if child.created_at < parent.created_at:
        violations.append(
            "created_at: "
            f"child '{_format_utc(child.created_at)}' "
            f"is before parent '{_format_utc(parent.created_at)}'"
        )

    # 2. allowed_tools
    child_allowed_extra = child.allowed_tools - parent.allowed_tools
    if child_allowed_extra:
        violations.append(
            "allowed_tools: "
            f"child adds tools not in parent: {sorted(child_allowed_extra)}"
        )
    merged_allowed_tools = parent.allowed_tools & child.allowed_tools

    # 3. never_allow_tools
    child_removed_prohibitions = parent.never_allow_tools - child.never_allow_tools
    if child_removed_prohibitions:
        violations.append(
            "never_allow_tools: "
            f"child removes parent prohibitions: {sorted(child_removed_prohibitions)}"
        )
    merged_never_allow_tools = parent.never_allow_tools | child.never_allow_tools

    # 4. tool_risk_classes
    for tool in parent.tool_risk_classes:
        if tool in child.tool_risk_classes:
            parent_risk = parent.tool_risk_classes[tool]
            child_risk = child.tool_risk_classes[tool]
            if RISK_SEVERITY[child_risk] < RISK_SEVERITY[parent_risk]:
                violations.append(
                    "tool_risk_classes: "
                    f"child downgrades '{tool}' from {parent_risk.value} to {child_risk.value}"
                )

    merged_tool_risk_classes: dict[str, RiskClass] = {}
    all_risk_tools = set(parent.tool_risk_classes) | set(child.tool_risk_classes)
    for tool in sorted(all_risk_tools):
        in_parent = tool in parent.tool_risk_classes
        in_child = tool in child.tool_risk_classes
        if in_parent and in_child:
            parent_risk = parent.tool_risk_classes[tool]
            child_risk = child.tool_risk_classes[tool]
            if RISK_SEVERITY[parent_risk] >= RISK_SEVERITY[child_risk]:
                merged_tool_risk_classes[tool] = parent_risk
            else:
                merged_tool_risk_classes[tool] = child_risk
        elif in_parent:
            merged_tool_risk_classes[tool] = parent.tool_risk_classes[tool]
        else:
            merged_tool_risk_classes[tool] = child.tool_risk_classes[tool]

    # 5. max_tool_calls
    merged_max_tool_calls = min(parent.max_tool_calls, child.max_tool_calls)

    # 6. max_net_calls
    merged_max_net_calls = min(parent.max_net_calls, child.max_net_calls)

    # 7. expires_at
    merged_expires_at = min(parent.expires_at, child.expires_at)

    # 8. egress_allowlist
    child_egress_extra = child.egress_allowlist - parent.egress_allowlist
    if child_egress_extra:
        violations.append(
            "egress_allowlist: "
            f"child adds domains not in parent: {sorted(child_egress_extra)}"
        )
    merged_egress_allowlist = parent.egress_allowlist & child.egress_allowlist

    # 9. identity
    if child.identity_agent_id != parent.identity_agent_id:
        violations.append(
            "identity: "
            f"child agent_id '{child.identity_agent_id}' differs from parent "
            f"'{parent.identity_agent_id}'"
        )
    if parent.identity_code_sha256 is not None and child.identity_code_sha256 is None:
        violations.append(
            "identity: child removes code_sha256 constraint present in parent"
        )
    if (
        parent.identity_code_sha256 is not None
        and child.identity_code_sha256 is not None
        and child.identity_code_sha256 != parent.identity_code_sha256
    ):
        violations.append(
            "identity: "
            f"child code_sha256 '{child.identity_code_sha256}' differs from parent "
            f"'{parent.identity_code_sha256}'"
        )
    merged_identity_agent_id = child.identity_agent_id
    merged_identity_code_sha256 = child.identity_code_sha256

    if violations:
        raise ContractMergeViolation("\n".join(violations))

    return Contract(
        schema_version=merged_schema_version,
        contract_id=child.contract_id,
        parent_contract_id=parent.contract_id,
        created_at=child.created_at,
        expires_at=merged_expires_at,
        signed_by=child.signed_by,
        identity_agent_id=merged_identity_agent_id,
        identity_code_sha256=merged_identity_code_sha256,
        allowed_tools=merged_allowed_tools,
        never_allow_tools=merged_never_allow_tools,
        tool_risk_classes=merged_tool_risk_classes,
        max_tool_calls=merged_max_tool_calls,
        max_net_calls=merged_max_net_calls,
        egress_allowlist=merged_egress_allowlist,
    )
