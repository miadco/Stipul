from __future__ import annotations

import copy
import uuid
from dataclasses import replace

import pytest

from agentshield.contract.merge import RISK_SEVERITY, merge
from agentshield.contract.schema import Contract
from agentshield.exceptions import ContractMergeViolation
from agentshield.models import RiskClass


def make_child_dict(base_dict: dict, **overrides) -> dict:
    d = copy.deepcopy(base_dict)
    d["contract_id"] = str(uuid.uuid4())
    d["created_at"] = base_dict["created_at"]
    for k, v in overrides.items():
        d[k] = v
    return d


def test_valid_restriction_merges_successfully(base_dict, contract):
    one_tool = next(iter(contract.allowed_tools))
    child_dict = make_child_dict(base_dict, allowed_tools=[one_tool])
    child = Contract.from_dict(child_dict)

    result = merge(contract, child)
    assert result.allowed_tools == frozenset({one_tool})


def test_child_adding_tool_raises_violation(base_dict, contract):
    child_tools = list(contract.allowed_tools) + ["injected_tool"]
    child_dict = make_child_dict(base_dict, allowed_tools=child_tools)
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(contract, child)
    assert "allowed_tools" in str(exc.value)


def test_child_removing_never_allow_raises_violation(base_dict, contract):
    child_dict = make_child_dict(base_dict, never_allow_tools=[])
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(contract, child)
    assert "never_allow_tools" in str(exc.value)


def test_child_downgrading_risk_class_raises_violation(base_dict, contract):
    tool = next(iter(contract.tool_risk_classes))
    parent = contract
    if parent.tool_risk_classes[tool] == RiskClass.read:
        parent = replace(
            contract,
            tool_risk_classes={**contract.tool_risk_classes, tool: RiskClass.irreversible},
        )

    child_dict = make_child_dict(base_dict)
    child_risks = dict(child_dict["tool_risk_classes"])
    child_risks[tool] = "read"
    child_dict["tool_risk_classes"] = child_risks
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(parent, child)
    assert "tool_risk_classes" in str(exc.value)


def test_child_adding_egress_domain_raises_violation(base_dict):
    parent = Contract.from_dict(base_dict)
    child_egress = list(base_dict["egress_allowlist"]) + ["newly-added.example"]
    child_dict = make_child_dict(base_dict, egress_allowlist=child_egress)
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(parent, child)
    assert "egress_allowlist" in str(exc.value)


def test_child_different_schema_version_raises_violation(contract):
    child = replace(contract, schema_version="1.1", contract_id=str(uuid.uuid4()))

    with pytest.raises(ContractMergeViolation) as exc:
        merge(contract, child)
    assert "schema_version" in str(exc.value)


def test_child_agent_id_differs_raises_violation(base_dict, contract):
    child_dict = make_child_dict(base_dict, identity_agent_id="different-agent")
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(contract, child)
    assert "identity" in str(exc.value)


def test_multiple_violations_reported_together(base_dict, contract):
    child_tools = list(contract.allowed_tools) + ["injected_tool"]
    child_egress = list(contract.egress_allowlist) + ["newly-added.example"]
    child_dict = make_child_dict(
        base_dict,
        allowed_tools=child_tools,
        egress_allowlist=child_egress,
        identity_agent_id="different-agent",
    )
    child = Contract.from_dict(child_dict)

    with pytest.raises(ContractMergeViolation) as exc:
        merge(contract, child)

    msg = str(exc.value)
    assert "allowed_tools" in msg
    assert "egress_allowlist" in msg
    assert "identity" in msg


def test_risk_class_merge_takes_higher_severity(contract):
    tool = next(iter(contract.allowed_tools))
    parent = replace(
        contract,
        tool_risk_classes={**contract.tool_risk_classes, tool: RiskClass.write},
    )
    child = replace(
        parent,
        contract_id=str(uuid.uuid4()),
        tool_risk_classes={**parent.tool_risk_classes, tool: RiskClass.irreversible},
    )

    result = merge(parent, child)
    assert RISK_SEVERITY[result.tool_risk_classes[tool]] == RISK_SEVERITY[RiskClass.irreversible]
    assert result.tool_risk_classes[tool] == RiskClass.irreversible


def test_child_adding_code_sha256_is_allowed(base_dict):
    parent_dict = copy.deepcopy(base_dict)
    parent_dict["identity_code_sha256"] = None
    parent = Contract.from_dict(parent_dict)

    child_dict = make_child_dict(parent_dict, identity_code_sha256="a" * 64)
    child = Contract.from_dict(child_dict)

    result = merge(parent, child)
    assert result.identity_code_sha256 == "a" * 64
