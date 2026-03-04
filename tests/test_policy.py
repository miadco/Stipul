from datetime import datetime, timezone

from agentshield.contract.schema import Contract
from agentshield.engine.policy import evaluate
from agentshield.models import RiskClass
from tests.conftest import make_state, pick_read_tool, pick_write_tool


def test_allowed_read_tool_returns_allow(contract):
    tool = pick_read_tool(contract)
    result = evaluate(contract, tool, make_state(contract))
    assert result.decision == "allow"
    assert result.rule_triggered == "risk_class"
    assert result.risk_class == RiskClass.read


def test_allowed_write_tool_returns_allow(contract):
    tool = pick_write_tool(contract)
    result = evaluate(contract, tool, make_state(contract))
    assert result.decision == "allow"
    assert result.rule_triggered == "risk_class"
    assert result.risk_class == RiskClass.write


def test_tool_not_in_allowed_returns_deny(contract):
    unknown_tool = "totally_unknown_tool_xyz"
    assert unknown_tool not in contract.allowed_tools
    assert unknown_tool not in contract.never_allow_tools
    result = evaluate(contract, unknown_tool, make_state(contract))
    assert result.decision == "deny"
    assert result.rule_triggered == "not_allowed"


def test_never_allow_tool_returns_deny(contract):
    tool = next(iter(contract.never_allow_tools))
    result = evaluate(contract, tool, make_state(contract))
    assert result.decision == "deny"
    assert result.rule_triggered == "never_allow_tools"


def test_irreversible_tool_returns_require_approval(base_dict):
    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("dangerous_op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["dangerous_op"] = "irreversible"

    contract = Contract.from_dict(base_dict)
    result = evaluate(contract, "dangerous_op", make_state(contract))
    assert result.decision == "require_approval"
    assert result.rule_triggered == "risk_class"
    assert result.risk_class == RiskClass.irreversible


def test_exfil_risk_tool_returns_require_approval(base_dict):
    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("exfil_op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["exfil_op"] = "exfil_risk"

    contract = Contract.from_dict(base_dict)
    result = evaluate(contract, "exfil_op", make_state(contract))
    assert result.decision == "require_approval"
    assert result.rule_triggered == "risk_class"


def test_expired_contract_returns_deny(base_dict):
    contract = Contract.from_dict(base_dict)
    state = make_state(
        contract,
        current_time=datetime(2100, 1, 1, tzinfo=timezone.utc),
    )
    tool = pick_write_tool(contract)
    result = evaluate(contract, tool, state)
    assert result.decision == "deny"
    assert result.rule_triggered == "expired"


def test_tool_call_budget_exhausted_returns_deny(contract):
    tool = pick_write_tool(contract)
    state = make_state(contract, tool_calls_made=contract.max_tool_calls)
    result = evaluate(contract, tool, state)
    assert result.decision == "deny"
    assert result.rule_triggered == "budget_tool_calls"


def test_net_call_budget_exhausted_returns_deny(base_dict):
    allowed_tools = set(base_dict["allowed_tools"])
    allowed_tools.add("exfil_op")
    base_dict["allowed_tools"] = sorted(allowed_tools)
    base_dict["tool_risk_classes"]["exfil_op"] = "exfil_risk"

    contract = Contract.from_dict(base_dict)
    exact_host = next(entry for entry in contract.egress_allowlist if not entry.startswith("."))
    state = make_state(
        contract,
        net_calls_made=contract.max_net_calls,
        egress_target=exact_host,
    )
    result = evaluate(contract, "exfil_op", state)
    assert result.decision == "deny"
    assert result.rule_triggered == "budget_net_calls"


def test_egress_not_in_allowlist_returns_deny(contract):
    tool = pick_write_tool(contract)
    state = make_state(contract, egress_target="definitely.not.allowed.example.com")
    result = evaluate(contract, tool, state)
    assert result.decision == "deny"
    assert result.rule_triggered == "egress_not_allowed"


def test_egress_suffix_match_returns_allow(base_dict):
    contract = Contract.from_dict(base_dict)
    suffix_entry = next(entry for entry in contract.egress_allowlist if entry.startswith("."))
    egress_target = f"sub{suffix_entry}"
    tool = pick_write_tool(contract)
    result = evaluate(contract, tool, make_state(contract, egress_target=egress_target))
    assert not (result.decision == "deny" and result.rule_triggered == "egress_not_allowed")


def test_identity_mismatch_returns_deny(contract):
    tool = pick_write_tool(contract)
    state = make_state(contract, requesting_agent_id="wrong-agent-id")
    result = evaluate(contract, tool, state)
    assert result.decision == "deny"
    assert result.rule_triggered == "identity_mismatch"


def test_empty_allowed_tools_denies_everything(base_dict):
    base_dict["allowed_tools"] = []
    contract = Contract.from_dict(base_dict)
    tool = "synthetic_tool_not_in_any_list"
    assert tool not in contract.never_allow_tools
    result = evaluate(contract, tool, make_state(contract))
    assert result.decision == "deny"


def test_code_identity_missing_returns_deny(base_dict):
    base_dict["identity_code_sha256"] = "a" * 64
    contract = Contract.from_dict(base_dict)
    tool = pick_write_tool(contract)

    result = evaluate(contract, tool, make_state(contract))
    assert result.decision == "deny"
    assert result.rule_triggered == "code_identity_missing"


def test_code_identity_mismatch_returns_deny(base_dict):
    base_dict["identity_code_sha256"] = "a" * 64
    contract = Contract.from_dict(base_dict)
    tool = pick_write_tool(contract)
    state = make_state(contract, requesting_code_sha256="b" * 64)

    result = evaluate(contract, tool, state)
    assert result.decision == "deny"
    assert result.rule_triggered == "code_identity_mismatch"


def test_code_identity_match_allows_evaluation(base_dict):
    base_dict["identity_code_sha256"] = "a" * 64
    contract = Contract.from_dict(base_dict)
    tool = pick_write_tool(contract)
    state = make_state(contract, requesting_code_sha256="a" * 64)

    result = evaluate(contract, tool, state)
    assert result.decision in {"allow", "require_approval"}
