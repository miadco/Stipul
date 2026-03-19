from __future__ import annotations

from stipul.charter.contract.lint import lint_contract_payload
from stipul.charter.contract.schema import Contract
from tests.cli_support import load_base_contract_dict


def test_lint_valid_contract_has_no_errors() -> None:
    payload = load_base_contract_dict()
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert result.errors == []
    assert any(issue.code == "implicit_risk_defaults" for issue in result.warnings)
    assert any(issue.code == "never_allow_present" for issue in result.info)


def test_lint_reports_missing_policy_definition() -> None:
    payload = load_base_contract_dict()
    payload["allowed_tools"] = []
    payload["never_allow_tools"] = []
    payload["tool_risk_classes"] = {}
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert len(result.errors) == 1
    assert result.errors[0].code == "no_policy_defined"


def test_lint_warns_on_empty_egress_allowlist() -> None:
    payload = load_base_contract_dict()
    payload["egress_allowlist"] = []
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert any(issue.code == "empty_egress_allowlist" for issue in result.warnings)
