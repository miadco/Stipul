from __future__ import annotations

from stipul.charter.contract.lint import lint_contract_payload
from stipul.charter.contract.schema import Contract
from tests.cli_support import load_base_charter_dict


def test_lint_valid_charter_has_no_errors() -> None:
    payload = load_base_charter_dict()
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert result.errors == []
    assert any(issue.code == "implicit_risk_defaults" for issue in result.warnings)
    assert any(issue.code == "never_allow_present" for issue in result.info)


def test_lint_reports_missing_policy_definition() -> None:
    payload = load_base_charter_dict()
    payload["allowed_tools"] = []
    payload["never_allow_tools"] = []
    payload["tool_risk_classes"] = {}
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert len(result.errors) == 1
    assert result.errors[0].code == "no_policy_defined"


def test_lint_warns_on_empty_egress_allowlist() -> None:
    payload = load_base_charter_dict()
    payload["egress_allowlist"] = []
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert any(issue.code == "empty_egress_allowlist" for issue in result.warnings)


def test_lint_passes_when_allowed_and_never_allow_do_not_overlap() -> None:
    payload = load_base_charter_dict()
    payload["allowed_tools"] = ["filesystem.write", "web.search"]
    payload["never_allow_tools"] = ["subprocess.exec"]
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert not any(issue.code == "conflicting_tool_policy" for issue in result.errors)


def test_lint_fails_for_single_overlapping_tool() -> None:
    payload = load_base_charter_dict()
    payload["allowed_tools"] = ["filesystem.write", "web.search"]
    payload["never_allow_tools"] = ["web.search"]
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert any(
        issue.message
        == "Tool(s) in both allowed_tools and never_allow_tools: ['web.search']"
        for issue in result.errors
    )


def test_lint_fails_for_multiple_overlapping_tools_in_sorted_order() -> None:
    payload = load_base_charter_dict()
    payload["allowed_tools"] = ["web.search", "filesystem.write", "browser.open"]
    payload["never_allow_tools"] = ["browser.open", "filesystem.write", "shell.exec"]
    contract = Contract.from_dict(payload)

    result = lint_contract_payload(payload, contract)

    assert any(
        issue.message
        == (
            "Tool(s) in both allowed_tools and never_allow_tools: "
            "['browser.open', 'filesystem.write']"
        )
        for issue in result.errors
    )


def test_lint_passes_when_only_allowed_tools_is_present() -> None:
    payload = load_base_charter_dict()
    contract = Contract.from_dict(payload)
    del payload["never_allow_tools"]

    result = lint_contract_payload(payload, contract)

    assert not any(issue.code == "conflicting_tool_policy" for issue in result.errors)


def test_lint_passes_when_only_never_allow_tools_is_present() -> None:
    payload = load_base_charter_dict()
    contract = Contract.from_dict(payload)
    del payload["allowed_tools"]

    result = lint_contract_payload(payload, contract)

    assert not any(issue.code == "conflicting_tool_policy" for issue in result.errors)
