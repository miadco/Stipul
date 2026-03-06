"""Semantic linting for operator-facing contract review."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from stipul.charter.contract.schema import Contract

Severity = Literal["ERROR", "WARN", "INFO"]


@dataclass(frozen=True)
class LintIssue:
    severity: Severity
    code: str
    message: str


@dataclass(frozen=True)
class ContractLintResult:
    issues: list[LintIssue]

    @property
    def errors(self) -> list[LintIssue]:
        return [issue for issue in self.issues if issue.severity == "ERROR"]

    @property
    def warnings(self) -> list[LintIssue]:
        return [issue for issue in self.issues if issue.severity == "WARN"]

    @property
    def info(self) -> list[LintIssue]:
        return [issue for issue in self.issues if issue.severity == "INFO"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "errors": [issue.__dict__ for issue in self.errors],
            "info": [issue.__dict__ for issue in self.info],
            "issues": [issue.__dict__ for issue in self.issues],
            "warnings": [issue.__dict__ for issue in self.warnings],
        }


def lint_contract_payload(payload: dict[str, Any], contract: Contract) -> ContractLintResult:
    issues: list[LintIssue] = []

    allowed_tools = _string_collection(payload.get("allowed_tools"))
    never_allow_tools = _string_collection(payload.get("never_allow_tools"))
    if allowed_tools is not None and never_allow_tools is not None:
        if not allowed_tools and not never_allow_tools:
            issues.append(
                LintIssue(
                    severity="ERROR",
                    code="no_policy_defined",
                    message="allowed_tools and never_allow_tools are both empty.",
                )
            )

    egress_allowlist = _string_collection(payload.get("egress_allowlist"))
    if egress_allowlist is not None and not egress_allowlist:
        issues.append(
            LintIssue(
                severity="WARN",
                code="empty_egress_allowlist",
                message="egress_allowlist is empty; no outbound egress will be allowed.",
            )
        )

    raw_tool_risk_classes = payload.get("tool_risk_classes")
    if allowed_tools is not None and isinstance(raw_tool_risk_classes, dict):
        missing_risk_classes = sorted(tool for tool in allowed_tools if tool not in raw_tool_risk_classes)
        if missing_risk_classes:
            issues.append(
                LintIssue(
                    severity="WARN",
                    code="implicit_risk_defaults",
                    message=(
                        "tool_risk_classes omits allowed tools; the schema will default them to write: "
                        f"{missing_risk_classes}"
                    ),
                )
            )

    if contract.never_allow_tools:
        issues.append(
            LintIssue(
                severity="INFO",
                code="never_allow_present",
                message="never_allow_tools is non-empty.",
            )
        )

    return ContractLintResult(issues=issues)


def _string_collection(value: Any) -> list[str] | None:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    output: list[str] = []
    for item in value:
        if isinstance(item, str):
            output.append(item)
    return output
