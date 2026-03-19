"""Data models for policy evaluation."""

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class RiskClass(Enum):
    """Risk class assigned to a policy decision."""

    read = "read"
    write = "write"
    irreversible = "irreversible"
    exfil_risk = "exfil_risk"

    # Backward-compatible aliases.
    READ = "read"
    WRITE = "write"
    IRREVERSIBLE = "irreversible"
    EXFIL_RISK = "exfil_risk"


Decision = Literal["allow", "deny", "require_approval"]


@dataclass
class PolicyDecision:
    """Represents the outcome of evaluating a policy rule."""

    decision: Decision
    reason: str
    risk_class: RiskClass
    rule_triggered: str
