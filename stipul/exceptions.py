"""Custom exceptions for contract handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from stipul.writ.breakglass import BreakGlassEvent, BreakGlassManager
    from stipul.charter.permits import (
        ExceptionPermit,
        ExceptionRequest,
        PermitManager,
        PermitScopeError,
        PermitTTLError,
    )


class ContractValidationError(Exception):
    """Raised when a contract fails validation."""


class ContractMergeViolation(Exception):
    """Raised when a contract merge violates constraints."""


class BudgetExhaustedError(Exception):
    """Raised when restarting an exhausted budget session."""


__all__ = [
    "BreakGlassEvent",
    "BreakGlassManager",
    "BudgetExhaustedError",
    "ContractMergeViolation",
    "ContractValidationError",
    "ExceptionPermit",
    "ExceptionRequest",
    "PermitManager",
    "PermitScopeError",
    "PermitTTLError",
]


def __getattr__(name: str) -> Any:
    if name in {
        "BreakGlassEvent",
        "BreakGlassManager",
        "ExceptionPermit",
        "ExceptionRequest",
        "PermitManager",
        "PermitScopeError",
        "PermitTTLError",
    }:
        if name in {"BreakGlassEvent", "BreakGlassManager"}:
            from stipul.writ import breakglass

            return getattr(breakglass, name)
        from stipul.charter import permits

        return getattr(permits, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
