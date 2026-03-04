"""Custom exceptions for contract handling."""


class ContractValidationError(Exception):
    """Raised when a contract fails validation."""


class ContractMergeViolation(Exception):
    """Raised when a contract merge violates constraints."""


class BudgetExhaustedError(Exception):
    """Raised when restarting an exhausted budget session."""
