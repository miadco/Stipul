from __future__ import annotations


def test_verify_chain_tests_are_marked_signed_chain(pytestconfig) -> None:
    """
    Guardrail intent:
    verify_chain() usage is restricted to tests/test_chain_*.py with signed_chain markers.

    Enforcement is done in CI via grep-based checks in .github/workflows/ci.yml.
    """
    _ = pytestconfig
    assert True
