from __future__ import annotations

from tests.cli_support import run_cli


def test_agentshield_help_works() -> None:
    result = run_cli("--help")

    assert result.returncode == 0
    assert "usage: agentshield" in result.stdout
    assert "verify" in result.stdout
    assert "scan" in result.stdout


def test_agentshield_verify_help_works() -> None:
    result = run_cli("verify", "--help")

    assert result.returncode == 0
    assert "usage: agentshield verify" in result.stdout
    assert "--session-dir" in result.stdout


def test_missing_args_returns_non_zero_with_helpful_error() -> None:
    result = run_cli("verify")

    assert result.returncode != 0
    assert "error:" in result.stderr.lower()
    assert "--session-dir" in result.stderr
