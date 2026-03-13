from __future__ import annotations

from tests.cli_support import run_cli


def test_agentshield_help_works() -> None:
    result = run_cli("--help")

    assert result.returncode == 0
    assert "usage: stipul" in result.stdout
    assert "verify" in result.stdout
    assert "scan" in result.stdout


def test_agentshield_verify_help_works() -> None:
    result = run_cli("verify", "--help")

    assert result.returncode == 0
    assert "usage: stipul verify" in result.stdout
    assert "--session-dir" in result.stdout


def test_missing_args_returns_non_zero_with_helpful_error() -> None:
    result = run_cli("verify")

    assert result.returncode != 0
    assert "error:" in result.stderr.lower()
    assert "--session-dir" in result.stderr


def test_history_runs_against_repo_root_sample_ledger() -> None:
    result = run_cli("history")

    assert result.returncode == 0
    assert "Session 11111111-1111-1111-1111-111111111111" in result.stdout
    assert "Agent called filesystem.read - allowed within allowed risk class" in result.stdout
    assert "Kill switch enabled by operator@example.com" in result.stdout
