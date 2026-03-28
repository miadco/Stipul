from __future__ import annotations

import logging

import pytest

from stipul.writ.proxy.startup import (
    SecretIsolationError,
    check_secret_isolation,
)


def test_secret_in_agent_environment_refuses_startup(caplog) -> None:
    caplog.set_level(logging.WARNING)

    with pytest.raises(SecretIsolationError):
        check_secret_isolation(
            agent_env={
                "PATH": "/usr/bin",
                "STIPUL_TOKEN_SECRET": "super-secret",
            }
        )

    assert any(
        "FATAL: Token secret detected in agent environment." in record.message
        for record in caplog.records
    )
    assert not any(record.levelno < logging.ERROR for record in caplog.records)


def test_token_secret_marker_in_any_key_refuses_startup(caplog) -> None:
    caplog.set_level(logging.WARNING)

    with pytest.raises(SecretIsolationError):
        check_secret_isolation(
            agent_env={
                "SOME_TOKEN_SECRET_ALIAS": "abc",
            }
        )

    assert any(
        "FATAL: Token secret detected in agent environment." in record.message
        for record in caplog.records
    )


def test_secret_absent_in_agent_environment_allows_startup(caplog) -> None:
    caplog.set_level(logging.INFO)

    result = check_secret_isolation(
        agent_env={
            "PATH": "/usr/bin",
            "HOME": "/tmp/agent",
        }
    )

    assert result.verified is True
    assert result.check_performed is True
    assert result.source == "agent_env"
    assert result.detected_keys == ()
    assert caplog.records == []


def test_no_inspection_target_logs_info_and_proceeds(caplog) -> None:
    caplog.set_level(logging.INFO)

    result = check_secret_isolation()

    assert result.verified is False
    assert result.check_performed is False
    assert result.source == "no_target"
    assert any(
        "Token secret isolation was not verified in this attach mode" in record.message
        for record in caplog.records
    )
    assert not any(record.levelno >= logging.WARNING for record in caplog.records)


def test_proc_inspection_error_logs_warning_and_proceeds(monkeypatch, caplog) -> None:
    caplog.set_level(logging.WARNING)

    def _boom(_pid: int):
        raise OSError("permission denied")

    monkeypatch.setattr("stipul.writ.proxy.startup._read_linux_proc_environ", _boom)

    result = check_secret_isolation(agent_pid=1234)

    assert result.verified is False
    assert result.check_performed is False
    assert result.source == "proc"
    assert any(
        "Token secret isolation could not be verified because the agent environment could not be inspected."
        in record.message
        for record in caplog.records
    )
