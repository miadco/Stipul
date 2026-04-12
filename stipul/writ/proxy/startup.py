"""Startup checks for MCP Proxy trust boundaries."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, cast

_TOKEN_SECRET_MARKER = "TOKEN_SECRET"  # nosec B105
_FATAL_SECRET_MESSAGE = (
    "FATAL: Token secret detected in agent environment. "
    "Secret isolation violated. Resolve before starting proxy."
)  # nosec B105
_ISOLATION_SKIPPED_INFO = (
    "Token secret isolation was not verified in this attach mode because "
    "no inspectable agent environment target was provided."
)
_ISOLATION_UNVERIFIED_WARNING = (
    "Token secret isolation could not be verified because the agent "
    "environment could not be inspected. "
    "Ensure STIPUL_TOKEN_SECRET is not accessible to the agent process."
)


class SecretIsolationError(RuntimeError):
    """Raised when token secret isolation is violated."""


@dataclass(frozen=True)
class SecretIsolationResult:
    """Outcome of startup token secret isolation check."""

    verified: bool
    check_performed: bool
    source: str
    detected_keys: tuple[str, ...]


def _contains_token_secret_marker(env_key: str) -> bool:
    return _TOKEN_SECRET_MARKER in env_key.upper()


def _detected_secret_keys(env: Mapping[str, str]) -> list[str]:
    detected = [key for key in env if _contains_token_secret_marker(key)]
    return sorted(set(detected))


def _read_linux_proc_environ(agent_pid: int) -> dict[str, str]:
    proc_environ = Path(f"/proc/{agent_pid}/environ")
    raw = proc_environ.read_bytes()
    parsed: dict[str, str] = {}
    for entry in raw.split(b"\0"):
        if not entry or b"=" not in entry:
            continue
        key_raw, value_raw = entry.split(b"=", 1)
        key = key_raw.decode("utf-8", errors="replace")
        value = value_raw.decode("utf-8", errors="replace")
        parsed[key] = value
    return parsed


def _inspect_agent_environment(
    *,
    agent_pid: int | None,
    agent_env: Mapping[str, str] | None,
    inspect_current_process: bool,
) -> tuple[Mapping[str, str] | None, str]:
    source = _inspection_source(
        agent_pid=agent_pid,
        agent_env=agent_env,
        inspect_current_process=inspect_current_process,
    )
    if source == "agent_env":
        return dict(agent_env or {}), source

    if source == "proc":
        return _read_linux_proc_environ(cast(int, agent_pid)), source

    if source == "current_process":
        return dict(os.environ), source

    return None, source


def _inspection_source(
    *,
    agent_pid: int | None,
    agent_env: Mapping[str, str] | None,
    inspect_current_process: bool,
) -> str:
    if agent_env is not None:
        return "agent_env"

    if agent_pid is not None and sys.platform.startswith("linux"):
        return "proc"

    if inspect_current_process:
        return "current_process"

    return "no_target"


def check_secret_isolation(
    *,
    agent_pid: int | None = None,
    agent_env: Mapping[str, str] | None = None,
    inspect_current_process: bool = False,
    logger: logging.Logger | None = None,
) -> SecretIsolationResult:
    """
    Verify token secret is not visible to the agent runtime.

    Raises:
        SecretIsolationError: when token secret markers are detected in agent env.
    """
    active_logger = logger or logging.getLogger(__name__)
    inspection_source = _inspection_source(
        agent_pid=agent_pid,
        agent_env=agent_env,
        inspect_current_process=inspect_current_process,
    )

    try:
        environment, source = _inspect_agent_environment(
            agent_pid=agent_pid,
            agent_env=agent_env,
            inspect_current_process=inspect_current_process,
        )
    except Exception:
        active_logger.warning(_ISOLATION_UNVERIFIED_WARNING)
        return SecretIsolationResult(
            verified=False,
            check_performed=False,
            source=inspection_source,
            detected_keys=(),
        )

    if environment is None:
        active_logger.info(_ISOLATION_SKIPPED_INFO)
        return SecretIsolationResult(
            verified=False,
            check_performed=False,
            source=source,
            detected_keys=(),
        )

    detected_keys = _detected_secret_keys(environment)
    if detected_keys:
        active_logger.error(_FATAL_SECRET_MESSAGE)
        raise SecretIsolationError(_FATAL_SECRET_MESSAGE)

    return SecretIsolationResult(
        verified=True,
        check_performed=True,
        source=source,
        detected_keys=(),
    )
