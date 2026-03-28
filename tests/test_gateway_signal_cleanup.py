from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from importlib.resources import as_file, files
from pathlib import Path

import pytest

from tests.cli_support import DEFAULT_SESSION_ID, REPO_ROOT


def _read_events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _process_logs(stdout_path: Path, stderr_path: Path) -> tuple[str, str]:
    stdout = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
    stderr = stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""
    return stdout, stderr


def _wait_for_session_open(
    process: subprocess.Popen[bytes],
    events_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = _process_logs(stdout_path, stderr_path)
            pytest.fail(
                "gateway exited before session_open was persisted\n"
                f"returncode={process.returncode}\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}"
            )
        if events_path.exists():
            events = _read_events(events_path)
            if events and events[0].get("event_type") == "session_open":
                return
        time.sleep(0.05)
    stdout, stderr = _process_logs(stdout_path, stderr_path)
    pytest.fail(
        "timed out waiting for session_open event\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}"
    )


def test_gateway_sigterm_emits_session_close_and_writes_seal(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    events_path = session_dir / "events.jsonl"
    seal_file = session_dir / "seal.json"
    stdout_path = tmp_path / "gateway.stdout"
    stderr_path = tmp_path / "gateway.stderr"
    env = os.environ.copy()
    env["HOME"] = str(tmp_path / "home")
    env["STIPUL_TOKEN_SECRET"] = "test-secret"

    with as_file(files("stipul.demo").joinpath("demo_charter.yaml")) as contract_path:
        with (
            stdout_path.open("w", encoding="utf-8") as stdout_handle,
            stderr_path.open("w", encoding="utf-8") as stderr_handle,
        ):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "stipul.cli.main",
                    "gateway",
                    "mcp",
                    "--contract",
                    str(contract_path),
                    "--session-dir",
                    str(session_dir),
                    "--session-id",
                    DEFAULT_SESSION_ID,
                    "--runtime",
                    "stipul.examples.demo_runtime:build_runtime",
                ],
                cwd=REPO_ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=stdout_handle,
                stderr=stderr_handle,
            )

            try:
                _wait_for_session_open(process, events_path, stdout_path, stderr_path)
                time.sleep(2.0)
                if process.poll() is not None:
                    stdout, stderr = _process_logs(stdout_path, stderr_path)
                    pytest.fail(
                        "gateway exited before SIGTERM was sent\n"
                        f"returncode={process.returncode}\n"
                        f"stdout:\n{stdout}\n"
                        f"stderr:\n{stderr}"
                    )
                process.send_signal(signal.SIGTERM)
                if process.stdin is not None:
                    process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
                    stdout, stderr = _process_logs(stdout_path, stderr_path)
                    pytest.fail(
                        "gateway did not exit after SIGTERM\n"
                        f"stdout:\n{stdout}\n"
                        f"stderr:\n{stderr}"
                    )
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=1)

    stdout, stderr = _process_logs(stdout_path, stderr_path)
    events = _read_events(events_path)

    assert events[-1]["event_type"] == "session_close", stdout + stderr
    assert seal_file.exists(), stderr
