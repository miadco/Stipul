from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.cli_support import REPO_ROOT


def test_console_script_installs_and_runs_in_isolated_venv(tmp_path: Path) -> None:
    venv_dir = tmp_path / "venv"
    env = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"}

    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    python_bin = venv_dir / "bin" / "python"
    agentshield_bin = venv_dir / "bin" / "stipul"

    subprocess.run(
        [
            str(python_bin),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-build-isolation",
            "-e",
            str(REPO_ROOT),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    result = subprocess.run(
        [str(agentshield_bin), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0
    assert "usage: stipul" in result.stdout
    assert "verify" in result.stdout
    assert "scan" in result.stdout

    version_result = subprocess.run(
        [str(python_bin), "-c", "import stipul; print(stipul.__version__)"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert version_result.returncode == 0
    assert version_result.stdout.strip() == "0.1.1"
