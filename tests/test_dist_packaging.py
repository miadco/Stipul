from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.cli_support import REPO_ROOT


def test_built_wheel_and_sdist_install_and_expose_cli(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    env = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_CACHE_DIR": str(tmp_path / "pip-cache"),
    }

    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    wheel_path = next(dist_dir.glob("*.whl"))
    sdist_path = next(dist_dir.glob("*.tar.gz"))

    _assert_artifact_smoke(tmp_path, env, wheel_path, "wheel-venv")
    _assert_artifact_smoke(tmp_path, env, sdist_path, "sdist-venv")


def test_built_wheel_top_level_help_runs_in_isolated_no_deps_venv(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    env = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_CACHE_DIR": str(tmp_path / "pip-cache"),
    }

    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    wheel_path = next(dist_dir.glob("*.whl"))
    venv_dir = tmp_path / "isolated-wheel-venv"

    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    python_bin = venv_dir / "bin" / "python"
    stipul_bin = venv_dir / "bin" / "stipul"

    subprocess.run(
        [
            str(python_bin),
            "-m",
            "pip",
            "install",
            "--no-deps",
            str(wheel_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    result = subprocess.run(
        [str(stipul_bin), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0
    assert "usage: stipul" in result.stdout
    assert "history" in result.stdout


def _assert_artifact_smoke(
    tmp_path: Path,
    env: dict[str, str],
    artifact_path: Path,
    env_name: str,
) -> None:
    venv_dir = tmp_path / env_name
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
            str(artifact_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    for args in (
        [str(agentshield_bin), "--help"],
        [str(agentshield_bin), "verify", "--help"],
        [str(agentshield_bin), "scan", "--help"],
    ):
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "usage: stipul" in result.stdout

    version_result = subprocess.run(
        [str(python_bin), "-c", "import stipul; print(stipul.__version__)"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert version_result.returncode == 0
    assert version_result.stdout.strip() == "0.2.1"
