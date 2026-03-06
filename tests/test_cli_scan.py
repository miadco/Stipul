from __future__ import annotations

import argparse
import json
from pathlib import Path

from stipul.cli import scan_cmd


def _build_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (repo / "runner.py").write_text(
        "import subprocess\n"
        "def run(cmd: str) -> None:\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    return repo


def _build_high_only_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo_high"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (repo / "wrapper_handler.py").write_text(
        "def handle(headers: dict[str, str]) -> str:\n"
        '    token = headers["Authorization"]\n'
        "    return token\n",
        encoding="utf-8",
    )
    return repo


def test_cli_scan_writes_json_and_fails_on_threshold(tmp_path: Path, capsys) -> None:
    repo = _build_repo(tmp_path)
    json_out = tmp_path / "scan.json"
    args = argparse.Namespace(
        path=str(repo),
        json_out=str(json_out),
        fail_on="high",
        max_file_bytes=512_000,
    )

    exit_code = scan_cmd.run(args)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Scan target:" in captured.out
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scanner_version"] == "1"
    assert payload["summary"]["critical"] == 1


def test_cli_scan_returns_zero_when_threshold_not_met(tmp_path: Path, capsys) -> None:
    repo = _build_high_only_repo(tmp_path)
    args = argparse.Namespace(
        path=str(repo),
        json_out=None,
        fail_on="critical",
        max_file_bytes=512_000,
    )

    exit_code = scan_cmd.run(args)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "AS-SCAN-003" in captured.out
