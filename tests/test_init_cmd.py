from __future__ import annotations

import yaml
from tests.cli_support import run_cli


def test_init_writes_starter_charter(tmp_path):
    output = tmp_path / "charter.yaml"
    result = run_cli("init", "--output", str(output))
    assert result.returncode == 0
    assert output.exists()
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert "filesystem.read" in data["allowed_tools"]
    assert "shell.exec" in data["never_allow_tools"]
    assert "Wrote starter charter" in result.stdout


def test_init_default_filename_is_charter_yaml(tmp_path):
    output = tmp_path / "charter.yaml"
    result = run_cli("init", "--output", str(output))
    assert result.returncode == 0
    assert output.name == "charter.yaml"


def test_init_refuses_overwrite_without_force(tmp_path):
    output = tmp_path / "charter.yaml"
    output.write_text("existing content", encoding="utf-8")
    result = run_cli("init", "--output", str(output))
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "already exists" in combined


def test_init_force_overwrites(tmp_path):
    output = tmp_path / "charter.yaml"
    output.write_text("existing content", encoding="utf-8")
    result = run_cli("init", "--output", str(output), "--force")
    assert result.returncode == 0
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
