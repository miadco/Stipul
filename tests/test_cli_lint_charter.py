from __future__ import annotations

import json
from pathlib import Path

from tests.cli_support import load_base_charter_dict, run_cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _write_contract(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_cli_lint_charter_success_with_warnings(tmp_path: Path) -> None:
    result = run_cli(
        "lint-charter",
        "--charter",
        str(FIXTURES_DIR / "base_charter.yaml"),
    )

    assert result.returncode == 0
    assert "Errors: 0" in result.stdout
    assert "WARN implicit_risk_defaults" in result.stdout


def test_cli_lint_charter_returns_error_exit_for_no_policy(tmp_path: Path) -> None:
    payload = load_base_charter_dict()
    payload["allowed_tools"] = []
    payload["never_allow_tools"] = []
    payload["tool_risk_classes"] = {}
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, payload)

    result = run_cli("lint-charter", "--charter", str(contract_path))

    assert result.returncode == 1
    assert "ERROR no_policy_defined" in result.stdout


def test_cli_lint_charter_returns_fatal_for_schema_invalid_payload(tmp_path: Path) -> None:
    payload = load_base_charter_dict()
    payload["expires_at"] = payload["created_at"]
    contract_path = tmp_path / "contract.json"
    _write_contract(contract_path, payload)

    result = run_cli("lint-charter", "--charter", str(contract_path))

    assert result.returncode == 3
    assert "expires_at must be strictly after created_at" in result.stderr


def test_cli_lint_charter_returns_fatal_for_invalid_yaml(tmp_path: Path) -> None:
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text("allowed_tools: [web.search\n", encoding="utf-8")

    result = run_cli("lint-charter", "--charter", str(contract_path))

    assert result.returncode == 3
    assert "Invalid YAML" in result.stderr
