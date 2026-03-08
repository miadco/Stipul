from __future__ import annotations

from pathlib import Path

import pytest

from stipul.charter.contract.loader import load_charter
from stipul.writ.proxy.server import ProxyServer
from stipul.writ.proxy.server import load_contract


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_load_charter_yaml_matches_json_fixture() -> None:
    loaded_yaml = load_charter(FIXTURES_DIR / "base_contract.yaml")
    loaded_json = load_charter(FIXTURES_DIR / "base_contract.json")

    assert loaded_yaml.payload["schema_version"] == "1.0"
    assert loaded_yaml.contract.to_canonical_dict() == loaded_json.contract.to_canonical_dict()


def test_load_charter_invalid_yaml_raises_value_error(tmp_path: Path) -> None:
    path = tmp_path / "broken_contract.yaml"
    path.write_text("allowed_tools: [web.search\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid YAML"):
        load_charter(path)


def test_proxy_load_contract_supports_yaml() -> None:
    contract = load_contract(FIXTURES_DIR / "base_contract.yaml")

    assert contract.identity_agent_id == "agent.alpha"
    assert "filesystem.write" in contract.allowed_tools


def test_proxy_from_contract_path_supports_yaml(tmp_path: Path) -> None:
    proxy = ProxyServer.from_contract_path(
        FIXTURES_DIR / "base_contract.yaml",
        session_id="yaml-session",
        events_path=tmp_path / "events.jsonl",
    )
    try:
        assert proxy.contract.identity_agent_id == "agent.alpha"
        assert proxy.contract.contract_id == "2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f"
    finally:
        proxy.close()
