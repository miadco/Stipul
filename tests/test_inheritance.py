from __future__ import annotations

import copy
import uuid
from pathlib import Path

import pytest
import yaml

from stipul.charter.contract.inheritance import (
    ContractInheritanceError,
    ContractLayer,
    InheritanceResolver,
)
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.templates import (
    admin_agent_template,
    read_only_agent_template,
    sandbox_dev_template,
    web_search_agent_template,
    write_capable_agent_template,
)


def _child_dict(base_dict: dict, **overrides) -> dict:
    payload = copy.deepcopy(base_dict)
    payload["contract_id"] = str(uuid.uuid4())
    for key, value in overrides.items():
        payload[key] = value
    return payload


def _layer(level: str, payload: dict, source: str) -> ContractLayer:
    return ContractLayer(level=level, contract=Contract.from_dict(payload), source=source)  # type: ignore[arg-type]


def test_resolve_single_layer_returns_same_effective_contract(contract):
    resolver = InheritanceResolver()
    resolved = resolver.resolve([ContractLayer(level="base", contract=contract, source="base.json")])

    assert resolved.effective == contract
    assert resolved.merge_log == []
    assert resolved.layers[0].source == "base.json"


def test_resolve_multi_layer_applies_restrictions(base_dict):
    resolver = InheritanceResolver()
    org_payload = _child_dict(
        base_dict,
        allowed_tools=["web.search"],
        never_allow_tools=["dangerous.api", "shell.exec"],
        egress_allowlist=["api.example.com"],
        max_tool_calls=5,
        max_net_calls=3,
        expires_at="2090-01-01T00:00:00Z",
        tool_risk_classes={"web.search": "write"},
    )
    env_payload = _child_dict(
        org_payload,
        allowed_tools=["web.search"],
        never_allow_tools=["dangerous.api", "shell.exec", "filesystem.write"],
        egress_allowlist=["api.example.com"],
        max_tool_calls=4,
        max_net_calls=2,
        expires_at="2080-01-01T00:00:00Z",
        tool_risk_classes={"web.search": "irreversible"},
    )

    resolved = resolver.resolve(
        [
            _layer("base", base_dict, "base.json"),
            _layer("org", org_payload, "org.json"),
            _layer("env", env_payload, "env.json"),
        ]
    )

    assert resolved.effective.allowed_tools == frozenset({"web.search"})
    assert resolved.effective.never_allow_tools == frozenset(
        {"shell.exec", "dangerous.api", "filesystem.write"}
    )
    assert resolved.effective.egress_allowlist == frozenset({"api.example.com"})
    assert resolved.effective.max_tool_calls == 4
    assert resolved.effective.max_net_calls == 2
    assert resolved.effective.expires_at.isoformat().startswith("2080-01-01T00:00:00")
    assert resolved.effective.tool_risk_classes["web.search"].value == "irreversible"
    assert any("allowed_tools reduced" in entry for entry in resolved.merge_log)
    assert any("never_allow_tools added" in entry for entry in resolved.merge_log)
    assert any("risk for web.search escalated" in entry for entry in resolved.merge_log)


def test_resolve_out_of_order_layers_raises(contract):
    resolver = InheritanceResolver()

    with pytest.raises(ContractInheritanceError, match="strictly ordered"):
        resolver.resolve(
            [
                ContractLayer(level="agent", contract=contract, source="agent.json"),
                ContractLayer(level="org", contract=contract, source="org.json"),
            ]
        )


def test_expansion_attempt_raises_contract_inheritance_error(base_dict):
    resolver = InheritanceResolver()
    child_payload = _child_dict(
        base_dict,
        allowed_tools=["filesystem.write", "web.search", "new.tool"],
        tool_risk_classes={"web.search": "read", "new.tool": "write"},
    )

    with pytest.raises(ContractInheritanceError, match="allowed_tools"):
        resolver.resolve(
            [
                _layer("base", base_dict, "base.json"),
                _layer("org", child_payload, "org.json"),
            ]
        )


def test_identity_mismatch_raises_contract_inheritance_error(base_dict):
    resolver = InheritanceResolver()
    child_payload = _child_dict(base_dict, identity_agent_id="agent.beta")

    with pytest.raises(ContractInheritanceError, match="identity"):
        resolver.resolve(
            [
                _layer("base", base_dict, "base.json"),
                _layer("org", child_payload, "org.json"),
            ]
        )


def test_load_layers_respects_order_and_skips_none(tmp_path: Path, base_dict):
    resolver = InheritanceResolver()
    base_path = tmp_path / "base.yaml"
    session_path = tmp_path / "session.yaml"
    base_path.write_text(yaml.safe_dump(base_dict, sort_keys=False), encoding="utf-8")
    session_path.write_text(
        yaml.safe_dump(_child_dict(base_dict, allowed_tools=["web.search"]), sort_keys=False),
        encoding="utf-8",
    )

    layers = resolver.load_layers(base_path=base_path, session_path=session_path)

    assert [layer.level for layer in layers] == ["base", "session"]
    assert layers[0].source == str(base_path)
    assert layers[1].source == str(session_path)


def test_show_effective_includes_layers_and_contract_json(contract):
    resolver = InheritanceResolver()
    resolved = resolver.resolve([ContractLayer(level="base", contract=contract, source="base.json")])

    text = resolver.show_effective(resolved)

    assert "Layers:" in text
    assert "base.json" in text
    assert '"contract_id"' in text


@pytest.mark.parametrize(
    "builder, kwargs",
    [
        (
            read_only_agent_template,
            {
                "identity_agent_id": "agent.alpha",
                "tools": ["web.search"],
                "egress_allowlist": ["api.example.com"],
            },
        ),
        (
            web_search_agent_template,
            {
                "identity_agent_id": "agent.alpha",
                "search_tools": ["web.search"],
                "egress_allowlist": ["api.example.com"],
            },
        ),
        (
            write_capable_agent_template,
            {
                "identity_agent_id": "agent.alpha",
                "read_tools": ["web.search"],
                "write_tools": ["filesystem.write"],
                "egress_allowlist": ["api.example.com"],
            },
        ),
        (
            admin_agent_template,
            {
                "identity_agent_id": "agent.alpha",
                "all_tools": ["web.search", "filesystem.write"],
                "egress_allowlist": ["api.example.com"],
            },
        ),
        (
            sandbox_dev_template,
            {
                "identity_agent_id": "agent.alpha",
                "all_tools": ["web.search", "filesystem.write"],
                "egress_allowlist": ["api.example.com"],
            },
        ),
    ],
)
def test_templates_produce_valid_contracts(builder, kwargs):
    payload = builder(
        **kwargs,
        created_at_iso="2026-01-01T00:00:00Z",
        expires_at_iso="2026-12-31T00:00:00Z",
    )

    contract = Contract.from_dict(payload)

    assert contract.identity_agent_id == "agent.alpha"
