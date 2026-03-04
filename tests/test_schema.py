from datetime import datetime, timedelta, timezone

import pytest

from agentshield.contract.schema import Contract
from agentshield.exceptions import ContractValidationError
from agentshield.models import RiskClass


def test_valid_fixture_loads(base_dict):
    Contract.from_dict(base_dict)


def test_schema_version_rejected(base_dict):
    base_dict["schema_version"] = "2.0"
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_invalid_uuid_rejected(base_dict):
    base_dict["contract_id"] = "not-a-uuid"
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_expires_before_created_rejected(base_dict):
    created_at = datetime.fromisoformat(base_dict["created_at"].replace("Z", "+00:00"))
    expires_at = created_at - timedelta(seconds=1)
    base_dict["expires_at"] = expires_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_egress_entry_with_port_rejected(base_dict):
    egress = list(base_dict["egress_allowlist"])
    egress.append("api.example.com:443")
    base_dict["egress_allowlist"] = egress
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_egress_entry_with_scheme_rejected(base_dict):
    egress = list(base_dict["egress_allowlist"])
    egress.append("https://api.example.com")
    base_dict["egress_allowlist"] = egress
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_unknown_risk_class_rejected(base_dict):
    tool = next(iter(base_dict["tool_risk_classes"]))
    base_dict["tool_risk_classes"][tool] = "nuclear"
    with pytest.raises(ContractValidationError):
        Contract.from_dict(base_dict)


def test_default_write_risk_applied(base_dict, contract):
    tool = next(iter(set(contract.allowed_tools) & set(contract.tool_risk_classes)))
    base_dict["tool_risk_classes"].pop(tool, None)
    parsed = Contract.from_dict(base_dict)
    assert parsed.tool_risk_classes[tool] == RiskClass.write


def test_canonical_dict_excludes_nulls_and_signing_fields(base_dict):
    base_dict["parent_contract_id"] = None
    base_dict["signed_by"] = None
    parsed = Contract.from_dict(base_dict)
    canonical = parsed.to_canonical_dict()
    assert "parent_contract_id" not in canonical
    assert "signed_by" not in canonical
    assert all(value is not None for value in canonical.values())
