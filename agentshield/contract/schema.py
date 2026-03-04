"""Contract schema parsing and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Mapping
from uuid import UUID

from agentshield.exceptions import ContractValidationError
from agentshield.models import RiskClass

_SUFFIX_HOST_RE = re.compile(
    r"^(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)
_EXACT_HOST_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _required(data: dict[str, Any], field: str) -> Any:
    if field not in data:
        raise ContractValidationError(f"Missing required field: {field}")
    return data[field]


def _parse_non_empty_str(field: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ContractValidationError(f"{field} must be a string")
    if value == "":
        raise ContractValidationError(f"{field} must not be empty")
    return value


def _parse_optional_str(field: str, value: Any) -> str | None:
    if value is None:
        return None
    return _parse_non_empty_str(field, value)


def _parse_uuid(field: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ContractValidationError(f"{field} must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ContractValidationError(f"{field} must be a valid UUID") from exc
    return str(parsed)


def _parse_optional_uuid(field: str, value: Any) -> str | None:
    if value is None:
        return None
    return _parse_uuid(field, value)


def _parse_utc_datetime(field: str, value: Any) -> datetime:
    if not isinstance(value, str):
        raise ContractValidationError(f"{field} must be an ISO 8601 string")
    if "T" not in value:
        raise ContractValidationError(
            f"{field} must use ISO 8601 datetime format with 'T' separator"
        )
    if not (value.endswith("Z") or value.endswith("+00:00")):
        raise ContractValidationError(f"{field} must end with 'Z' or '+00:00'")

    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError as exc:
        raise ContractValidationError(f"{field} must be a valid ISO 8601 datetime") from exc

    if parsed.tzinfo is None:
        raise ContractValidationError(f"{field} must be timezone-aware UTC datetime")
    if parsed.utcoffset() != timedelta(0):
        raise ContractValidationError(f"{field} must be UTC (+00:00)")

    return parsed.astimezone(timezone.utc)


def _parse_positive_int(field: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractValidationError(f"{field} must be an integer")
    if value <= 0:
        raise ContractValidationError(f"{field} must be > 0")
    return int(value)


def _parse_str_frozenset(field: str, value: Any) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ContractValidationError(f"{field} must be a list of strings")

    parsed: set[str] = set()
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            raise ContractValidationError(f"{field}[{idx}] must be a string")
        if item == "":
            raise ContractValidationError(f"{field}[{idx}] must not be empty")
        parsed.add(item)
    return frozenset(parsed)


def _validate_egress_host(entry: str) -> None:
    if any(ch.isspace() for ch in entry):
        raise ContractValidationError(
            f"egress_allowlist entry '{entry}' must not contain whitespace"
        )
    for bad in (":", "/", "?", "#", "*"):
        if bad in entry:
            raise ContractValidationError(
                f"egress_allowlist entry '{entry}' must not contain '{bad}'"
            )
    if ".." in entry:
        raise ContractValidationError(
            f"egress_allowlist entry '{entry}' must not contain consecutive dots"
        )
    if entry.endswith("."):
        raise ContractValidationError(
            f"egress_allowlist entry '{entry}' must not end with a dot"
        )
    if not (_EXACT_HOST_RE.fullmatch(entry) or _SUFFIX_HOST_RE.fullmatch(entry)):
        raise ContractValidationError(
            f"egress_allowlist entry '{entry}' must be an exact host or leading-dot suffix"
        )


def _parse_egress_allowlist(value: Any) -> frozenset[str]:
    parsed = _parse_str_frozenset("egress_allowlist", value)
    for entry in parsed:
        _validate_egress_host(entry)
    return parsed


def _parse_tool_risk_classes(value: Any) -> dict[str, RiskClass]:
    if not isinstance(value, dict):
        raise ContractValidationError("tool_risk_classes must be an object")

    parsed: dict[str, RiskClass] = {}
    for tool, risk in value.items():
        if not isinstance(tool, str):
            raise ContractValidationError("tool_risk_classes keys must be strings")
        if tool == "":
            raise ContractValidationError("tool_risk_classes keys must not be empty")

        if isinstance(risk, RiskClass):
            parsed_risk = risk
        elif isinstance(risk, str):
            try:
                parsed_risk = RiskClass(risk)
            except ValueError as exc:
                allowed = ", ".join(member.value for member in RiskClass)
                raise ContractValidationError(
                    f"tool_risk_classes['{tool}'] has unknown risk class '{risk}'. "
                    f"Expected one of: {allowed}"
                ) from exc
        else:
            raise ContractValidationError(
                f"tool_risk_classes['{tool}'] must be a RiskClass string"
            )

        parsed[tool] = parsed_risk
    return parsed


def _format_utc_z(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc)
    return utc_value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Contract:
    """Validated agent permission contract."""

    schema_version: str
    contract_id: str
    parent_contract_id: str | None
    created_at: datetime
    expires_at: datetime
    signed_by: str | None
    identity_agent_id: str
    identity_code_sha256: str | None
    allowed_tools: frozenset[str]
    never_allow_tools: frozenset[str]
    tool_risk_classes: Mapping[str, RiskClass]
    max_tool_calls: int
    max_net_calls: int
    egress_allowlist: frozenset[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Contract:
        """Parse and validate a contract payload."""
        if not isinstance(data, dict):
            raise ContractValidationError("Contract payload must be a dictionary")

        schema_version = _parse_non_empty_str(
            "schema_version", _required(data, "schema_version")
        )
        if schema_version != "1.0":
            raise ContractValidationError("schema_version must equal '1.0'")

        contract_id = _parse_uuid("contract_id", _required(data, "contract_id"))
        parent_contract_id = _parse_optional_uuid(
            "parent_contract_id", data.get("parent_contract_id")
        )

        created_at = _parse_utc_datetime("created_at", _required(data, "created_at"))
        expires_at = _parse_utc_datetime("expires_at", _required(data, "expires_at"))
        if expires_at <= created_at:
            raise ContractValidationError("expires_at must be strictly after created_at")

        signed_by = _parse_optional_str("signed_by", data.get("signed_by"))

        identity_agent_id = _parse_non_empty_str(
            "identity_agent_id", _required(data, "identity_agent_id")
        )

        identity_code_sha256 = _parse_optional_str(
            "identity_code_sha256", data.get("identity_code_sha256")
        )
        if identity_code_sha256 is not None and not _SHA256_HEX_RE.fullmatch(
            identity_code_sha256
        ):
            raise ContractValidationError(
                "identity_code_sha256 must be a 64-character hexadecimal SHA-256"
            )

        allowed_tools = _parse_str_frozenset(
            "allowed_tools", _required(data, "allowed_tools")
        )
        never_allow_tools = _parse_str_frozenset(
            "never_allow_tools", _required(data, "never_allow_tools")
        )

        tool_risk_classes = _parse_tool_risk_classes(
            _required(data, "tool_risk_classes")
        )
        for tool in allowed_tools:
            if tool not in tool_risk_classes:
                tool_risk_classes[tool] = RiskClass.WRITE

        max_tool_calls = _parse_positive_int(
            "max_tool_calls", _required(data, "max_tool_calls")
        )
        max_net_calls = _parse_positive_int(
            "max_net_calls", _required(data, "max_net_calls")
        )

        egress_allowlist = _parse_egress_allowlist(
            _required(data, "egress_allowlist")
        )

        return cls(
            schema_version=schema_version,
            contract_id=contract_id,
            parent_contract_id=parent_contract_id,
            created_at=created_at,
            expires_at=expires_at,
            signed_by=signed_by,
            identity_agent_id=identity_agent_id,
            identity_code_sha256=identity_code_sha256,
            allowed_tools=allowed_tools,
            never_allow_tools=never_allow_tools,
            tool_risk_classes=MappingProxyType(tool_risk_classes),
            max_tool_calls=max_tool_calls,
            max_net_calls=max_net_calls,
            egress_allowlist=egress_allowlist,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Return canonical signing payload with sorted keys."""
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "contract_id": self.contract_id,
            "created_at": _format_utc_z(self.created_at),
            "expires_at": _format_utc_z(self.expires_at),
            "identity_agent_id": self.identity_agent_id,
            "identity_code_sha256": self.identity_code_sha256,
            "allowed_tools": sorted(self.allowed_tools),
            "never_allow_tools": sorted(self.never_allow_tools),
            "tool_risk_classes": {
                tool: risk.value
                for tool, risk in sorted(self.tool_risk_classes.items(), key=lambda x: x[0])
            },
            "max_tool_calls": self.max_tool_calls,
            "max_net_calls": self.max_net_calls,
            "egress_allowlist": sorted(self.egress_allowlist),
        }

        return {key: payload[key] for key in sorted(payload) if payload[key] is not None}
