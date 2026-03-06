"""Contract template helpers that emit schema-valid dictionaries."""

from __future__ import annotations

from typing import Any
from uuid import uuid4


def _base_template(
    *,
    template_name: str,
    identity_agent_id: str,
    created_at_iso: str,
    expires_at_iso: str,
    allowed_tools: list[str],
    never_allow_tools: list[str],
    tool_risk_classes: dict[str, str],
    egress_allowlist: list[str],
    max_tool_calls: int,
    max_net_calls: int,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "contract_id": str(uuid4()),
        "parent_contract_id": None,
        "created_at": created_at_iso,
        "expires_at": expires_at_iso,
        "signed_by": f"template:{template_name}",
        "identity_agent_id": identity_agent_id,
        "identity_code_sha256": None,
        "allowed_tools": sorted(set(allowed_tools)),
        "never_allow_tools": sorted(set(never_allow_tools)),
        "tool_risk_classes": {
            tool: tool_risk_classes[tool]
            for tool in sorted(tool_risk_classes)
        },
        "max_tool_calls": int(max_tool_calls),
        "max_net_calls": int(max_net_calls),
        "egress_allowlist": sorted(set(egress_allowlist)),
    }


def _classify_tool(tool_name: str) -> str:
    lower = tool_name.lower()
    if any(token in lower for token in ("http", "web", "fetch", "download", "curl", "request")):
        return "exfil_risk"
    if any(token in lower for token in ("delete", "drop", "deploy", "exec", "apply", "write", "commit")):
        return "irreversible"
    return "write"


def read_only_agent_template(
    identity_agent_id: str,
    tools: list[str],
    egress_allowlist: list[str],
    *,
    created_at_iso: str,
    expires_at_iso: str,
) -> dict[str, Any]:
    return _base_template(
        template_name="read_only_agent",
        identity_agent_id=identity_agent_id,
        created_at_iso=created_at_iso,
        expires_at_iso=expires_at_iso,
        allowed_tools=tools,
        never_allow_tools=["shell.exec"],
        tool_risk_classes={tool: "read" for tool in tools},
        egress_allowlist=egress_allowlist,
        max_tool_calls=25,
        max_net_calls=10,
    )


def web_search_agent_template(
    identity_agent_id: str,
    search_tools: list[str],
    egress_allowlist: list[str],
    *,
    created_at_iso: str,
    expires_at_iso: str,
) -> dict[str, Any]:
    return _base_template(
        template_name="web_search_agent",
        identity_agent_id=identity_agent_id,
        created_at_iso=created_at_iso,
        expires_at_iso=expires_at_iso,
        allowed_tools=search_tools,
        never_allow_tools=["shell.exec", "filesystem.write"],
        tool_risk_classes={tool: "read" for tool in search_tools},
        egress_allowlist=egress_allowlist,
        max_tool_calls=50,
        max_net_calls=20,
    )


def write_capable_agent_template(
    identity_agent_id: str,
    read_tools: list[str],
    write_tools: list[str],
    egress_allowlist: list[str],
    *,
    created_at_iso: str,
    expires_at_iso: str,
) -> dict[str, Any]:
    tool_risk_classes = {tool: "read" for tool in read_tools}
    tool_risk_classes.update({tool: "write" for tool in write_tools})
    return _base_template(
        template_name="write_capable_agent",
        identity_agent_id=identity_agent_id,
        created_at_iso=created_at_iso,
        expires_at_iso=expires_at_iso,
        allowed_tools=read_tools + write_tools,
        never_allow_tools=["shell.exec"],
        tool_risk_classes=tool_risk_classes,
        egress_allowlist=egress_allowlist,
        max_tool_calls=75,
        max_net_calls=25,
    )


def admin_agent_template(
    identity_agent_id: str,
    all_tools: list[str],
    egress_allowlist: list[str],
    *,
    created_at_iso: str,
    expires_at_iso: str,
) -> dict[str, Any]:
    return _base_template(
        template_name="admin_agent",
        identity_agent_id=identity_agent_id,
        created_at_iso=created_at_iso,
        expires_at_iso=expires_at_iso,
        allowed_tools=all_tools,
        never_allow_tools=["shell.exec"],
        tool_risk_classes={tool: _classify_tool(tool) for tool in all_tools},
        egress_allowlist=egress_allowlist,
        max_tool_calls=200,
        max_net_calls=100,
    )


def sandbox_dev_template(
    identity_agent_id: str,
    all_tools: list[str],
    egress_allowlist: list[str],
    *,
    created_at_iso: str,
    expires_at_iso: str,
) -> dict[str, Any]:
    return _base_template(
        template_name="sandbox_dev",
        identity_agent_id=identity_agent_id,
        created_at_iso=created_at_iso,
        expires_at_iso=expires_at_iso,
        allowed_tools=all_tools,
        never_allow_tools=["shell.exec"],
        tool_risk_classes={tool: _classify_tool(tool) for tool in all_tools},
        egress_allowlist=egress_allowlist,
        max_tool_calls=150,
        max_net_calls=75,
    )


__all__ = [
    "admin_agent_template",
    "read_only_agent_template",
    "sandbox_dev_template",
    "web_search_agent_template",
    "write_capable_agent_template",
]
