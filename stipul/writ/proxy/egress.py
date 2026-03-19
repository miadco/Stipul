"""Egress Guard checks.

Egress enforcement applies only when a tool call explicitly declares an
``egress_target`` field in its input. The MCP Proxy cannot observe or block
arbitrary outbound network calls made directly by the agent process.
"""

from __future__ import annotations

from stipul.charter.contract.schema import Contract


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def check_egress(destination: str, contract: Contract) -> tuple[bool, str]:
    """Allow if destination matches or is a subdomain of an allowlisted domain."""
    if not isinstance(destination, str) or not destination.strip():
        return False, "not_in_egress_allowlist"

    normalized_destination = _normalize_host(destination)
    for entry in contract.egress_allowlist:
        normalized_entry = _normalize_host(entry)
        if normalized_entry.startswith("."):
            normalized_entry = normalized_entry[1:]

        if (
            normalized_destination == normalized_entry
            or normalized_destination.endswith(f".{normalized_entry}")
        ):
            return True, "allowed"

    return False, "not_in_egress_allowlist"
