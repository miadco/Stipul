"""Multi-layer contract orchestration built on the existing merge engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from stipul.charter.contract.loader import load_charter
from stipul.charter.contract.merge import RISK_SEVERITY, merge
from stipul.charter.contract.schema import Contract
from stipul.exceptions import ContractMergeViolation

_LEVEL_ORDER: dict[str, int] = {
    "base": 0,
    "org": 1,
    "env": 2,
    "agent": 3,
    "session": 4,
}


@dataclass(frozen=True)
class ContractLayer:
    level: Literal["base", "org", "env", "agent", "session"]
    contract: Contract
    source: str


@dataclass(frozen=True)
class ResolvedContract:
    effective: Contract
    layers: list[ContractLayer]
    merge_log: list[str]


class ContractInheritanceError(Exception):
    """Raised when multi-layer contract resolution fails."""


class InheritanceResolver:
    """Resolve an ordered set of contract layers into one effective contract."""

    def resolve(self, layers: list[ContractLayer]) -> ResolvedContract:
        if not layers:
            raise ContractInheritanceError("layers must not be empty")
        self._validate_layer_order(layers)

        effective = layers[0].contract
        merge_log: list[str] = []

        for layer in layers[1:]:
            parent = effective
            try:
                effective = merge(parent, layer.contract)
            except ContractMergeViolation as exc:
                raise ContractInheritanceError(str(exc)) from exc
            merge_log.extend(self._describe_step(parent, effective, layer))

        return ResolvedContract(
            effective=effective,
            layers=list(layers),
            merge_log=merge_log,
        )

    def load_layers(
        self,
        base_path: str | Path | None = None,
        org_path: str | Path | None = None,
        env_path: str | Path | None = None,
        agent_path: str | Path | None = None,
        session_path: str | Path | None = None,
    ) -> list[ContractLayer]:
        specs = [
            ("base", base_path),
            ("org", org_path),
            ("env", env_path),
            ("agent", agent_path),
            ("session", session_path),
        ]
        layers: list[ContractLayer] = []
        for level, raw_path in specs:
            if raw_path is None:
                continue
            path = Path(raw_path)
            layers.append(
                ContractLayer(
                    level=level,  # type: ignore[arg-type]
                    contract=load_charter(path).contract,
                    source=str(path),
                )
            )
        return layers

    def show_effective(self, resolved: ResolvedContract) -> str:
        lines = ["Effective Contract"]
        lines.append("Layers:")
        for layer in resolved.layers:
            lines.append(f"- {layer.level}: {layer.source}")
        lines.append("Merge log:")
        if resolved.merge_log:
            lines.extend(f"- {entry}" for entry in resolved.merge_log)
        else:
            lines.append("- no merge steps")
        lines.append("Contract:")
        lines.append(json.dumps(resolved.effective.to_canonical_dict(), indent=2, sort_keys=True))
        return "\n".join(lines)

    @staticmethod
    def _validate_layer_order(layers: list[ContractLayer]) -> None:
        last_rank = -1
        for layer in layers:
            rank = _LEVEL_ORDER.get(layer.level)
            if rank is None:
                raise ContractInheritanceError(f"unknown layer level '{layer.level}'")
            if rank <= last_rank:
                raise ContractInheritanceError(
                    "layers must be strictly ordered as base < org < env < agent < session"
                )
            last_rank = rank

    @staticmethod
    def _describe_step(parent: Contract, merged: Contract, layer: ContractLayer) -> list[str]:
        entries: list[str] = []
        prefix = f"{layer.level} ({layer.source})"

        removed_tools = sorted(parent.allowed_tools - merged.allowed_tools)
        if removed_tools:
            entries.append(f"{prefix}: allowed_tools reduced by {removed_tools}")

        added_prohibitions = sorted(merged.never_allow_tools - parent.never_allow_tools)
        if added_prohibitions:
            entries.append(f"{prefix}: never_allow_tools added {added_prohibitions}")

        removed_egress = sorted(parent.egress_allowlist - merged.egress_allowlist)
        if removed_egress:
            entries.append(f"{prefix}: egress_allowlist reduced by {removed_egress}")

        if merged.max_tool_calls != parent.max_tool_calls:
            entries.append(
                f"{prefix}: max_tool_calls tightened from {parent.max_tool_calls} to {merged.max_tool_calls}"
            )
        if merged.max_net_calls != parent.max_net_calls:
            entries.append(
                f"{prefix}: max_net_calls tightened from {parent.max_net_calls} to {merged.max_net_calls}"
            )
        if merged.expires_at != parent.expires_at:
            entries.append(
                f"{prefix}: expires_at tightened from {parent.expires_at.isoformat()} to {merged.expires_at.isoformat()}"
            )
        if merged.created_at != parent.created_at:
            entries.append(
                f"{prefix}: created_at advanced from {parent.created_at.isoformat()} to {merged.created_at.isoformat()}"
            )

        for tool in sorted(set(parent.tool_risk_classes) & set(merged.tool_risk_classes)):
            parent_risk = parent.tool_risk_classes[tool]
            merged_risk = merged.tool_risk_classes[tool]
            if RISK_SEVERITY[merged_risk] > RISK_SEVERITY[parent_risk]:
                entries.append(
                    f"{prefix}: risk for {tool} escalated from {parent_risk.value} to {merged_risk.value}"
                )

        if not entries:
            entries.append(f"{prefix}: no material restriction changes")
        return entries


__all__ = [
    "ContractInheritanceError",
    "ContractLayer",
    "InheritanceResolver",
    "ResolvedContract",
]
