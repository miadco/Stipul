"""Shared Charter file loading for JSON and YAML policy files."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import yaml

from stipul.charter.contract.schema import Contract


@dataclass(frozen=True)
class LoadedCharter:
    """Raw and normalized Charter loaded from disk."""

    path: Path
    payload: dict[str, Any]
    contract: Contract


def load_charter(path: str | Path) -> LoadedCharter:
    """Load a Charter file and normalize it into the canonical Contract model."""
    charter_path = Path(path)
    payload = load_charter_payload(charter_path)
    return LoadedCharter(
        path=charter_path,
        payload=payload,
        contract=Contract.from_dict(payload),
    )


def load_charter_payload(path: str | Path) -> dict[str, Any]:
    """Load raw Charter payload data from JSON or YAML."""
    charter_path = Path(path)
    suffix = charter_path.suffix.lower()

    try:
        raw_text = charter_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Contract file not found: {charter_path}") from exc

    try:
        if suffix == ".json":
            payload = json.loads(raw_text)
        elif suffix in {".yaml", ".yml"}:
            payload = yaml.safe_load(raw_text)
        else:
            raise ValueError(
                f"Unsupported contract file extension for {charter_path}: "
                "expected .json, .yaml, or .yml"
            )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {charter_path}: line {exc.lineno} column {exc.colno}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {charter_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Contract file must contain a top-level object: {charter_path}")
    return payload


__all__ = ["LoadedCharter", "load_charter", "load_charter_payload"]
