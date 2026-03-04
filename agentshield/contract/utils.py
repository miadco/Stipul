"""Contract canonicalization and hashing utilities."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any, cast

from agentshield.contract.schema import Contract
from agentshield.utils.canonical import canonical_json_bytes


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        # Rebuild dict with lexicographically ordered keys and recursively canonicalized values.
        return {key: _canonicalize(value[key]) for key in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    return value


def canonical_dict(contract: dict[str, Any]) -> dict[str, Any]:
    """
    Return a canonical contract dictionary.

    Canonicalization recursively sorts dictionary keys and applies Unicode NFC
    normalization to all string values. The input dictionary is never mutated.
    """
    if not isinstance(contract, dict):
        raise TypeError("contract must be a dictionary")
    canonical = _canonicalize(contract)
    if not isinstance(canonical, dict):
        raise TypeError("canonical contract must be an object")
    return cast(dict[str, Any], canonical)


def compute_contract_hash(contract: Contract) -> str:
    """
    Compute canonical SHA-256 contract hash from a validated Contract instance.

    Caller constraint: the canonical payload must come from
    `Contract.to_canonical_dict()` only. Callers should never pass raw JSON
    payloads or ad-hoc dictionaries directly into hashing.
    """
    if not isinstance(contract, Contract):
        raise TypeError("compute_contract_hash expects a Contract instance")

    canonical = canonical_dict(contract.to_canonical_dict())
    return hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()
