from __future__ import annotations

import base64
import hashlib
import json
import stat
import unicodedata
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import canonical_dict, compute_contract_hash
from stipul.writ.proxy.session_head import read_session_head, write_session_head
from stipul.chronicle.signing import signer as signer_module
from stipul.chronicle.signing import verifier as verifier_module
from stipul.chronicle.signing.keys import (
    KeyMetadataError,
    generate_keypair,
    get_key_id,
    load_key,
    load_or_create_keypair,
    rotate_key,
)
from stipul.chronicle.signing.signer import sign_event
from stipul.utils.canonical import canonical_event_payload, canonical_json_bytes, compute_prev_hash


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _public_raw_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _sample_event(signature: str | None = None) -> dict:
    payload = {
        "sequence_id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "session_id": "11111111-1111-1111-1111-111111111111",
        "event_type": "tool_call",
        "tool_name": "filesystem.write",
        "risk_class": "write",
        "decision": "allow",
        "reason": "risk_class",
        "contract_id": "22222222-2222-2222-2222-222222222222",
        "contract_hash": "a" * 64,
        "agent_identity": "b" * 64,
        "input_hash": "c" * 64,
        "key_id": "deadbeef",
        "algorithm": "ed25519",
        "key_created_at": "2026-01-01T00:00:00Z",
        "prev_hash": "d" * 64,
    }
    if signature is not None:
        payload["signature"] = signature
    return payload


def test_generate_keypair_sets_secure_permissions_and_sidecar(tmp_path: Path) -> None:
    keys_dir = tmp_path / ".stipul" / "keys"
    keypair = generate_keypair(keys_dir)

    assert keys_dir.exists()
    assert _mode(keys_dir) == 0o700
    assert keypair.private_key_path.exists()
    assert _mode(keypair.private_key_path) == 0o600
    assert keypair.public_key_path.exists()
    assert keypair.metadata_path.exists()
    assert keypair.metadata_path.name == f"runtime_{keypair.key_id}.meta.json"
    assert _mode(keypair.metadata_path) == 0o600
    assert len(keypair.key_id) == 8
    assert all(ch in "0123456789abcdef" for ch in keypair.key_id)
    metadata = json.loads(keypair.metadata_path.read_text(encoding="utf-8"))
    assert metadata["key_id"] == keypair.key_id
    assert metadata["algorithm"] == "ed25519"
    assert metadata["created_at"] == keypair.key_created_at


def test_load_key_round_trips_existing_keypair_with_sidecar(tmp_path: Path) -> None:
    keys_dir = tmp_path / ".stipul" / "keys"
    generated = generate_keypair(keys_dir)

    loaded = load_key(generated.key_id, keys_dir)

    assert loaded.key_id == generated.key_id
    assert loaded.algorithm == "ed25519"
    assert loaded.key_created_at == generated.key_created_at
    assert _public_raw_bytes(loaded.public_key) == _public_raw_bytes(generated.public_key)


def test_load_key_missing_sidecar_raises_fatal_message(tmp_path: Path) -> None:
    keys_dir = tmp_path / ".stipul" / "keys"
    generated = generate_keypair(keys_dir)
    generated.metadata_path.unlink()

    with pytest.raises(
        KeyMetadataError,
        match=rf"Key metadata missing for key_id `{generated.key_id}`. Re-generate key with `stipul rotate-key`.",
    ):
        load_key(generated.key_id, keys_dir)


def test_rotate_key_archives_previous_runtime_keypair_and_sidecar(tmp_path: Path) -> None:
    keys_dir = tmp_path / ".stipul" / "keys"
    first = generate_keypair(keys_dir)

    rotated = rotate_key(keys_dir)

    assert rotated.key_id != first.key_id
    archived_dir = keys_dir / "archived"
    assert archived_dir.exists()
    assert _mode(archived_dir) == 0o700
    assert (archived_dir / first.private_key_path.name).exists()
    assert (archived_dir / first.public_key_path.name).exists()
    assert (archived_dir / first.metadata_path.name).exists()
    assert not first.private_key_path.exists()
    assert not first.public_key_path.exists()
    assert not first.metadata_path.exists()


def test_get_key_id_is_deterministic_for_same_public_key(tmp_path: Path) -> None:
    keys_dir = tmp_path / ".stipul" / "keys"
    keypair = generate_keypair(keys_dir)

    assert get_key_id(keypair.public_key) == keypair.key_id
    assert get_key_id(keypair.public_key) == keypair.key_id


def test_load_or_create_keypair_creates_missing_key_directory(tmp_path: Path) -> None:
    keys_dir = tmp_path / "nested" / "state" / "keys"
    assert not keys_dir.exists()

    keypair = load_or_create_keypair(keys_dir)

    assert keys_dir.exists()
    assert _mode(keys_dir) == 0o700
    assert keypair.private_key_path.exists()
    assert keypair.public_key_path.exists()
    assert keypair.metadata_path.exists()


def test_signature_round_trip_validates_against_public_key(tmp_path: Path) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    unsigned_event = _sample_event()
    signature = sign_event(unsigned_event, keypair.private_key)
    signed_event = {**unsigned_event, "signature": signature}

    keypair.public_key.verify(
        base64.b64decode(signature.encode("ascii")),
        canonical_event_payload(signed_event),
    )


def test_tampered_payload_fails_signature_verification(tmp_path: Path) -> None:
    keypair = generate_keypair(tmp_path / "keys")
    unsigned_event = _sample_event()
    signature = sign_event(unsigned_event, keypair.private_key)
    signed_event = {**unsigned_event, "signature": signature}
    tampered = dict(signed_event)
    tampered["reason"] = "tampered"

    with pytest.raises(InvalidSignature):
        keypair.public_key.verify(
            base64.b64decode(signature.encode("ascii")),
            canonical_event_payload(tampered),
        )


def test_canonical_event_payload_excludes_signature_and_prev_hash_includes_it() -> None:
    event = _sample_event(signature="ZmFrZQ==")
    payload_bytes = canonical_event_payload(event)
    serialized_payload = payload_bytes.decode("utf-8")
    assert "signature" not in serialized_payload

    expected_prev_hash = hashlib.sha256(
        canonical_json_bytes(event)
    ).hexdigest()
    assert compute_prev_hash(event) == expected_prev_hash


def test_canonical_dict_sorts_nested_keys_recursively() -> None:
    value = {
        "z": {"b": "two", "a": "one"},
        "a": [{"d": 4, "c": 3}],
    }
    canonical = canonical_dict(value)
    assert list(canonical.keys()) == ["a", "z"]
    assert list(canonical["z"].keys()) == ["a", "b"]
    assert list(canonical["a"][0].keys()) == ["c", "d"]


def test_canonical_dict_normalizes_nfc_string_values() -> None:
    decomposed = "Cafe\u0301"
    composed = unicodedata.normalize("NFC", decomposed)

    canonical = canonical_dict({"title": decomposed, "nested": {"name": decomposed}})
    assert canonical["title"] == composed
    assert canonical["nested"]["name"] == composed


def test_compute_contract_hash_stable_for_semantically_equivalent_contracts(base_dict) -> None:
    payload_a = dict(base_dict)
    payload_b = dict(base_dict)
    payload_b["allowed_tools"] = list(reversed(payload_b["allowed_tools"]))
    payload_b["never_allow_tools"] = list(reversed(payload_b["never_allow_tools"]))

    contract_a = Contract.from_dict(payload_a)
    contract_b = Contract.from_dict(payload_b)
    assert compute_contract_hash(contract_a) == compute_contract_hash(contract_b)


def test_compute_contract_hash_rejects_non_contract_inputs() -> None:
    with pytest.raises(TypeError):
        compute_contract_hash({"contract_id": "x"})  # type: ignore[arg-type]


def test_compute_contract_hash_nfc_equivalence(base_dict) -> None:
    payload_a = dict(base_dict)
    payload_b = dict(base_dict)
    payload_a["identity_agent_id"] = "Cafe\u0301-agent"
    payload_b["identity_agent_id"] = unicodedata.normalize("NFC", payload_a["identity_agent_id"])

    hash_a = compute_contract_hash(Contract.from_dict(payload_a))
    hash_b = compute_contract_hash(Contract.from_dict(payload_b))
    assert hash_a == hash_b


def test_compute_contract_hash_is_stable_across_calls(contract) -> None:
    first = compute_contract_hash(contract)
    second = compute_contract_hash(contract)
    third = compute_contract_hash(contract)
    assert first == second == third


def test_contract_signing_prev_hash_and_session_head_share_serialization_constants(contract, tmp_path: Path):
    contract_hash = compute_contract_hash(contract)
    canonical_contract = canonical_dict(contract.to_canonical_dict())
    expected_contract_hash = hashlib.sha256(
        canonical_json_bytes(canonical_contract)
    ).hexdigest()
    assert contract_hash == expected_contract_hash

    event = _sample_event(signature="ZmFrZQ==")
    expected_payload = canonical_json_bytes({k: v for k, v in event.items() if k != "signature"})
    assert canonical_event_payload(event) == expected_payload

    expected_prev_hash = hashlib.sha256(
        canonical_json_bytes(event)
    ).hexdigest()
    assert compute_prev_hash(event) == expected_prev_hash

    write_session_head(tmp_path, event)
    head = read_session_head(tmp_path)
    assert head is not None
    assert head["event_hash"] == expected_prev_hash


def test_signer_and_verifier_use_shared_canonical_helpers() -> None:
    from stipul.utils import canonical as canonical_module

    assert signer_module.canonical_event_payload is canonical_module.canonical_event_payload
    assert signer_module.compute_prev_hash is canonical_module.compute_prev_hash
    assert verifier_module.canonical_event_payload is canonical_module.canonical_event_payload
    assert verifier_module.compute_prev_hash is canonical_module.compute_prev_hash
