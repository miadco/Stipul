"""Signing Layer primitives."""

from stipul.chronicle.signing.keys import (
    KeyMetadataError,
    KeyNotFoundError,
    RuntimeKeyPair,
    generate_keypair,
    get_key_id,
    load_key,
    load_latest_keypair,
    load_or_create_keypair,
    rotate_key,
)
from stipul.chronicle.signing.signer import canonical_event_payload, compute_prev_hash, sign_event
from stipul.chronicle.signing.verifier import (
    DecisionsVerificationResult,
    VerificationFailure,
    VerificationResult,
    print_verification_result,
    verify_chain,
    verify_decisions,
)

__all__ = [
    "KeyMetadataError",
    "KeyNotFoundError",
    "RuntimeKeyPair",
    "DecisionsVerificationResult",
    "VerificationFailure",
    "VerificationResult",
    "canonical_event_payload",
    "compute_prev_hash",
    "generate_keypair",
    "get_key_id",
    "load_key",
    "load_latest_keypair",
    "load_or_create_keypair",
    "print_verification_result",
    "rotate_key",
    "sign_event",
    "verify_chain",
    "verify_decisions",
]
