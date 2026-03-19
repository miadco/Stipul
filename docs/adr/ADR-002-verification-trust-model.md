# ADR-002: Verification Trust Model

Date: 2026-03-18
Status: Accepted

## Context

As of commit `408d6314d7d2fda5945a07670141f090e316e798` on branch
`stipul-refactor`, `stipul verify` checks both the authoritative Chronicle
stream and the session Seal against a caller-supplied contract and
caller-supplied Ed25519 public key.

This ADR does not classify all of `stipul/seal/*` as a monolithic unit. It is
limited to the Seal signing and verification trust path in
`stipul/seal/signer.py`, `stipul/seal/verifier.py`, and
`stipul/seal/builder.py`, plus the upstream trust inputs in
`stipul/chronicle/signing/keys.py`, `stipul/chronicle/events/logger.py`,
`stipul/writ/proxy/server.py`, and `stipul/cli/verify_cmd.py`.

This ADR records what verification proves and what it does not prove at that
commit, based on a line-level recon of the signing, verification, and
key-management code.

## Findings

### What verification proves today

- `stipul verify` proves integrity and cryptographic consistency of
  `events.jsonl` and `seal.json` relative to a caller-supplied contract and
  caller-supplied Ed25519 public key.
- If both inputs are authentic and independently trusted, verification confirms
  that the Chronicle and Seal have not been modified since signing.

### What verification does not prove today

- Origin. The signing key is not bound to an external identity, CA,
  transparency log, or HSM attestation.
- Contract authenticity. The contract is caller-supplied. If an attacker can
  substitute both artifacts and contract, verification can still pass.
- Temporal authority. RFC 3161 timestamping exists as an opt-in export feature,
  not as a default verification input.

### Key lifecycle

- Ed25519 keypair generated via `load_or_create_keypair()` in
  `stipul/chronicle/signing/keys.py`; there is no Seal-side keys module on
  this trust path.
- Private key persisted unencrypted as PKCS8 PEM at
  `~/.stipul/keys/runtime_<key_id>.pem` using `NoEncryption()`.
- File permissions: directory `0700`, private key `0600`, public key `0644`.
- No encryption at rest. No HSM. No external key registration.
- Rotation exists as local file archival (`archived/` + regenerate). No
  revocation model. No verifier-side trust store. No CLI command exposes
  rotation.
- The same signing key is used for both Chronicle event signatures
  (`logger.py:147`, `logger.py:220`) and Seal signatures through
  `ProxyServer.close()` (`server.py:352-356`). This is one trust domain, not
  two.

### Verifier trust source

- `stipul verify` requires `--contract` and `--public-key` as explicit CLI
  arguments (`verify_cmd.py:26-28`).
- The verifier loads the supplied public key from disk and uses it for both
  Chronicle chain verification and Seal verification (`verify_cmd.py:77-81`).
- The verifier has no built-in trust store, no key pinning, and no mechanism
  to obtain trust material independently of the caller.

### Demo boundary

- Shipped demos repoint `HOME` into demo-local directories, making the key
  appear session-scoped. This is launcher behavior, not the core trust model.
- Demo verification supplies contract and public key from the same output tree
  that produced the artifacts.
- Demo token secrets (`STIPUL_TOKEN_SECRET`) are hardcoded sample values
  committed in source. The demo boundary is cooperative, not isolated.

### Attack surface summary

- If an attacker has filesystem access to `~/.stipul/keys/`, they can extract
  the unencrypted private key and re-sign modified artifacts.
- If an attacker can replace both the artifacts and the trust material
  (contract + public key) that the verifier consumes, verification will still
  pass.
- These are not bugs. They are the boundaries of a locally-anchored trust
  model.

## Classification

Persisted local trust (awkward hybrid).

The core model persists a reusable local key. Demos make it look ephemeral by
repointing `HOME`. Verification is not circular at the single-file level
because `seal.json` does not carry its own public key. But it is not
externally bound by default because the verifier trusts caller-supplied local
inputs.

## Claim Language Guidance

- "Tamper-evident" is accurate if qualified: tamper-evident relative to a
  supplied public key.
- "Cryptographically verifiable" is accurate if qualified: verifiable given
  independently trusted inputs.
- Do not imply origin proof without stating the trust assumption.
- Do not describe verification as independent or third-party-verifiable without
  an external trust root that does not yet exist in the default path.

## References

`stipul/seal/exporter.py` and `stipul/seal/rfc3161_anchor.py` are substantive
modules in `stipul/seal/` but are outside the signing/verification trust path
classified in this ADR.

- `stipul/chronicle/signing/keys.py` — key generation, persistence, rotation
- `stipul/seal/signer.py` — signing mechanics
- `stipul/seal/verifier.py` — Seal signature verification
- `stipul/seal/builder.py` — Seal payload construction
- `stipul/chronicle/signing/verifier.py` — Chronicle chain verification
- `stipul/cli/verify_cmd.py` — CLI verify entry point and trust input wiring
- `stipul/writ/proxy/server.py` — Seal attach point (`close()`) and signing
  call
- `stipul/chronicle/events/logger.py` — shared signing key usage
