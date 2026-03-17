# ADR-002: Verification Trust Model

Date: 2026-03-18
Status: Accepted

## Context

As of commit `8e6bbcee` on branch `stipul-refactor`, Stipul's live
verification path is the Chronicle chain verifier, not a live Seal verifier.
`stipul verify` checks signed `events.jsonl` against a caller-supplied
contract and caller-supplied Ed25519 public key. Seal-related modules exist in
`stipul/seal/`, but on this commit they are placeholders and are not wired
into `stipul verify` or `ProxyServer.close()`.

This ADR records what verification proves and what it does not prove at that
commit, based on a line-level recon of the signing, verification, and
key-management code.

## Findings

### What verification proves today

- `stipul verify` proves integrity and cryptographic consistency of signed
  `events.jsonl` relative to a caller-supplied contract and caller-supplied
  Ed25519 public key.
- If both inputs are authentic and independently trusted, verification confirms
  that the Chronicle chain has not been modified since signing.
- Verification also confirms that the signed chain is bound to the supplied
  contract hash. It does not establish that the supplied contract is itself
  authentic.

### What verification does not prove today

- Origin. Verification does not prove who produced the artifacts. The signing
  key is not bound to an external identity, CA, transparency log, or HSM
  attestation.
- Contract authenticity. The contract is caller-supplied. If an attacker can
  substitute both artifacts and contract, verification can still pass.
- Seal integrity on the live path. `stipul/seal/builder.py`,
  `stipul/seal/signer.py`, and `stipul/seal/verifier.py` exist, but they are
  placeholders on this commit, and `stipul verify` does not invoke them.
- Temporal authority. RFC 3161 timestamping exists as an opt-in export feature,
  not as a default verification input.

### Key lifecycle

- Ed25519 keypair generated via `load_or_create_keypair()` in
  `stipul/chronicle/signing/keys.py` and wired into the runtime through
  `stipul/writ/proxy/server.py`.
- Private key persisted unencrypted as PKCS8 PEM at
  `~/.stipul/keys/runtime_<key_id>.pem` using `NoEncryption()`.
- File permissions: directory `0700`, private key `0600`, public key `0644`.
- No encryption at rest. No HSM delegation. No external key registration.
- Rotation exists as local file archival (`archived/` + regenerate). No
  revocation model. No verifier-side trust store. No CLI command exposes
  rotation on this commit.
- There is one live Ed25519 trust domain on this commit: Chronicle event
  signing. Seal signing helpers are placeholders and are not on the live path.

### Verifier trust source

- `stipul verify` requires `--contract` and `--public-key` as explicit CLI
  arguments (`verify_cmd.py`).
- The verifier loads the supplied public key from disk and uses it for
  Chronicle chain verification.
- The verifier has no built-in trust store, no key pinning, and no mechanism
  to obtain trust material independently of the caller.
- `verify_cmd.py` does not invoke `stipul/seal/verifier.py` on this commit.

### Demo boundary

- On commit `8e6bbcee`, there is no `demo/run.py`. The relevant shipped demo
  paths are the Sunday runbook and the OpenAI Agents / LangGraph integration
  demos.
- Shipped source-checkout demos repoint `HOME` into demo-local directories,
  making the key appear session-scoped. This is launcher behavior, not the core
  trust model.
- Demo verification supplies contract and public key from the same output tree
  that produced the artifacts. This proves the code path works; it does not
  prove the trust boundary is hostile-reviewable.
- Demo token secrets (`STIPUL_TOKEN_SECRET`) are hardcoded sample values
  committed in source. The demo boundary is cooperative, not isolated.

### Attack surface summary

- If an attacker has filesystem access to `~/.stipul/keys/`, they can extract
  the unencrypted private key and re-sign modified signed Chronicle artifacts.
- If an attacker can replace both the artifacts and the trust material
  (contract + public key) that the verifier consumes, verification will still
  pass. This is inherent to caller-supplied trust inputs without an external
  anchor.
- Placeholder Seal modules do not change this trust boundary on this commit.
- These are not bugs. They are the boundaries of a locally anchored trust
  model.

## Classification

Persisted local trust (awkward hybrid).

The core model persists a reusable local key. Demos make it look ephemeral by
repointing `HOME`. Verification is not circular at the single-file level
because the live path does not consume self-embedded trust material. But it is
not externally bound by default because the verifier trusts caller-supplied
local inputs.

## Claim Language Guidance

- "Tamper-evident" is accurate only if qualified: tamper-evident relative to a
  supplied public key and supplied contract.
- "Cryptographically verifiable" is accurate only if qualified: verifiable
  given independently trusted inputs.
- Do not describe `stipul verify` as verifying `seal.json` or a live Seal path
  on commit `8e6bbcee`. The Seal modules are present but placeholder.
- Do not imply origin proof without stating the trust assumption.
- Do not describe verification as independent or third-party-verifiable without
  an external trust root that does not exist in the default path on this
  commit.

## References

- `stipul/chronicle/signing/keys.py` — key generation, persistence, rotation
- `stipul/chronicle/signing/signer.py` — Chronicle signing mechanics
- `stipul/chronicle/signing/verifier.py` — Chronicle chain verification
- `stipul/chronicle/events/logger.py` — runtime signing key usage for Chronicle
  events
- `stipul/cli/verify_cmd.py` — live verify entry point and trust input wiring
- `stipul/writ/proxy/server.py` — key wiring and `close()` behavior
- `stipul/seal/builder.py` — placeholder, not on live path
- `stipul/seal/signer.py` — placeholder, not on live path
- `stipul/seal/verifier.py` — placeholder, not on live path
- `stipul/seal/exporter.py` — export-side public key and artifact packaging
- `stipul/seal/rfc3161_anchor.py` — opt-in RFC 3161 export-side timestamping
- `integrations/openai-agents/openai_agents_stdio.py` — demo-local `HOME` and
  token-secret wiring
- `integrations/langgraph/langgraph_stdio.py` — demo-local `HOME` and
  token-secret wiring
- `docs/SUNDAY_DEMO_RUNBOOK.md` — demo-local key and token-secret handling
