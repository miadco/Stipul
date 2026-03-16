# Stipul Shipped State

## What Stipul Is
Stipul is an agent authorization and audit platform. It lets operators define Charter policy, enforce decisions through Writ, record authoritative evidence in the Chronicle, and verify that evidence through Chronicle verification plus additive Seal status.

## Canonical Architecture
Writ enforces the Charter, records every decision in the Chronicle, and produces a cryptographic Seal.

- Writ = enforcement proxy
- Charter = policy engine
- Chronicle = evidence store
- Seal = cryptographic attestation layer

## Shipped Capabilities

### Sprint 3
- Kill switch state is enforced in Writ through a single control authority in `state_dir/operator_state.json`.
- Operator state changes and kill-switch denials are recorded in the authoritative Chronicle stream.
- Operator controls ship through the CLI, a loopback HTTP sidecar, and a local web panel.
- Operator state handling is hardened around one atomic sidecar path.

### Sprint 4
- Charter loads through one shared loader.
- YAML is the preferred operator-facing Charter format. JSON is still accepted.
- Writ, `stipul lint-contract`, `stipul simulate`, `stipul diff`, and contract inheritance all use the same Charter loading path.

### Sprint 5
- Stipul ships a minimal MCP gateway surface.
- MCP `initialize`, `tools/list`, and `tools/call` are supported.
- MCP `tools/call` flows into the existing Writ enforcement path.
- Gateway-originated Chronicle evidence is tagged with `ingress="mcp_gateway"` in metadata.
- A standalone gateway launch surface exists through `stipul gateway mcp`.

### Sprint 6 Track 1
- Delegation chains are validated inside Writ.
- Delegation is signed, TTL-bound, contract-bound, and session-bound.
- Delegation chain depth is enforced at validation time.
- Delegation context is recorded in Chronicle metadata through `delegation_context`.

### Sprint 6 Track 2
- Multi-party approval is implemented.
- Charter owns quorum through top-level `approval_quorum`.
- Approval state is stored in one atomic sidecar authority at `state_dir/approval_state.json`.
- Writ auto-creates or reuses pending approval requests when Charter requires quorum.
- Approved execution reuses the existing permit/override path.
- Approval lifecycle evidence is recorded in Chronicle metadata through `approval_context`.

### Sprint 6 Track 3
- Stipul exports SIEM-friendly JSONL derived from authoritative Chronicle evidence.
- SIEM export reads from on-disk `events.jsonl`, applies deterministic filtering, and writes additive downstream output only.
- SIEM export includes a companion manifest with `source_events_sha256` binding the export back to the authoritative Chronicle source file.

### Product-Surface Correction Block
- A shipped example runtime exists for first-run gateway success: `stipul.examples.echo_runtime:build_runtime`.
- `stipul gateway mcp` can optionally start the existing loopback control sidecar with `--control-port`.
- README and CLI docs now reflect the current product surface instead of older internal/demo-first paths.

## Current Product Surfaces
- Charter validation: `stipul lint-contract`
- Chronicle verification + Seal status: `stipul verify`
- Evidence export: `stipul export`
- SIEM export: `stipul export --siem-out ...`
- Trace simulation: `stipul simulate`
- Contract diff: `stipul diff`
- MCP gateway launch: `stipul gateway mcp`
- Operator controls:
  - `stipul operator kill-switch ...`
  - `stipul operator approval status`
  - `stipul operator approval approve`
- Live local control surfaces:
  - loopback HTTP sidecar
  - local web panel served by the sidecar
- Example first-run runtime:
  - `stipul.examples.echo_runtime:build_runtime`

## Authority Model
- Writ is the single enforcement path.
- Charter is the single policy authority.
- YAML is the preferred operator-facing Charter format.
- Sidecars and state files are the sole control authorities for their domains.
- Stipul does not ship a second enforcement path, a second policy authority path, or a second control authority path.

## Evidence Model
- `events.jsonl` is the sole authoritative evidence source.
- Chronicle writes authoritative evidence to `events.jsonl`.
- Chronicle verification applies to the authoritative `events.jsonl` stream.
- `seal.json` is an additive session-sidecar Seal bound to the authoritative `events.jsonl` stream.
- Derived outputs remain downstream only:
  - `decisions.jsonl`
  - `summary.json`
  - export bundles
  - SIEM JSONL exports
- Metadata is used to extend evidence meaning where possible instead of changing Chronicle’s base event schema.

## Known Caveats
- The control sidecar and local panel are loopback-only. They are not remote/mobile control surfaces.
- Separate CLI processes can still contend on the session lock held by a running gateway or proxy process.
- The shipped example runtime is demo-only.
- Real deployments still need their own runtime factory and tool catalog.
- Delegation max depth currently comes from runtime configuration, not Charter.
- SIEM export is JSONL-only in the current shipped state.

## Not Yet Built
- A session-lock-safe live operator workflow for separate CLI processes against a running gateway session
- Remote control surfaces beyond the existing loopback-only sidecar and local panel
- Charter-owned delegation depth configuration
- HTTP approval controls
- Gateway-owned runtime/catalog packaging beyond the shipped demo runtime
- Live SIEM shipping or vendor-specific SIEM connectors

## Highest-Priority Next Items
- Reduce cold-start friction further for operators who are not working from repo context
- Improve runtime packaging beyond the shipped demo runtime
- Improve live operator ergonomics around session-lock contention
- Extend the operator-facing approval surface beyond the current CLI-only path
