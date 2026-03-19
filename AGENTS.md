# Stipul Repository Rules

## Product Naming
- Stipul is the primary product name.

## Canonical Component Names
- Writ = enforcement proxy
- Charter = policy engine
- Chronicle = evidence store
- Seal = cryptographic attestation layer

## Canonical Architecture
- Writ enforces the Charter, records every decision in the Chronicle, and produces a cryptographic Seal.

## Authority And Evidence Rules
- Do not invent second authority paths.
- Do not invent second enforcement paths.
- Do not invent second evidence paths.
- YAML is the preferred operator-facing Charter format.
- `events.jsonl` is the sole authoritative evidence source.
- Operator/control sidecars and state files are sole control authorities for their domains.
- Use metadata instead of Chronicle schema churn whenever possible.

## Workflow Defaults
- Prefer discovery-first, stop-gated workflow.
- Prefer product-surface improvements when the core architecture is already strong.
- Update `README.md`, CLI docs, and runbooks when command semantics change.
- Avoid test-helper-first demos unless they are explicitly labeled source-checkout-only.
