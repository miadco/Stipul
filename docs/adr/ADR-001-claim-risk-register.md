# ADR-001: Claim Risk Register

Date: 2026-03-16
Status: Active

## Context

Stipul's value proposition rests on evidence claims — that its output is
tamper-evident, cryptographically verifiable, and useful as proof of
authorization decisions. These claims must survive hostile review by auditors,
regulators, and opposing counsel. This register tracks gaps between what the
product says and what the code proves.

## Risk Register

### R-001 — "Admissible" headline claim (HIGH)

README described agent actions as "admissible as evidence." Admissibility is a
legal conclusion dependent on jurisdiction and court rules, not a technical
property the code can deliver. Narrowed to "tamper-evident, cryptographically
verifiable records" on 2026-03-16.

Residual risk: the product one-liner ("Makes automated actions admissible")
still appears in session context and may appear in external materials. Full
positioning review deferred to end-of-week.

### R-002 — Unsealed sessions (HIGH)

SIGKILL, OOM, host crash, and embedder-skipped close() all bypass Seal
generation. Verifier returns ABSENT, which is backward-compatible but
ambiguous — it does not yet distinguish incomplete session termination from
other causes of missing Seal. Signed chain integrity holds for completed
sessions only.

Next action: failing test or verifier state distinction for abnormal
termination (scheduled Wednesday).

### R-003 — RFC 3161 timestamp anchoring (MEDIUM)

rfc3161_anchor.py is live, invoked via export --timestamp-rfc3161. Opt-in,
correctly scoped in docs as "downstream timestamp proof only." Tests mock the
network call. Bandit B310 on urlopen is low-impact (operator-supplied TSA URL).
No implementation overclaim identified. Risk is inference-based: presence of
RFC 3161 on the export path may lead readers to assume externally anchored time
applies to the runtime Seal path.

Next action: formal classification confirmation (scheduled Thursday).

### R-004 — STIPUL_TOKEN_SECRET exposure boundary (MEDIUM)

Token minting secret is shared across processes in local demo layout. Trust
boundary docs describe the implication. Demo stderr prints a warning on every
run, which is a credibility issue when the demo is the primary proof surface.

Next action: assign OL number (OL-011), investigate alongside Ed25519 trust
boundary (scheduled Tuesday).

### R-005 — Ed25519 signing key trust boundary (UNCLASSIFIED)

Runtime-generated Ed25519 key signs the Seal. Key lifecycle, process exposure,
and attacker model not yet investigated. Current docs may imply stronger
protection than exists.

Next action: full investigation as OL-010 (scheduled Tuesday).

## Decisions

- DECISION: "Admissible as evidence" removed from README on 2026-03-16.
- DECISION: Product one-liner review deferred to Friday/Sunday.
- DECISION: Ed25519 key investigation assigned as R-005 / OL-010, scheduled Tuesday.
- DECISION: Token-secret demo warning assigned as R-004 / OL-011.
- DECISION: R-002 rated HIGH — absence ambiguity is hostile-reviewable.
- DECISION: R-003 rated MEDIUM — inference risk from optional temporal feature.
