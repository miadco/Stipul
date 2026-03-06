# AgentShield CLI

## Commands

### `agentshield lint-contract`

Check a contract for operator-facing foot-guns after JSON loading and schema validation.

```bash
agentshield lint-contract --contract contract.json
```

Exit codes:

- `0`: no lint errors
- `1`: lint errors present
- `3`: unreadable file or schema validation failure

### `agentshield verify`

Verify the signed event chain and the derivability of `decisions.jsonl` from `events.jsonl`.

```bash
agentshield verify \
  --session-dir /path/to/session \
  --contract contract.json \
  --public-key /path/to/runtime_key.pub
```

Exit codes:

- `0`: chain status `INTACT` and decisions projection valid
- `2`: chain `BROKEN` or `UNVERIFIABLE`, or decisions projection invalid / missing
- `3`: fatal input or parsing error

### `agentshield export`

Write a deterministic evidence bundle from a session directory.

```bash
agentshield export \
  --session-dir /path/to/session \
  --out-dir /path/to/bundle \
  --contract contract.json \
  --public-key /path/to/runtime_key.pub \
  --scan-report scan.json
```

Use `--redact` to emit `redacted_events.jsonl` instead of copying `events.jsonl`. Redaction only touches metadata leaf values; it does not re-sign events. Use `--scan-report` to include a previously generated scan report in the evidence bundle.

`manifest.json` uses a source-derived `exported_at` value so repeated exports of the same session inputs remain byte-stable.

Exit codes:

- `0`: export completed
- `3`: fatal input or filesystem error

### `agentshield scan`

Run a bounded, deterministic scanner against a file or directory.

```bash
agentshield scan /path/to/repo --json-out scan.json
```

The scanner:

- only reads text files
- never imports scanned modules
- never executes code from scanned content
- never makes network calls

Exit codes:

- `0`: no findings at or above the fail threshold
- `1`: at least one finding at or above the fail threshold
- `3`: fatal input or parsing error

### `agentshield simulate`

Replay a trace against a contract using the Week 4 simulator.

```bash
agentshield simulate --events events.jsonl --contract contract.json
```

Exit codes:

- `0`: simulation completed
- `3`: fatal input error

### `agentshield diff`

Compare two contracts against the same trace.

```bash
agentshield diff \
  --events events.jsonl \
  --contract-a contract_a.json \
  --contract-b contract_b.json
```

Exit codes:

- `0`: diff completed
- `3`: fatal input error

## Session Directory

A session directory must contain `events.jsonl`. It may also contain:

- `decisions.jsonl`
- `summary.json`
- `wrapper_log.jsonl`
- `budget_state.json`

## Packaging Smoke

Release validation builds both wheel and sdist artifacts, then installs each into a fresh virtual environment before running:

- `agentshield --help`
- `agentshield verify --help`
- `agentshield scan --help`

The checked-in helper is `scripts/validate_dist.sh`.

## Trust Boundaries

- The proxy proves what it observed and signed at the enforcement boundary.
- `events.jsonl` is the authoritative source for verify/export flows.
- `decisions.jsonl` is derived and must match `events.jsonl`.
- `scan` is heuristic and advisory. It is not a proof of absence.
- Coverage and bypass-gap claims depend on `wrapper_log.jsonl` when present.
- Response payloads are not inspected.
- Agent filesystem writes are not monitored.
