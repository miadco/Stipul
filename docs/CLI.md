# Stipul CLI

> Start with the [root README](../README.md) for the native demo and supported-path overview. This document is the command reference.

Examples in this document use `stipul ...`.
In a source checkout, the equivalent entry point is `python -m stipul.cli.main ...` from the interpreter where Stipul is installed.
Use whichever form matches the current environment.

## Commands

### `stipul lint-contract`

Check a Charter policy file for operator-facing foot-guns after loading and schema validation.

```bash
stipul lint-contract --contract charter.yaml
```

Exit codes:

- `0`: no lint errors
- `1`: lint errors present
- `3`: unreadable file or schema validation failure

### `stipul operator status`

Show current operator status from the proxy health surface.

```bash
stipul operator status \
  --session-dir /path/to/session \
  --contract charter.yaml
```

Required arguments:

- `--session-dir`: session directory containing `events.jsonl`
- `--contract`: Charter policy file, preferably YAML

Exit codes:

- `0`: status printed
- `3`: fatal input or runtime error

### `stipul operator kill-switch enable`

Enable the proxy kill switch and print the resulting status.

```bash
stipul operator kill-switch enable \
  --session-dir /path/to/session \
  --contract charter.yaml \
  --by operator-1 \
  --reason "manual stop"
```

Required arguments:

- `--session-dir`: session directory containing `events.jsonl`
- `--contract`: Charter policy file, preferably YAML
- `--by`: non-empty operator identifier recorded with the state change
- `--reason`: non-empty reason recorded with the state change

Exit codes:

- `0`: kill switch enabled and status printed
- `3`: fatal input or runtime error

### `stipul operator kill-switch disable`

Disable the proxy kill switch and print the resulting status.

```bash
stipul operator kill-switch disable \
  --session-dir /path/to/session \
  --contract charter.yaml \
  --by operator-1 \
  --reason "resume traffic"
```

Required arguments:

- `--session-dir`: session directory containing `events.jsonl`
- `--contract`: Charter policy file, preferably YAML
- `--by`: non-empty operator identifier recorded with the state change
- `--reason`: non-empty reason recorded with the state change

Exit codes:

- `0`: kill switch disabled and status printed
- `3`: fatal input or runtime error

### `stipul operator approval status`

Show current approval requests, optionally filtered by request ID.

```bash
stipul operator approval status \
  --session-dir /path/to/session \
  --contract charter.yaml
```

Required arguments:

- `--session-dir`: session directory containing `events.jsonl`
- `--contract`: Charter policy file, preferably YAML

Optional arguments:

- `--request-id`: show a single approval request

Exit codes:

- `0`: approval status printed
- `3`: fatal input or runtime error

### `stipul operator approval approve`

Add an approval to an existing approval request and print the resulting approval status.

```bash
stipul operator approval approve \
  --session-dir /path/to/session \
  --contract charter.yaml \
  --request-id <request-id> \
  --by <64-hex-approver-id>
```

Required arguments:

- `--session-dir`: session directory containing `events.jsonl`
- `--contract`: Charter policy file, preferably YAML
- `--request-id`: approval request ID
- `--by`: 64-character hexadecimal approver ID

Exit codes:

- `0`: approval added or existing approval status printed
- `3`: fatal input or runtime error

### `stipul verify`

Verify the signed authoritative `events.jsonl` chain and the session Seal.

```bash
stipul verify /path/to/session
```

If the session directory contains session-local `contract.json` and `public_key.pem`, `stipul verify` auto-discovers them. Use `--contract` and `--public-key` to override those trust inputs explicitly.

The receipt begins with a `Trust:` line:

- `Trust: VERIFIED` when `Chain: INTACT` and `Seal: VALID`
- `Trust: UNVERIFIED (unsealed)` when `Chain: INTACT` and `Seal: ABSENT`
- `Trust: REJECTED` for all other chain and seal combinations

Exit codes:

- `0`: trust `VERIFIED` or `UNVERIFIED (unsealed)`
- `2`: trust `REJECTED`
- `3`: fatal input or parsing error

### `stipul demo proof`

Run the packaged proof demo.

```bash
stipul demo proof
```

The command creates a fresh temporary session, runs one allowed action and two denied actions through the existing proxy, closes and seals the session, self-verifies it, and prints:

- a replay card derived from authoritative `events.jsonl`
- a trust receipt
- a guided `seal.json` tamper challenge

Exit codes:

- `0`: demo completed and self-verified
- `2`: demo session failed self-verification
- `3`: fatal input or runtime error

### `stipul export`

Write a deterministic evidence bundle from a session directory.

```bash
stipul export \
  --session-dir /path/to/session \
  --out-dir /path/to/bundle \
  --contract charter.yaml \
  --public-key /path/to/runtime_key.pub \
  --scan-report scan.json \
  --siem-out /path/to/siem_events.jsonl \
  --timestamp-rfc3161 https://tsa.example
```

Use `--redact` to emit `redacted_events.jsonl` instead of copying `events.jsonl`. Redaction only touches metadata leaf values; it does not re-sign events. Use `--scan-report` to include a previously generated scan report in the evidence bundle.

`manifest.json` uses a source-derived `exported_at` value so repeated exports of the same session inputs remain byte-stable.

`--siem-out` writes a downstream SIEM-friendly JSONL projection derived from the authoritative `events.jsonl` file on disk. It does not create a second Chronicle authority or a second event ledger.

`--timestamp-rfc3161 <tsa-url>` submits the deterministic non-redacted export bundle hash to an RFC 3161 timestamp authority and writes a receipt at `<out-dir>/rfc3161_receipt.json`. This is additive only. It does not change Chronicle verification of `events.jsonl`.

`--timestamp-rfc3161` is incompatible with `--redact`.

Optional SIEM filters:

- `--event-type <value>`
- `--decision <value>`
- `--ingress <value>`
- `--since <UTC timestamp>`
- `--until <UTC timestamp>`

The SIEM export writes:

- the filtered JSONL file at `--siem-out`
- a companion manifest at `<siem-out>.manifest.json`

The SIEM manifest includes:

- `source_events_sha256`: SHA-256 of the authoritative `events.jsonl` file before flattening
- `exported_at`: deterministic source-derived timestamp
- `applied_filters`
- source identity fields such as `source_session_id` and `source_contract_hash`

SIEM output is additive only. Chronicle verification still applies to the original `events.jsonl`, not to the downstream SIEM projection.

RFC 3161 timestamping is additive only. It timestamps the export bundle `top_level_sha256` from `manifest.json`, not `events.jsonl` directly, and does not replace local Chronicle verification.

Exit codes:

- `0`: export completed
- `3`: fatal input or filesystem error

### `stipul history`

Render a human-readable timeline directly from the authoritative `events.jsonl` stream.

```bash
stipul history --events /path/to/events.jsonl --session-id 11111111-1111-1111-1111-111111111111 --limit 20
```

By default, `stipul history` reads `./events.jsonl`. It stays read-only, validates each row against the canonical event schema, groups output by `session_id`, and translates decisions into plain language for operators.

### `stipul scan`

Run a bounded, deterministic scanner against a file or directory.

```bash
stipul scan /path/to/repo --json-out scan.json
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

### `stipul simulate`

Replay a trace against a contract using the Week 4 simulator.

```bash
stipul simulate --events events.jsonl --contract charter.yaml
```

Exit codes:

- `0`: simulation completed
- `3`: fatal input error

### `stipul diff`

Compare two contracts against the same trace.

```bash
stipul diff \
  --events events.jsonl \
  --contract-a contract_a.yaml \
  --contract-b contract_b.yaml
```

Exit codes:

- `0`: diff completed
- `3`: fatal input error

### `stipul gateway mcp`

Run the existing MCP gateway surface over stdio.

```bash
stipul gateway mcp \
  --charter charter.yaml \
  --session-dir /path/to/session \
  --session-id 11111111-1111-1111-1111-111111111111 \
  --runtime stipul.examples.echo_runtime:build_runtime \
  --tool-visibility allowed \
  --control-port 0
```

Required arguments:

- `--charter`: Charter policy file, preferably YAML
- `--session-dir`: session directory that will hold `events.jsonl`
- `--session-id`: stable session UUID
- `--runtime`: import path in `module:callable` form returning `{"tool_catalog": ..., "execute_tool": ...}`

Optional arguments:

- `--tool-visibility allowed|governed`: choose the MCP discovery surface. The default `allowed` lists only tools allowed by the active Charter and excludes `never_allow_tools`. `governed` lists every tool in the configured runtime catalog so clients can discover governed tools that may be denied later. Execution is unchanged: every `tools/call` still goes through Writ enforcement at call time.
- `--control-port`: if set, start the existing loopback control sidecar in the same process. Use `0` to auto-select a free local port.

The shipped example runtime is:

- `stipul.examples.echo_runtime:build_runtime`

It exposes one tool:

- `demo.echo`

Its executor is intentionally trivial and deterministic:

- it returns a JSON payload containing `ok`, the invoked `tool_name`, and the provided `inputs`

Operator caveats:

- gateway mode still uses the existing `ProxyServer` and existing Writ/Charter/Chronicle path
- the sidecar started by `--control-port` is local-only and binds to `127.0.0.1`
- when the gateway process already holds the session lock, separate CLI commands against the same session directory may fail until that process exits

## Session Directory

A session directory must contain `events.jsonl`. It may also contain:

- `decisions.jsonl`
- `summary.json`
- `wrapper_log.jsonl`
- `budget_state.json`

## Packaging Smoke

Release validation builds both wheel and sdist artifacts, then installs each into a fresh virtual environment before running:

- `stipul --help`
- `stipul verify --help`
- `stipul scan --help`

The checked-in helper is `scripts/validate_dist.sh`.

## Trust Boundaries

- The proxy proves what it observed and signed at the enforcement boundary.
- `events.jsonl` is the authoritative source for verify/export flows.
- `decisions.jsonl` is derived convenience output, not a verification authority.
- SIEM JSONL exported with `--siem-out` is a downstream deterministic projection of `events.jsonl`, not a second evidence source.
- `source_events_sha256` in the SIEM manifest binds the downstream export back to the Chronicle source file.
- `scan` is heuristic and advisory. It is not a proof of absence.
- Coverage and bypass-gap claims depend on `wrapper_log.jsonl` when present.
- Response payloads are not inspected.
- Agent filesystem writes are not monitored.
