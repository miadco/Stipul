# Stipul
Stipul is an agent authorization and audit platform for tool-using systems. Operators define a Charter before an agent runs, and each tool call is evaluated at the execution boundary. Writ enforces the Charter, records every decision in the Chronicle, and produces a cryptographic Seal. Session artifacts can then be verified after execution against the Charter and signing material.

## Native demo
Run `python3 demo/run.py`.

`Actions` shows the three tool calls and their enforcement outcomes.
`Evidence` shows the Chronicle history rendered from the signed `events.jsonl` session log.
`Proof` shows Chronicle verification and Seal validation for the preserved session.

See [demo/README.md](demo/README.md) for full details.

This proves three enforcement outcomes through the real proxy path, a signed Chronicle, and a verified Seal.
This does not prove framework integration, external API calls, or an operator UI.

## Where to start
- [Native demo](demo/README.md)
- [Command reference](docs/CLI.md)
- [Shipped state and boundaries](docs/SHIPPED_STATE.md)

## Supported paths
Currently supported:

- Native local demo: `demo/run.py`
- OpenAI Agents SDK integration: [`integrations/openai-agents/`](integrations/openai-agents/README.md)
- LangGraph integration: [`integrations/langgraph/`](integrations/langgraph/README.md)

This does not imply general framework coverage beyond the two listed integrations, an operator dashboard or UI, production deployment patterns, or cloud or hosted operation.

## What problem this solves

When an AI agent calls an API, writes to a database, or triggers a workflow, there is often no independent proof it was authorized to do so. Logs show what happened. They do not prove what was permitted. If you are building an agent, that means you have no reliable way to enforce boundaries at runtime, test policy changes safely, or explain why a specific action was allowed or denied. If you are deploying one, it means you have nothing that qualifies as evidence when a regulator, auditor, or customer asks how you know the agent stayed within policy. Stipul makes agent actions admissible as evidence: every tool call hits a deterministic policy boundary before execution, and every decision is recorded in a cryptographically signed chain that anyone can verify without trusting the system that produced it.

## Quickstart
```bash
pip install -e ".[dev]"
pytest
```

## Manual gateway flow
YAML Charter is the preferred operator-facing format. JSON is still accepted, but the canonical first successful run is:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

cat > charter.yaml <<'YAML'
schema_version: "1.0"
contract_id: "2f2c1ef3-5f4e-47a8-a95a-6205fbb86f5f"
created_at: "2026-01-01T00:00:00Z"
expires_at: "2026-12-31T23:59:59Z"
identity_agent_id: "demo-agent"
allowed_tools:
  - "demo.echo"
never_allow_tools:
  - "shell.exec"
tool_risk_classes:
  demo.echo: "read"
max_tool_calls: 20
max_net_calls: 5
egress_allowlist:
  - "api.example.com"
approval_quorum: 1
YAML

export STIPUL_TOKEN_SECRET=demo-secret

stipul lint-contract --contract charter.yaml

stipul gateway mcp \
  --contract charter.yaml \
  --session-dir .demo-session \
  --session-id 11111111-1111-1111-1111-111111111111 \
  --runtime stipul.examples.echo_runtime:build_runtime \
  --control-port 0
```

What you should see first:

- gateway mode running over stdio
- a printed local control URL like `http://127.0.0.1:43123`
- the existing local operator panel at that URL

Notes:

- `--runtime stipul.examples.echo_runtime:build_runtime` uses the shipped demo runtime. It exposes one tool, `demo.echo`, and returns the provided JSON inputs unchanged.
- `--control-port 0` starts the existing loopback-only control sidecar in the same process and chooses a free local port automatically.
- This control surface is local-only. It binds to `127.0.0.1`, not `0.0.0.0`.
- If the gateway process is already holding the session lock, separate CLI commands against the same session directory may fail until the process exits.

## Trust Boundaries
**Token secret isolation:** `STIPUL_TOKEN_SECRET` must not be present in
the agent runtime environment. If the agent can read this secret, it can mint
valid tokens and bypass the chokepoint. The secret is only permitted in the
MCP Proxy and Server Wrapper process environments. It must be absent from the
agent runtime process env, any agent-accessible filesystem path, and any config
mounted into the agent container or VM.

## Contract Schema
Annotated example contract:

```yaml
schema_version: "1.0"                # must be "1.0"
contract_id: "<uuid>"                # unique contract identifier
parent_contract_id: null             # optional parent link for merge chains
created_at: "2026-01-01T00:00:00Z"   # UTC ISO 8601
expires_at: "2026-12-31T23:59:59Z"   # absolute expiry, must be after created_at
signed_by: null                      # optional signing key id

identity_agent_id: "my-agent-v1"     # stable agent name, pinned at session open
identity_code_sha256: null           # optional code identity binding

allowed_tools:                       # explicit allowlist
  - "filesystem.write"
  - "web.search"
never_allow_tools:                   # deny wins over allowed_tools
  - "shell.exec"

tool_risk_classes:                   # tools absent here default to "write"
  filesystem.write: "write"
  web.search: "read"

max_tool_calls: 100                  # hard cap on total tool invocations
max_net_calls: 20                    # hard cap on network-touching calls
approval_quorum: 1                   # required approvals when Charter returns require_approval

egress_allowlist:                    # permitted outbound domains
  - "api.example.com"                # exact host match
  - ".trusted.example"               # suffix match, leading dot required
```

## Policy Rule Table
| Risk Class   | Decision         | Notes                             |
|--------------|------------------|-----------------------------------|
| read         | allow            |                                   |
| write        | allow            | default if tool has no risk class |
| irreversible | require_approval |                                   |
| exfil_risk   | require_approval |                                   |

## Evaluation Order
1. Contract expired -> deny
2. Identity mismatch -> deny
3. Tool in never_allow_tools -> deny
4. Tool not in allowed_tools -> deny
5. Tool call budget exhausted -> deny
6. Network call budget exhausted -> deny
7. Egress domain not allowlisted -> deny
8. Risk class lookup -> allow / require_approval
9. Default -> deny

## Hierarchical Contracts
Child contracts can only restrict parent permissions, never expand them. `merge(parent, child)` validates this across every field and returns all violations together as one `ContractMergeViolation`, not one error at a time.

| Field             | Merge Rule                       |
|-------------------|----------------------------------|
| allowed_tools     | intersection                     |
| never_allow_tools | union                            |
| tool_risk_classes | higher severity wins             |
| max_tool_calls    | min                              |
| max_net_calls     | min                              |
| expires_at        | min (earlier)                    |
| egress_allowlist  | intersection                     |
| identity          | child may restrict, never loosen |

<!-- REVIEW: verify this is still current -->
## Operator Workflow
Plain operator loop:

```bash
stipul scan /path/to/repo --json-out scan.json
stipul lint-contract --contract charter.yaml
stipul gateway mcp --contract charter.yaml --session-dir /path/to/session --session-id 11111111-1111-1111-1111-111111111111 --runtime stipul.examples.echo_runtime:build_runtime --control-port 0
stipul verify --session-dir /path/to/session --contract charter.yaml --public-key /path/to/runtime_key.pub
stipul export --session-dir /path/to/session --out-dir /path/to/bundle --contract charter.yaml --public-key /path/to/runtime_key.pub --scan-report scan.json
stipul export --session-dir /path/to/session --out-dir /path/to/bundle --contract charter.yaml --public-key /path/to/runtime_key.pub --timestamp-rfc3161 https://tsa.example
```

Required environment variables:

- `STIPUL_TOKEN_SECRET`: token minting / validation secret. Keep it out of the agent runtime environment.
- `STIPUL_PERMIT_SECRET`: required when JIT permit validation is enabled.
- `STIPUL_WRAPPER_LOG_PATH`: optional wrapper log path used for coverage and bypass-gap detection.

Operator notes:

- `scan` is heuristic, deterministic, and read-only. It never imports scanned modules, executes code, or makes network calls.
- `verify` proves Chronicle signed-chain integrity for the authoritative `events.jsonl` stream and reports additive session Seal status from `seal.json` when present.
- `export` produces a shareable evidence bundle. Use `--redact` when you need to remove metadata leaf values from `events.jsonl`, and `--scan-report` when you want to bundle prior scanner output. Its manifest `exported_at` is derived from session artifacts so repeated exports of the same inputs stay deterministic.
- `export --timestamp-rfc3161 <tsa-url>` adds an RFC 3161 receipt beside the export bundle manifest for the deterministic non-redacted bundle hash. This is downstream timestamp proof only; it does not replace Chronicle verification of `events.jsonl`.
- `gateway mcp` runs the existing Writ enforcement core over MCP stdio. The tool catalog is still caller-supplied; the shipped `stipul.examples.echo_runtime:build_runtime` is only a minimal first-run runtime.
- `--control-port` starts the existing loopback operator sidecar in the same process. The printed URL is local-only and is the best live control surface when the gateway process already holds the session lock.
- Trust remains bounded: response payloads are not inspected, agent filesystem writes are not monitored, and coverage claims depend on wrapper logging when `wrapper_log.jsonl` is present.

## Framework Integration Boundary
Stipul is the runtime contract and evidence layer for agent actions. The current official protocol surface is MCP, and the shipped path is `stipul/cli/gateway_cmd.py -> stipul/writ/proxy/mcp_gateway.py -> ProxyServer.handle_tool_call()`.

Adapters for frameworks such as LangGraph or the OpenAI Agents SDK should attach at the same boundary:

- MCP-speaking adapters should use the existing gateway surface and pass their tool catalog plus executor into `ProxyServer.create_mcp_gateway(...)`.
- Non-MCP adapters should normalize each action into the proxy request shape that `ProxyServer.handle_tool_call()` already expects, then provide the real tool execution function as the `forward_call`.
- Normalize `tool_name` to a non-empty string, normalize tool arguments under `inputs`, put network destinations in `inputs.egress_target`, and set `metadata.ingress` to the adapter name or protocol. Include narrow target hints such as `path`, `target`, or `approval_context` only when the adapter already has them.
- Keep `events.jsonl` authoritative. Do not add a second event ledger, second enforcement path, or adapter-side derived cache.

Standard scenario pack for every first-party adapter:

1. allowed safe read
2. denied dangerous write
3. approval-gated irreversible or exfil-risk action
4. unknown tool denied
5. kill switch enforced
6. evidence verification success via `stipul verify`
7. tamper verification failure after mutating `events.jsonl`

See `docs/CLI.md` for command details and exit codes.
See `CHANGELOG.md`, `docs/THREAT_MODEL.md`, and `SECURITY.md` for release and trust documentation.

## Signing (Week 3)
Contracts are designed for Ed25519 signing. `to_canonical_dict()` produces the signing input with lexicographically sorted keys, null values removed, and `signed_by` plus `parent_contract_id` excluded from signing scope. Signing implementation ships in Week 3.

## Versioning And Release

- `stipul.__version__` in `stipul/__init__.py` is the single version source of truth.
- Packaging metadata derives the project version from that attribute.
- Release notes begin in `CHANGELOG.md`.
- Threat-model assumptions and trust boundaries are summarized in `docs/THREAT_MODEL.md`.

Repeatable release build flow:

```bash
python -m build --no-isolation
python -m twine check dist/*
bash scripts/validate_dist.sh dist
```

The release workflow runs on `v*` tags, rebuilds the project from source, runs the full test and static-analysis gates, validates wheel and sdist installs in fresh virtual environments, and publishes artifact hashes alongside the built distributions.

## Project Status
| Week | Scope                           | Status   |
|------|---------------------------------|----------|
| 1    | Contract schema + policy engine | ✓ Done   |
| 2    | MCP proxy enforcement           | ✓ Done   |
| 3    | Signed event stream             | ✓ Done   |
| 4    | Bypass detection                | ✓ Done   |
| 5    | CLI packaging                   | ✓ Done   |
| 6    | Scanner + launch wedge          | ✓ Done   |
| 7    | Packaging + release workflow    | ✓ Done   |

## CI Preflight Gates
GitHub Actions enforces a `preflight` job on every push and PR. The job runs `ruff`, `mypy --strict`, `bandit`, and `pytest`, plus guardrails for signed-chain tests and deterministic `DecayDetector.check(...)` usage.
