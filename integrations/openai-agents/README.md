> Start with the [root README](../../README.md) for the native demo and supported-path overview.

# OpenAI Agents SDK Integration

## What This Integration Is

This is the first Stipul integration for the OpenAI Agents SDK using MCP-native stdio.

It proves the narrow boundary where OpenAI Agents SDK MCP tool calls go through Writ, Writ enforces the Charter, Chronicle records the decision in `events.jsonl`, and Seal verification still works on the resulting evidence.

## Attach Point

- Writ enforcement boundary: `stipul/writ/proxy/server.py`
- Exact method: `ProxyServer.handle_tool_call(raw_request, forward_call)`
- Existing MCP gateway hook: `ProxyServer.create_mcp_gateway(...)`
- Existing shipped transport path: `stipul/cli/gateway_cmd.py -> stipul/writ/proxy/mcp_gateway.py`

This integration does not add a second enforcement path, a second evidence path, or a second ledger.

## SDK Inspection Evidence

Exact commands used with the project venv:

```bash
.venv/bin/python -m pip show openai-agents
.venv/bin/python -c "from agents import MCPServerStdio, MCPServerSse; print('MCP native available')"
.venv/bin/python -c "import agents; print(agents.__file__); print(dir(agents))"
.venv/bin/python -c "from agents.mcp import MCPServerStdio, MCPServerSse, MCPServerStreamableHttp; print(MCPServerStdio); print(MCPServerSse); print(MCPServerStreamableHttp)"
```

Observed results from this repo environment:

```text
Name: openai-agents
Version: 0.12.0
Location: /home/michael/Downloads/stipul/.venv/lib/python3.12/site-packages
```

```text
ImportError: cannot import name 'MCPServerStdio' from 'agents'
```

```text
agents.__file__ -> /home/michael/Downloads/stipul/.venv/lib/python3.12/site-packages/agents/__init__.py
dir(agents) includes HostedMCPTool and the agents.mcp submodule, but not top-level MCPServerStdio.
```

```text
<class 'agents.mcp.server.MCPServerStdio'>
<class 'agents.mcp.server.MCPServerSse'>
<class 'agents.mcp.server.MCPServerStreamableHttp'>
```

Discovered MCP-relevant symbols:

- `agents.mcp.MCPServerStdio`
- `agents.mcp.MCPServerSse`
- `agents.mcp.MCPServerStreamableHttp`

Design conclusion:

- OpenAI Agents SDK MCP-native client support exists in the installed package.
- The top-level `agents` package does not export `MCPServerStdio`.
- The correct import path for this integration is `agents.mcp.MCPServerStdio`.
- Stipul's shipped gateway surface is stdio-only, so this integration uses MCP-native stdio and does not add SSE or HTTP support on the Stipul side.

## Design Decision

This integration uses MCP-native stdio with `agents.mcp.MCPServerStdio`.

The launched server path is the existing Stipul stdio MCP gateway:

```text
.venv/bin/python -m stipul.cli.main gateway mcp --contract ... --session-dir ... --session-id ... --runtime openai_agents_stdio:build_runtime
```

The integration module in this directory does two jobs only:

- launch and configure `agents.mcp.MCPServerStdio` against the existing Stipul gateway
- provide the gateway runtime factory `build_runtime(...)` used by that existing gateway path

It does not introduce a broad protocol translation layer.

## Run Instructions

Run the real demo and regenerate the transcript:

```bash
bash -lc 'bash integrations/openai-agents/demo.sh' 2>&1 | tee integrations/openai-agents/demo.transcript.txt
```

Human reviewer ritual:

```text
integrations/openai-agents/TEST_PLAN.md
```

The demo creates fresh artifacts under:

```text
/tmp/stipul-openai-agents-demo/
```

This is a source-checkout-only demo path. It reuses the focused integration test nodes to exercise the real MCP boundary and then runs `stipul verify` over the resulting evidence.

Run from repo root: `bash integrations/openai-agents/demo.sh`. See `integrations/openai-agents/TEST_PLAN.md` for the supported reviewer path.

## Demo Output

During source-checkout demo runs, you may see `Token secret isolation could not be verified. Ensure STIPUL_TOKEN_SECRET is not accessible to the agent process.` on stderr.

This is expected in the local demo layout because the gateway is launched from the same source checkout and process tree as the calling integration client, so startup cannot verify the production isolation boundary.

In production, the gateway and agent run in separate process trees, so token secret isolation is verifiable.

This warning does not change enforcement decisions, Chronicle evidence writes, or `stipul verify` results.

## Test Instructions

Run the focused integration test file:

```bash
.venv/bin/python -m pytest integrations/openai-agents/test_openai_agents_stdio.py
```

Optional targeted checks used for this work:

```bash
.venv/bin/python -m ruff check integrations/openai-agents
.venv/bin/python -m mypy integrations/openai-agents/openai_agents_stdio.py integrations/openai-agents/test_openai_agents_stdio.py
```

## Scenario Proof Matrix

| Scenario | Expected Result | Actual Result | Evidence Location | Status |
|---|---|---|---|---|
| allowed safe read | `filesystem.read` is allowed, returns a stable payload, and Chronicle logs an allow event | OpenAI Agents SDK stdio client received a stable read payload and `events.jsonl` recorded `allow/risk_class` | `demo.transcript.txt` section `## Scenario 1: allowed safe read`; `test_openai_agents_stdio.py::test_allowed_safe_read_returns_stable_output_and_writes_evidence` | PASS |
| denied dangerous write | `filesystem.write` is blocked before execution with a structured denial and evidence write | Write call returned `{"decision":"deny","reason":"not_in_contract","tool_name":"filesystem.write"}` and the file content stayed unchanged | `test_openai_agents_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| approval-gated irreversible or exfil-risk action | irreversible action is not executed and returns a structured, auditable gated result | `filesystem.delete` returned `approval_required` and Chronicle recorded approval metadata without deleting the file | `demo.transcript.txt` section `## Scenario 3: approval-gated irreversible action`; `test_openai_agents_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| unknown tool denied | unknown tool is denied deterministically before execution | `unknown.tool` returned `not_in_contract` and Chronicle recorded the denial | `test_openai_agents_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| kill switch enforced | once operator state enables the kill switch, the next tool call is denied with operator metadata | `filesystem.read` returned `kill_switch_active` and the denial event carried operator fields | `test_openai_agents_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| evidence verification success via `stipul verify` | Seal-compatible evidence verifies successfully after the mediated run | `stipul verify` returned exit code `0` for the intact session | `demo.transcript.txt` section `## Scenario 6: evidence verification success via stipul verify` | PASS |
| tamper verification failure after mutating `events.jsonl` | mutating `events.jsonl` breaks verification and is reported explicitly | after mutating the last event reason, `stipul verify` returned a non-zero exit code for the tampered session | `demo.transcript.txt` section `## Scenario 7: tamper verification failure after mutating events.jsonl` | PASS |

## Known Limitations

- This proves mediation for the direct OpenAI Agents SDK MCP client path only.
- This does not yet prove full `Agent` orchestration with a live model making tool-planning decisions.
- This does not yet prove every OpenAI Agents SDK execution mode.
- This does not yet prove production deployment hardening.
- This does not yet prove SSE or HTTP transport support on the Stipul side.
- The runtime factory in this directory is intentionally small and deterministic. It is not a general runtime framework.
- OL-007 — run from repo root: `bash integrations/openai-agents/demo.sh`.

## Proven

- OpenAI Agents SDK `agents.mcp.MCPServerStdio` can launch and talk to the shipped Stipul stdio MCP gateway.
- Writ remains the enforcement decision point through `ProxyServer.handle_tool_call(...)`.
- Allow, deny, approval-required, unknown-tool, and kill-switch outcomes are deterministic and structured.
- Chronicle evidence is written to authoritative `events.jsonl`.
- Seal verification still succeeds for intact demo evidence and fails after tampering.
- The integration was implemented without touching files outside `integrations/openai-agents/`.

## Not Yet Proven

- Full OpenAI Agents SDK `Agent` runs with live model tool planning through this boundary.
- Any Stipul-side SSE transport.
- Any Stipul-side HTTP or streamable HTTP transport.
- Multi-agent orchestration, approvals being granted and retried, or production operator workflows through this integration.
