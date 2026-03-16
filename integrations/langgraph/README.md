> Start with the [root README](../../README.md) for the native demo and supported-path overview.

# LangGraph Integration

## What This Integration Is

This is the second Stipul integration, proving the LangGraph-side MCP client path over stdio.

It proves the narrow boundary where LangGraph-compatible MCP tool activity goes through Writ, Writ enforces the Charter, Chronicle records the decision in `events.jsonl`, and Seal verification still works on the resulting evidence.

This proves mediation for the direct `MultiServerMCPClient` tool-loading path used in a LangGraph integration path only. It does not claim full LangGraph graph execution with a live model.

## Attach Point

- Writ enforcement boundary: `stipul/writ/proxy/server.py`
- Exact method: `ProxyServer.handle_tool_call(raw_request, forward_call)`
- Existing MCP gateway hook: `ProxyServer.create_mcp_gateway(...)`
- Existing shipped transport path: `stipul/cli/gateway_cmd.py -> stipul/writ/proxy/mcp_gateway.py`

This integration does not add a second enforcement path, a second evidence path, or a second ledger.

## SDK Inspection Evidence

Exact commands used with the project venv:

```bash
.venv/bin/python -m pip show langgraph langchain-core langchain-mcp-adapters
.venv/bin/python -c "from langgraph.prebuilt import create_react_agent; from langchain_mcp_adapters.client import MultiServerMCPClient; from langchain_mcp_adapters.sessions import StdioConnection; print(create_react_agent); print(MultiServerMCPClient); print(StdioConnection)"
.venv/bin/python -c "import inspect; from langchain_mcp_adapters.client import MultiServerMCPClient; print(inspect.signature(MultiServerMCPClient.__init__))"
.venv/bin/python -c "import inspect; from langchain_mcp_adapters.sessions import StdioConnection; print(inspect.signature(StdioConnection))"
.venv/bin/python -c "from langchain_mcp_adapters.sessions import StdioConnection; print(StdioConnection); print(type(StdioConnection)); print(StdioConnection.__annotations__)"
```

Observed results from this repo environment:

```text
Name: langgraph
Version: 1.1.2
Name: langchain-core
Version: 1.2.18
Name: langchain-mcp-adapters
Version: 0.2.1
```

```text
<function create_react_agent at ...>
<class 'langchain_mcp_adapters.client.MultiServerMCPClient'>
<class 'langchain_mcp_adapters.sessions.StdioConnection'>
```

```text
(self, connections: dict[str, langchain_mcp_adapters.sessions.StdioConnection | langchain_mcp_adapters.sessions.SSEConnection | langchain_mcp_adapters.sessions.StreamableHttpConnection | langchain_mcp_adapters.sessions.WebsocketConnection] | None = None, *, callbacks: langchain_mcp_adapters.callbacks.Callbacks | None = None, tool_interceptors: list[langchain_mcp_adapters.interceptors.ToolCallInterceptor] | None = None, tool_name_prefix: bool = False) -> None
```

```text
ValueError: no signature found for builtin type <class 'dict'>
```

```text
<class 'langchain_mcp_adapters.sessions.StdioConnection'>
<class 'typing_extensions._TypedDictMeta'>
{
  'transport': Literal['stdio'],
  'command': str,
  'args': list[str],
  'env': NotRequired[dict[str, str] | None],
  'cwd': NotRequired[str | Path | None],
  'encoding': NotRequired[str],
  'encoding_error_handler': NotRequired[EncodingErrorHandler],
  'session_kwargs': NotRequired[dict[str, Any] | None]
}
```

Discovered MCP-relevant symbols:

- `langchain_mcp_adapters.client.MultiServerMCPClient`
- `langchain_mcp_adapters.sessions.StdioConnection`
- `langgraph.prebuilt.create_react_agent`

Design conclusion:

- LangGraph-side MCP integration is valid through `MultiServerMCPClient` with a stdio connection config.
- In this installed version, `StdioConnection` is a `TypedDict` transport shape, not a callable constructor with a normal `inspect.signature(...)` result.
- The correct stdio config shape is a `TypedDict` with `transport`, `command`, `args`, and optional `env` and `cwd`.
- Stipul's shipped gateway surface is stdio-only, so this integration uses `StdioConnection` to launch the existing Stipul stdio MCP gateway.
- `tool_interceptors` is not used for enforcement. Writ remains the enforcement boundary.
- `create_react_agent` imports successfully but is not used for proof here, because this first LangGraph pass avoids adding a live model dependency.

## Design Decision

This integration uses MCP-native stdio with `MultiServerMCPClient` and `StdioConnection`.

The launched server path is the existing Stipul stdio MCP gateway:

```text
.venv/bin/python -m stipul.cli.main gateway mcp --contract ... --session-dir ... --session-id ... --runtime langgraph_stdio:build_runtime
```

The integration module in this directory does three jobs only:

- build the `StdioConnection` config for the existing Stipul gateway
- load LangChain-compatible tools through `MultiServerMCPClient.get_tools()`
- provide the deterministic gateway runtime factory `build_runtime(...)` used by that existing gateway path

`tool_interceptors` is not used for enforcement. Writ remains the enforcement decision point.

## Run Instructions

Run the real demo and regenerate the transcript:

```bash
bash -lc 'bash integrations/langgraph/demo.sh' 2>&1 | tee integrations/langgraph/demo.transcript.txt
```

Human reviewer ritual:

```text
integrations/langgraph/TEST_PLAN.md
```

The demo creates fresh artifacts under:

```text
/tmp/stipul-langgraph-demo/
```

This is a source-checkout-only demo path. It reuses the focused integration test nodes to exercise the real LangGraph MCP client boundary and then runs `stipul verify` over the resulting evidence.

The login-shell wrapper above is a documented workaround, not a resolved fix. In this repo environment, the plain non-login invocation `bash integrations/langgraph/demo.sh` intermittently times out during MCP initialize. See `integrations/langgraph/TEST_PLAN.md` for the supported reviewer path.

## Demo Output

During source-checkout demo runs, you may see `Token secret isolation could not be verified. Ensure STIPUL_TOKEN_SECRET is not accessible to the agent process.` on stderr.

This is expected in the local demo layout because the gateway is launched from the same source checkout and process tree as the calling integration client, so startup cannot verify the production isolation boundary.

In production, the gateway and agent run in separate process trees, so token secret isolation is verifiable.

This warning does not change enforcement decisions, Chronicle evidence writes, or `stipul verify` results.

LangGraph opens multiple MCP stdio sessions during the demo flow, so the warning may appear multiple times. That is expected.

## Test Instructions

Run the focused integration test file:

```bash
.venv/bin/python -m pytest integrations/langgraph/test_langgraph_stdio.py
```

Optional targeted checks used for this work:

```bash
.venv/bin/python -m ruff check integrations/langgraph
.venv/bin/python -m mypy integrations/langgraph/langgraph_stdio.py integrations/langgraph/test_langgraph_stdio.py
```

## Scenario Proof Matrix

| Scenario | Expected Result | Actual Result | Evidence Location | Status |
|---|---|---|---|---|
| allowed safe read | `filesystem.read` is allowed, returns a stable payload, and Chronicle logs an allow event | `MultiServerMCPClient` loaded the tool, the LangGraph-side tool call returned a stable payload, and `events.jsonl` recorded `allow/risk_class` | `demo.transcript.txt` section `## Scenario 1: allowed safe read`; `test_langgraph_stdio.py::test_allowed_safe_read_returns_stable_output_and_writes_evidence` | PASS |
| denied dangerous write | `filesystem.write` is blocked before execution with a structured denial and evidence write | `ToolException` carried `{"decision":"deny","reason":"not_in_contract","tool_name":"filesystem.write"}` and the file content stayed unchanged | `test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| approval-gated irreversible or exfil-risk action | irreversible action is not executed and returns a structured, auditable gated result | `filesystem.delete` returned `approval_required` and Chronicle recorded approval metadata without deleting the file | `demo.transcript.txt` section `## Scenario 3: approval-gated irreversible action`; `test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| unknown tool denied | unknown tool is denied deterministically before execution | raw MCP call through `MultiServerMCPClient.session(...)` returned `not_in_contract` and Chronicle recorded the denial | `test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| kill switch enforced | once operator state enables the kill switch, the next tool call is denied with operator metadata | `filesystem.read` returned `kill_switch_active` and the denial event carried operator fields | `test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged` | PASS |
| evidence verification success via `stipul verify` | Seal-compatible evidence verifies successfully after the mediated run | `stipul verify` returned exit code `0` for the intact session | `demo.transcript.txt` section `## Scenario 6: evidence verification success via stipul verify` | PASS |
| tamper verification failure after mutating `events.jsonl` | mutating `events.jsonl` breaks verification and is reported explicitly | after mutating the last event reason, `stipul verify` returned a non-zero exit code for the tampered session | `demo.transcript.txt` section `## Scenario 7: tamper verification failure after mutating events.jsonl` | PASS |

## Known Limitations

- This proves mediation for the direct LangGraph MCP client path only.
- This does not yet prove full LangGraph graph execution with a live model making tool-planning decisions.
- This does not yet prove every LangGraph execution mode.
- This does not yet prove production deployment hardening.
- This does not yet prove SSE or HTTP transport support on the Stipul side.
- `create_react_agent` was inspected but is not exercised in this proof path.
- The runtime factory in this directory is intentionally small and deterministic. It is not a general runtime framework.
- OL-008 — demo invocation sensitivity: plain non-login `bash integrations/langgraph/demo.sh` intermittently times out during MCP initialize; current supported workaround is `bash -lc 'bash integrations/langgraph/demo.sh'`; root cause not yet isolated.

## Proven

- `MultiServerMCPClient` can launch and talk to the shipped Stipul stdio MCP gateway through `StdioConnection`.
- Writ remains the enforcement decision point through `ProxyServer.handle_tool_call(...)`.
- Allow, deny, approval-required, unknown-tool, and kill-switch outcomes are deterministic and structured.
- Chronicle evidence is written to authoritative `events.jsonl`.
- Seal verification still succeeds for intact demo evidence and fails after tampering.
- The integration does not use `tool_interceptors` for enforcement.
- The integration was implemented without touching files outside `integrations/langgraph/`.

## Not Yet Proven

- Full LangGraph graph execution with a live model.
- Any Stipul-side SSE transport.
- Any Stipul-side HTTP or streamable HTTP transport.
- Multi-agent orchestration, approvals being granted and retried, or production operator workflows through this integration.
