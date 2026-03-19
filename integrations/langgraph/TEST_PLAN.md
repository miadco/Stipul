# LangGraph Integration Test Plan

## Purpose

This plan gives a human reviewer a finite ritual to verify the current Stipul LangGraph integration without redesigning it.

The goal is to confirm that the shipped MCP-native stdio path is real, Writ stays at the enforcement boundary, Chronicle evidence lands in `events.jsonl`, and Seal verification still works on intact and tampered evidence.

## Supported Invocation Contract

- Supported demo command in this repo environment:

```bash
bash -lc 'bash integrations/langgraph/demo.sh' 2>&1 | tee integrations/langgraph/demo.transcript.txt
```

- This plan proves the direct `MultiServerMCPClient` tool-loading path used in a LangGraph integration path. It does not prove a full live-model LangGraph graph run.
- OL-008 — demo invocation sensitivity: plain non-login `bash integrations/langgraph/demo.sh` intermittently times out during MCP initialize; current supported workaround is `bash -lc 'bash integrations/langgraph/demo.sh'`; root cause not yet isolated.

## Environment Verification

Run these commands from the repo root:

```bash
test -f stipul/writ/proxy/server.py
rg -n "def handle_tool_call|def create_mcp_gateway" stipul/writ/proxy/server.py
rg -n "Run the MCP gateway over stdio|stdio_server" stipul/cli/gateway_cmd.py stipul/writ/proxy/mcp_gateway.py
.venv/bin/python -m pip show langgraph langchain-core langchain-mcp-adapters
.venv/bin/python -c "from langgraph.prebuilt import create_react_agent; from langchain_mcp_adapters.client import MultiServerMCPClient; from langchain_mcp_adapters.sessions import StdioConnection; print(create_react_agent); print(MultiServerMCPClient); print(StdioConnection)"
.venv/bin/python -c "import inspect; from langchain_mcp_adapters.client import MultiServerMCPClient; print(inspect.signature(MultiServerMCPClient.__init__))"
.venv/bin/python -c "import inspect; from langchain_mcp_adapters.sessions import StdioConnection; print(inspect.signature(StdioConnection))"
.venv/bin/python -c "from langchain_mcp_adapters.sessions import StdioConnection; print(StdioConnection); print(type(StdioConnection)); print(StdioConnection.__annotations__)"
```

Expected results:

- `stipul/writ/proxy/server.py` exists.
- `rg` shows `handle_tool_call` and `create_mcp_gateway` in `stipul/writ/proxy/server.py`.
- `rg` shows the Stipul gateway path is stdio-based in `stipul/cli/gateway_cmd.py` and `stipul/writ/proxy/mcp_gateway.py`.
- `.venv/bin/python -m pip show ...` reports `langgraph==1.1.2`, `langchain-core==1.2.18`, and `langchain-mcp-adapters==0.2.1`.
- The import command succeeds and prints `create_react_agent`, `MultiServerMCPClient`, and `StdioConnection`.
- `inspect.signature(MultiServerMCPClient.__init__)` prints the installed constructor signature.
- `inspect.signature(StdioConnection)` fails with `ValueError: no signature found for builtin type <class 'dict'>`.
- `StdioConnection.__annotations__` shows the effective stdio connection fields.

## Focused Integration Test Command

```bash
.venv/bin/python -m pytest integrations/langgraph/test_langgraph_stdio.py
```

Expected result:

- Exit code `0`
- Summary ends with `2 passed`

Artifacts:

- By default pytest uses temp directories.
- Use the scenario commands below for stable artifacts under `/tmp/stipul-langgraph-review`.

## Demo Command

```bash
bash -lc 'bash integrations/langgraph/demo.sh' 2>&1 | tee integrations/langgraph/demo.transcript.txt
```

Expected result:

- Exit code `0`
- `integrations/langgraph/demo.transcript.txt` is regenerated
- Transcript contains:
  - `## Scenario 1: allowed safe read`
  - `## Scenario 3: approval-gated irreversible action`
  - `## Scenario 6: evidence verification success via stipul verify`
  - `## Scenario 7: tamper verification failure after mutating events.jsonl`

Artifacts:

- `integrations/langgraph/demo.transcript.txt`
- `/tmp/stipul-langgraph-demo/allowed/contract.json`
- `/tmp/stipul-langgraph-demo/allowed/session/events.jsonl`
- `/tmp/stipul-langgraph-demo/allowed/home/.stipul/keys/runtime_*.pub`
- `/tmp/stipul-langgraph-demo/denied/session/events.jsonl`
- `/tmp/stipul-langgraph-demo/tampered-session/events.jsonl`

## Scenario Setup

Use a stable review output root for the targeted scenario runs:

```bash
REVIEW_ROOT=/tmp/stipul-langgraph-review
rm -rf "$REVIEW_ROOT"
```

## Scenario 1: Allowed Safe Read

Command:

```bash
STIPUL_LANGGRAPH_DEMO=1 STIPUL_LANGGRAPH_OUTPUT_DIR="$REVIEW_ROOT" .venv/bin/python -m pytest -s -q integrations/langgraph/test_langgraph_stdio.py::test_allowed_safe_read_returns_stable_output_and_writes_evidence
```

Expected result:

- Exit code `0`
- Output contains `## Scenario 1: allowed safe read`
- Output ends with `1 passed`

Artifacts to inspect:

- `$REVIEW_ROOT/allowed/allowed.txt`
- `$REVIEW_ROOT/allowed/contract.json`
- `$REVIEW_ROOT/allowed/session/events.jsonl`
- `$REVIEW_ROOT/allowed/home/.stipul/keys/runtime_*.pub`

Chronicle validation:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/allowed/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print([(event['sequence_id'], event['tool_name'], event['decision'], event['reason'], event['metadata']) for event in events])"
```

Expected Chronicle result:

- One event only
- The tuple shows `filesystem.read`, `allow`, `risk_class`
- Metadata is `{'ingress': 'mcp_gateway'}`

## Scenarios 2, 3, 4, and 5: Denied Write, Approval Required Delete, Unknown Tool Denial, Kill Switch

Command:

```bash
STIPUL_LANGGRAPH_DEMO=1 STIPUL_LANGGRAPH_OUTPUT_DIR="$REVIEW_ROOT" .venv/bin/python -m pytest -s -q integrations/langgraph/test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged
```

Expected result:

- Exit code `0`
- Output contains `## Scenario 3: approval-gated irreversible action`
- Output ends with `1 passed`

Artifacts to inspect:

- `$REVIEW_ROOT/denied/blocked.txt`
- `$REVIEW_ROOT/denied/contract.json`
- `$REVIEW_ROOT/denied/session/events.jsonl`
- `$REVIEW_ROOT/denied/session/operator_state.json`

Chronicle validation:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/denied/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print([(event['sequence_id'], event['tool_name'], event['decision'], event['reason']) for event in events]); print(events[1]['metadata']); print(events[4]['metadata'])"
```

Expected Chronicle result:

- Event sequence is:
  - `(1, 'filesystem.write', 'deny', 'not_in_contract')`
  - `(2, 'filesystem.delete', 'allow', 'approval_request_created')`
  - `(3, 'filesystem.delete', 'deny', 'approval_required')`
  - `(4, 'unknown.tool', 'deny', 'not_in_contract')`
  - `(5, 'filesystem.read', 'deny', 'kill_switch_active')`
- Event `2` metadata includes `approval_context`
- Event `5` metadata includes `operator_updated_by`

Scenario-specific checks:

- Scenario 2, denied dangerous write:

```bash
cat "$REVIEW_ROOT/denied/blocked.txt"
```

Expected result:

- File still contains `sensitive`

- Scenario 3, approval-gated irreversible action:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/denied/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print(events[1]['reason']); print(events[2]['reason'])"
```

Expected result:

- Prints `approval_request_created`
- Prints `approval_required`

- Scenario 4, unknown tool denied:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/denied/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print(events[3]['tool_name']); print(events[3]['decision']); print(events[3]['reason'])"
```

Expected result:

- Prints `unknown.tool`
- Prints `deny`
- Prints `not_in_contract`

- Scenario 5, kill switch enforced:

```bash
.venv/bin/python -c "import json; from pathlib import Path; print(json.loads(Path('$REVIEW_ROOT/denied/session/operator_state.json').read_text(encoding='utf-8'))['kill_switch_active'])"
```

Expected result:

- Prints `True`

## Scenario 6: Evidence Verification Success via stipul verify

Prerequisite:

- Run Scenario 1 first so `$REVIEW_ROOT/allowed/...` exists.

Commands:

```bash
PUBLIC_KEY="$(find "$REVIEW_ROOT/allowed/home/.stipul/keys" -maxdepth 1 -name 'runtime_*.pub' | sort | tail -n 1)"
.venv/bin/python -m stipul.cli.main verify --session-dir "$REVIEW_ROOT/allowed/session" --contract "$REVIEW_ROOT/allowed/contract.json" --public-key "$PUBLIC_KEY"
```

Expected result:

- Exit code `0`
- Output includes `Chain integrity: INTACT`
- Output includes `Signed events: 1 | Unsigned events: 0`

Artifacts to inspect:

- `$REVIEW_ROOT/allowed/session/events.jsonl`
- `$REVIEW_ROOT/allowed/contract.json`
- `$REVIEW_ROOT/allowed/home/.stipul/keys/runtime_*.pub`

## Scenario 7: Tamper Verification Failure After Mutating events.jsonl

Prerequisite:

- Run Scenario 6 commands first so `PUBLIC_KEY` is set.

Commands:

```bash
cp -R "$REVIEW_ROOT/allowed/session" "$REVIEW_ROOT/tampered-session"
.venv/bin/python -c "from pathlib import Path; import sys; sys.path.insert(0, 'integrations/langgraph'); from langgraph_stdio import tamper_last_event; tamper_last_event(Path('$REVIEW_ROOT/tampered-session/events.jsonl'))"
set +e
.venv/bin/python -m stipul.cli.main verify --session-dir "$REVIEW_ROOT/tampered-session" --contract "$REVIEW_ROOT/allowed/contract.json" --public-key "$PUBLIC_KEY"
echo "exit_code=$?"
set -e
```

Expected result:

- Output includes `Chain integrity: BROKEN`
- Output includes `SignatureFailure: signature_invalid`
- The printed `exit_code` is non-zero; in the current transcript it is `2`

Artifacts to inspect:

- `$REVIEW_ROOT/tampered-session/events.jsonl`
- `$REVIEW_ROOT/allowed/session/events.jsonl`

## Chronicle Validation Steps

Allowed path:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/allowed/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print(events[0]['event_type']); print(events[0]['decision']); print(events[0]['metadata'])"
```

Expected result:

- Prints `tool_call`
- Prints `allow`
- Prints `{'ingress': 'mcp_gateway'}`

Denied path:

```bash
.venv/bin/python -c "import json; from pathlib import Path; events=[json.loads(line) for line in Path('$REVIEW_ROOT/denied/session/events.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]; print([event['reason'] for event in events]); print(events[1]['metadata']['approval_context']['status']); print(events[4]['metadata']['operator_updated_by'])"
```

Expected result:

- Prints the ordered reasons `['not_in_contract', 'approval_request_created', 'approval_required', 'not_in_contract', 'kill_switch_active']`
- Prints `pending`
- Prints `operator@example.com`

## Negative-Path Checks

Denied action, unknown tool, and kill switch:

- Covered by the Scenarios 2, 4, and 5 commands above.
- Reviewer should confirm the ordered denied-path Chronicle events and unchanged `blocked.txt`.

Malformed or incomplete input sanity check:

```bash
set +e
.venv/bin/python -c "import sys; sys.path.insert(0, 'integrations/langgraph'); from langgraph_stdio import execute_tool; execute_tool({'tool_name':'filesystem.read','inputs':{}})"
echo "exit_code=$?"
set -e
```

Expected result:

- Output ends with `ValueError: path must be a non-empty string`
- `exit_code` is non-zero
- No Chronicle artifact is expected from this command because it is a local runtime input-validation check, not a Writ-mediated MCP run

## Manual Audit Checklist

- Confirm `integrations/langgraph/langgraph_stdio.py` imports `MultiServerMCPClient` and `StdioConnection` from `langchain_mcp_adapters`.
- Confirm `StipulLangGraphConfig.connection()` builds a stdio `TypedDict` config and does not use `tool_interceptors`.
- Confirm `runtime_spec()` resolves to `langgraph_stdio:build_runtime`.
- Confirm the gateway launch path in `StipulLangGraphConfig.connection()` uses `.venv/bin/python -m stipul.cli.main gateway mcp`.
- Confirm the integration proves the direct `MultiServerMCPClient` tool-loading path, not a full live-model graph run.
- Confirm the authoritative evidence file inspected in every scenario is `events.jsonl`.
- Confirm denied outcomes return structured reasons and do not silently mutate `blocked.txt`.
- Confirm intact evidence verifies and tampered evidence fails verification.
