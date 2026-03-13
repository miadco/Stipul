#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_ROOT="/tmp/stipul-langgraph-demo"
TEST_NODES=(
  "integrations/langgraph/test_langgraph_stdio.py::test_allowed_safe_read_returns_stable_output_and_writes_evidence"
  "integrations/langgraph/test_langgraph_stdio.py::test_denied_and_kill_switch_paths_are_structured_and_logged"
)

cd "$REPO_ROOT"
rm -rf "$OUTPUT_ROOT"

printf '## Startup\n'
printf 'repo_root=%s\n' "$REPO_ROOT"
printf 'output_dir=%s\n' "$OUTPUT_ROOT"
printf 'demo_mode=source_checkout_only\n'
printf 'transport=MultiServerMCPClient.get_tools() -> StdioConnection -> stipul gateway mcp stdio\n'
printf 'proof_boundary=direct LangGraph MCP client path\n'
printf '## Demo Execution\n'
printf '$ %s\n' "STIPUL_LANGGRAPH_DEMO=1 STIPUL_LANGGRAPH_OUTPUT_DIR=$OUTPUT_ROOT .venv/bin/python -m pytest -s -q ${TEST_NODES[*]}"
STIPUL_LANGGRAPH_DEMO=1 \
STIPUL_LANGGRAPH_OUTPUT_DIR="$OUTPUT_ROOT" \
  .venv/bin/python -m pytest -s -q "${TEST_NODES[@]}"
printf '[exit_code=0]\n'

PUBLIC_KEY="$(find "$OUTPUT_ROOT/allowed/home/.stipul/keys" -maxdepth 1 -name 'runtime_*.pub' | sort | tail -n 1)"
printf '## Scenario 6: evidence verification success via stipul verify\n'
printf '$ %s\n' ".venv/bin/python -m stipul.cli.main verify --session-dir $OUTPUT_ROOT/allowed/session --contract $OUTPUT_ROOT/allowed/contract.json --public-key $PUBLIC_KEY"
.venv/bin/python -m stipul.cli.main verify \
  --session-dir "$OUTPUT_ROOT/allowed/session" \
  --contract "$OUTPUT_ROOT/allowed/contract.json" \
  --public-key "$PUBLIC_KEY"
printf '[exit_code=0]\n'

cp -R "$OUTPUT_ROOT/allowed/session" "$OUTPUT_ROOT/tampered-session"
printf '$ %s\n' ".venv/bin/python -c \"from pathlib import Path; import sys; sys.path.insert(0, '$REPO_ROOT/integrations/langgraph'); from langgraph_stdio import tamper_last_event; tamper_last_event(Path('$OUTPUT_ROOT/tampered-session/events.jsonl'))\""
.venv/bin/python -c "from pathlib import Path; import sys; sys.path.insert(0, '$REPO_ROOT/integrations/langgraph'); from langgraph_stdio import tamper_last_event; tamper_last_event(Path('$OUTPUT_ROOT/tampered-session/events.jsonl'))"

printf '## Scenario 7: tamper verification failure after mutating events.jsonl\n'
printf '$ %s\n' ".venv/bin/python -m stipul.cli.main verify --session-dir $OUTPUT_ROOT/tampered-session --contract $OUTPUT_ROOT/allowed/contract.json --public-key $PUBLIC_KEY"
set +e
.venv/bin/python -m stipul.cli.main verify \
  --session-dir "$OUTPUT_ROOT/tampered-session" \
  --contract "$OUTPUT_ROOT/allowed/contract.json" \
  --public-key "$PUBLIC_KEY"
code=$?
set -e
printf '[exit_code=%s]\n' "$code"
test "$code" -ne 0
