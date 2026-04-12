# Sunday Demo Runbook

For the canonical first-run gateway path, start with [README.md](/home/michael/Downloads/stipul/README.md).
This runbook is the deeper source-checkout-oriented proof/demo path.

For the packaged screenshot demo, use `stipul demo proof`.
That command ships its own Charter, prints the trust receipt directly, and guides the `seal.json` tamper step.

This is still a source-checkout demo, not a clean-install operator workflow.

It intentionally uses repo-local assets because the current repo does not ship a smaller packaged demo path:

- `.venv`
- `tests/cli_support.py`
- `tests/fixtures/base_contract.json`

The demo keeps runtime key material local by setting `HOME="$PWD/.demo-run"`.
It also sets a local `STIPUL_TOKEN_SECRET` for the proxy snippets that mint execution tokens.
You may also see `Token secret isolation could not be verified...` during the local proxy snippets; that is expected in this one-process demo because no separate agent PID is supplied.

## 1. Create a clean demo workspace

```bash
rm -rf .demo-run

HOME="$PWD/.demo-run" .venv/bin/python - <<'PY'
from pathlib import Path
from tests.cli_support import write_contract_file

root = Path(".demo-run")
root.mkdir(parents=True, exist_ok=True)
contract_path, _ = write_contract_file(root)
(root / "session").mkdir(parents=True, exist_ok=True)

print(f"contract={contract_path}")
print(f"session_dir={root / 'session'}")
print(f"home={root}")
PY
```

## 2. Normal allow

```bash
export STIPUL_TOKEN_SECRET=demo-secret

HOME="$PWD/.demo-run" .venv/bin/python - <<'PY'
from pathlib import Path
from stipul.writ.proxy.server import ProxyServer

root = Path(".demo-run")
proxy = ProxyServer.from_contract_path(
    root / "contract.json",
    session_id="11111111-1111-1111-1111-111111111111",
    events_path=root / "session" / "events.jsonl",
)
try:
    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "hello"}},
        lambda request: {"ok": True, "tool_name": request["tool_name"]},
    )
    print(response)
finally:
    proxy.close()
PY
```

Expected result at a high level:

```text
{'ok': True, 'tool_name': 'filesystem.write'}
```

## 3. Show status and enable the kill switch

```bash
HOME="$PWD/.demo-run" .venv/bin/python -m stipul.cli.main operator status \
  --session-dir .demo-run/session \
  --contract .demo-run/contract.json

HOME="$PWD/.demo-run" .venv/bin/python -m stipul.cli.main operator kill-switch enable \
  --session-dir .demo-run/session \
  --contract .demo-run/contract.json \
  --by operator@example.com \
  --reason operator_kill_switch_enabled
```

Expected result at a high level after enable:

```text
status: healthy
kill_switch_active: true
operator_updated_at: <timestamp>
operator_updated_by: operator@example.com
operator_reason: operator_kill_switch_enabled
```

## 4. Confirm the next action is denied

```bash
HOME="$PWD/.demo-run" .venv/bin/python - <<'PY'
from pathlib import Path
from stipul.writ.proxy.server import ProxyServer

root = Path(".demo-run")
proxy = ProxyServer.from_contract_path(
    root / "contract.json",
    session_id="11111111-1111-1111-1111-111111111111",
    events_path=root / "session" / "events.jsonl",
)
try:
    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "blocked.txt", "content": "x"}},
        lambda request: {"ok": True, "tool_name": request["tool_name"]},
    )
    print(response)
finally:
    proxy.close()
PY
```

Expected result at a high level:

```text
{'decision': 'deny', 'reason': 'kill_switch_active', 'tool_name': 'filesystem.write'}
```

## 5. Disable the kill switch and allow again

```bash
HOME="$PWD/.demo-run" .venv/bin/python -m stipul.cli.main operator kill-switch disable \
  --session-dir .demo-run/session \
  --contract .demo-run/contract.json \
  --by operator@example.com \
  --reason operator_kill_switch_disabled

HOME="$PWD/.demo-run" .venv/bin/python - <<'PY'
from pathlib import Path
from stipul.writ.proxy.server import ProxyServer

root = Path(".demo-run")
proxy = ProxyServer.from_contract_path(
    root / "contract.json",
    session_id="11111111-1111-1111-1111-111111111111",
    events_path=root / "session" / "events.jsonl",
)
try:
    response = proxy.handle_tool_call(
        {"tool_name": "filesystem.write", "inputs": {"path": "after-disable.txt", "content": "ok"}},
        lambda request: {"ok": True, "tool_name": request["tool_name"]},
    )
    print(response)
finally:
    proxy.close()
PY
```

Expected result at a high level after disable:

```text
{'ok': True, 'tool_name': 'filesystem.write'}
```

## 6. Inspect the evidence rows

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path

events = [
    json.loads(line)
    for line in Path(".demo-run/session/events.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]

interesting = [
    {
        "sequence_id": event["sequence_id"],
        "event_type": event["event_type"],
        "decision": event["decision"],
        "reason": event["reason"],
        "tool_name": event["tool_name"],
    }
    for event in events
    if event["reason"] in {
        "operator_kill_switch_enabled",
        "kill_switch_active",
        "operator_kill_switch_disabled",
    }
]

print(json.dumps(interesting, indent=2))
PY
```

You should see these rows in order:

- enable: `event_type="elev_op"`, `decision="allow"`, `reason="operator_kill_switch_enabled"`
- deny: `event_type="tool_call"`, `decision="deny"`, `reason="kill_switch_active"`
- disable: `event_type="elev_op"`, `decision="allow"`, `reason="operator_kill_switch_disabled"`

## 7. Cleanup

```bash
unset STIPUL_TOKEN_SECRET
rm -rf .demo-run
```
