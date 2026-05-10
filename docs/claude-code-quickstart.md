# Claude Code Quickstart: Govern Claude Before Tool Execution

An agent reviews your code. Then it asks for authority that could expose secrets. Stipul allows normal work, denies risky tool use before execution, records the decision, and verifies the session afterward.

Claude reviews local project files under Stipul control. **Writ** enforces the **Charter** before tool execution, the **Chronicle** records every allow and deny decision, and the **Seal** verifies the session afterward.

**What you'll need:** Python 3.10+, Claude Code installed.

---

## Step 1 — Install Stipul

```bash
pipx install stipul
```

## Step 2 — Prove the packaged path first

```bash
stipul init
stipul demo proof
stipul verify <session-dir>
stipul report <session-dir>
```

Use the `<session-dir>` path printed by `stipul demo proof`.

## Step 3 — Create a project directory

```bash
mkdir stipul-demo && cd stipul-demo
```

## Step 4 — Set the token secret

Stipul signs authorization tokens with a secret. This is required for the gateway path used in this demo.

```bash
export STIPUL_TOKEN_SECRET=$(openssl rand -hex 32)
```

## Step 5 — Create sample files

```bash
cat > review-1.txt << 'EOF'
Release note draft:
- Add structured denial reasons to the tool audit log.
- Follow-up: confirm the reviewer can still inspect files after a denied action.

Pseudo code:
if decision == "deny":
    record_reason()
    continue_review = true
EOF

cat > review-2.txt << 'EOF'
Remediation note:
- Keep shell execution blocked for review sessions.
- Continue allowing local file reads needed for code review.
- Verify the sealed session after the review completes.
EOF
```

## Step 6 — Create the charter

This Charter lets Claude review local files while denying higher-risk authority. `file.read` is the only permitted tool. Both `file.write` and `shell.exec` are unconditionally denied. Claude can inspect project files, but **Writ** will block command execution before it runs.

```bash
cat > charter.yaml << 'EOF'
schema_version: "1.0"
contract_id: "de000001-0001-0001-0001-000000000001"
parent_contract_id: null
created_at: "2026-01-01T00:00:00Z"
expires_at: "2099-01-01T00:00:00Z"
signed_by: null
identity_agent_id: "claude-code-review"
identity_code_sha256: null
allowed_tools:
  - "file.read"
never_allow_tools:
  - "file.write"
  - "shell.exec"
tool_risk_classes:
  file.read: "read"
  file.write: "write"
  shell.exec: "irreversible"
max_tool_calls: 10
max_net_calls: 0
egress_allowlist: []
EOF
```

## Step 7 — Create the MCP configuration

This tells Claude Code to route tool calls through Stipul's gateway. Every decision — allow or deny — is recorded in `./stipul-session/` for the **Chronicle**, then sealed when the session closes.

```bash
cat > .mcp.json << 'EOF'
{
  "mcpServers": {
    "stipul": {
      "command": "stipul",
      "args": [
        "gateway", "mcp",
        "--charter", "./charter.yaml",
        "--tool-visibility", "governed",
        "--session-dir", "./stipul-session",
        "--session-id", "de000001-0001-0001-0001-000000000001",
        "--runtime", "stipul.examples.demo_runtime:build_runtime"
      ],
      "env": {
        "STIPUL_TOKEN_SECRET": "${STIPUL_TOKEN_SECRET}"
      }
    }
  }
}
EOF
```

The demo runtime provides placeholder tools such as `file.read`, `file.write`, and `shell.exec` that return static placeholder responses. This is intentional: the demo proves Charter enforcement, Chronicle recording, and Seal verification, not real tool execution. To connect real tools, replace the `--runtime` arg with your own runtime module.

## Step 8 — Launch Claude Code

Launch Claude Code from this directory so it picks up the local `.mcp.json` configuration.

```bash
claude
```

## Step 9 — Run three prompts

Send these three prompts in order:

**Prompt 1** — ALLOW:
> Read review-1.txt and summarize what you find.

Expected outcome: Claude requests a local file read. **Writ** allows it under the Charter.

**Prompt 2** — DENY:
> Check whether any secrets or API keys are exposed in the local environment by inspecting environment variables.

Expected outcome: this is an explicit attempted denied action. **Writ** denies `shell.exec` under the Charter before execution.

If Claude does not request shell execution, use this more explicit prompt: Check whether any secrets or API keys are exposed in the local environment by running a command such as printenv.

**Prompt 3** — ALLOW:
> Read review-2.txt and summarize what you find.

Expected outcome: Claude requests another local file read. **Writ** allows it, showing that a denial does not end the session.

A deny does not end the session. Claude can continue using permitted tools afterward.

## Step 10 — Exit Claude Code

Exit Claude Code cleanly before running verify so the session can close and seal.

```bash
/exit
```

## Step 11 — Verify the session

```bash
stipul verify ./stipul-session
```

Expected output:

```text
Verification receipt
Session: de000001-0001-0001-0001-000000000001
Trust: VERIFIED
Chain: INTACT
Seal: VALID
```

The session stayed read-only, and Stipul can prove it. Every tool call decision is in `./stipul-session/events.jsonl` — deterministic enforcement, append-only evidence, cryptographic proof.

---

## Inspect the Chronicle

The verify receipt tells you the session evidence is intact. The **Chronicle** shows the evidence record itself: Claude was allowed to read approved files, denied shell authority before execution, and then continued operating within policy.

```bash
jq . ./stipul-session/events.jsonl
```

You'll see one event per line, including session lifecycle events and each tool-call decision. In this demo, the key events are:

* `file.read` → allowed
* `shell.exec` → denied
* `file.read` → allowed

Each event is timestamped and sequenced, so the session is not just a claim of control. It is an itemized record of what Claude was allowed to do, what it was denied, and how the review continued afterward.

## Enforcement boundaries

Stipul governs tools mounted through its MCP gateway. Claude Code may also have built-in tools outside that surface. A deny from Stipul applies to the governed MCP path, not necessarily to every native capability in the host.

## Troubleshooting

If you re-run the demo, delete the previous session first:

```bash
rm -rf ./stipul-session
```
