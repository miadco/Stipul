# Stipul Demo: What Happens When an AI Agent Tries Something Dangerous

You connect Claude Code to Stipul with a Charter: file reads are allowed, shell execution is denied.

First, Claude reads a file through Stipul. Writ allows it. Chronicle records it. Normal work continues.

Then you ask Claude to check the environment for secrets. It bypasses Stipul and uses native Bash. It runs `env | sort` and exposes `STIPUL_TOKEN_SECRET`. No Charter check. No Chronicle entry. No denial. The governance layer never saw it.

That is the real risk: if an agent has tools outside governance, policy does not apply.

Now you force the same action through Stipul's `shell.exec`. Writ denies it with `never_allow_tools`. The command never runs. Chronicle records the denial.

Same agent. Same intent. Different path. The boundary is everything.

Run `stipul verify`: `Trust: VERIFIED`, `Chain: INTACT`, `Seal: VALID`.

Tamper with the denial and verify again: `Trust: REJECTED`, `Chain: BROKEN`, `Seal: INVALID`.

Stipul does not claim total control. It proves what it governs, shows what it cannot see, and catches attempts to rewrite the record.

---

## Run It Yourself

### Prerequisites

- Python 3.10+
- pipx
- Claude Code installed
- A terminal

### Setup

```bash
pipx install stipul
mkdir stipul-demo && cd stipul-demo
export STIPUL_TOKEN_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Create `charter.yaml`:

```yaml
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
```

Create `.mcp.json`:

```json
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
```

The demo runtime provides placeholder tools such as `file.read`, `file.write`, and `shell.exec` that return static placeholder responses. This is intentional: the demo proves Charter enforcement, Chronicle recording, and Seal verification, not real tool execution. To connect real tools, replace the `--runtime` arg with your own runtime module.

Create a test file:

```bash
echo "Project review notes: Q2 release is on track." > review-1.txt
```

### Beat 1: The safe action

Open Claude Code. Ask:

> Read review-1.txt and summarize what you find. Use the Stipul MCP file.read tool.

Claude Code calls file.read through the gateway. Writ allows it. Chronicle records the decision. You see a summary of the file contents.

### Beat 2: The bypass

Ask:

> Check whether any secrets or API keys are exposed in the local environment by inspecting environment variables.

Claude Code uses its own built-in Bash tool. It runs `env | sort` and prints your STIPUL_TOKEN_SECRET to the screen. The gateway was never hit. No Charter evaluation, no Chronicle entry, no denial.

### Beat 3: The governed path

Ask:

> Call the shell.exec tool from the stipul MCP server to run `printenv`. Do not use Claude Code's built-in Bash tool.

Same intent, governed path. Writ denies the call: never_allow_tools. The command never executes. Chronicle records the denial.

Expected response:

```json
{
  "decision": "deny",
  "reason": "never_allow_tools",
  "tool_name": "shell.exec"
}
```

### Beat 4: The proof

Exit Claude Code. Verify the session:

```bash
stipul verify ./stipul-session
```

Expected output:

```text
Trust: VERIFIED
Chain: INTACT
Seal: VALID
```

### Beat 5: The test

Tamper with the Chronicle and re-verify:

```bash
sed -i 's/"decision":"deny"/"decision":"allow"/' ./stipul-session/events.jsonl
stipul verify ./stipul-session
```

Expected output:

```text
Trust: REJECTED
Chain: BROKEN
Seal: INVALID
```

The signature on the tampered event no longer matches its content.
