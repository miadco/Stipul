# Stipul Quickstart — Claude Code in Read-Only Review Mode

Let Claude inspect your codebase. Block writes and shell commands. Verify the session stayed read-only with a sealed receipt.

**What you'll need:** Python 3.10+, Claude Code installed.

---

## Step 1 — Install Stipul

```bash
pipx install stipul
```

This installs the `stipul` command globally so Claude Code can find it. If you prefer `pip install stipul`, replace `"command": "stipul"` in `.mcp.json` with the full path from `which stipul`.

## Step 2 — Create a project directory

```bash
mkdir stipul-demo && cd stipul-demo
```

## Step 3 — Set the token secret

Stipul signs authorization tokens with a secret. This is required for the gateway path used in this demo.

```bash
export STIPUL_TOKEN_SECRET=$(openssl rand -hex 32)
```

## Step 4 — Create sample files

```bash
printf 'hello\n' > review-1.txt
printf 'world\n' > review-2.txt
```

## Step 5 — Create the charter

This charter puts Claude Code in read-only mode. `file.read` is the only permitted tool. Both `file.write` and `shell.exec` are unconditionally denied — the agent can look at everything but can't change or run anything.

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

## Step 6 — Create the MCP configuration

This tells Claude Code to route tool calls through Stipul's gateway. Every decision — allow or deny — is recorded in `./stipul-session/`.

```bash
cat > .mcp.json << 'EOF'
{
  "mcpServers": {
    "stipul": {
      "command": "stipul",
      "args": [
        "gateway", "mcp",
        "--contract", "./charter.yaml",
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

## Step 7 — Launch Claude Code

Launch Claude Code from this directory so it picks up the local `.mcp.json` configuration.

```bash
claude
```

## Step 8 — Run three prompts

Send these three prompts in order:

**Prompt 1** — read a file (expect: allowed):
> Use the file.read tool to read ./review-1.txt

**Prompt 2** — run a command (expect: denied):
> Use the shell.exec tool to run ls

**Prompt 3** — read another file (expect: allowed):
> Use the file.read tool to read ./review-2.txt

A deny does not end the session. Claude can continue using permitted tools afterward.

## Step 9 — Exit Claude Code

Exit Claude Code cleanly before running verify so the session can close and seal.

```bash
/exit
```

## Step 10 — Verify the session

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

## Enforcement boundaries

Stipul governs tools mounted through its MCP gateway. Claude Code may also have built-in tools outside that surface. A deny from Stipul applies to the governed MCP path, not necessarily to every native capability in the host.

## Optional — Inspect the Chronicle

The verify receipt tells you the session evidence is intact. The Chronicle shows what that evidence contains.

```bash
jq . ./stipul-session/events.jsonl
```

You'll see one event per line, including session lifecycle events and each tool-call decision. In this demo, the key events are:

* `file.read` → allowed
* `shell.exec` → denied
* `file.read` → allowed

Each event is timestamped and sequenced, so "read-only" is not just a claim — it is an itemized record.

## Troubleshooting

If you re-run the demo, delete the previous session first:

```bash
rm -rf ./stipul-session
```
