# Stipul

Your agents act. Can you prove what they did?

## What Stipul does

Stipul is an agent authorization and audit platform for AI agents. It intercepts tool calls, enforces policy, and produces a cryptographic proof chain for what actually happened. Writ enforces the Charter, records every decision in the Chronicle, and produces a Seal.

## See it work — the stranger proof path

Install the CLI from PyPI for Python 3.10+.

```bash
pip install stipul
```

Write a starter Charter in the current directory.

```bash
stipul init
```

Run the proof demo; it uses the packaged demo Charter at `stipul/demo/demo_charter.yaml`.

```bash
stipul demo proof
```

Your session directory, UUID, fingerprint, timestamps, and key ID will differ on each run.

```text
═══ Stipul Proof Demo ═══

Session: 2553f1a1-4f30-4459-8d71-e392f7e99026

  seq 1  allow   filesystem.read      reason: allowed_tool
  seq 2  deny    web.search           reason: not_in_egress_allowlist
  seq 3  deny    shell.exec           reason: never_allow_tools
  seq 4  close   session_close

Trust: VERIFIED
  Chain: INTACT
  Seal:  VALID
  Decisions: 3
  Fingerprint: 2553f1a1-4f30-4459-8d71-e392f7e99026 | INTACT | VALID | 3 decisions | fbac1645

═══ Tamper Challenge ═══

The seal records a cryptographic attestation over the session evidence.
Inspect it yourself, verify the session as-is, then change a recorded value and re-verify.

Step 1 — View the current seal:

  cat /tmp/stipul-proof-demo-6bvk92n7/session/seal.json | python3 -m json.tool

Step 2 — Verify the session as-is:

  stipul verify /tmp/stipul-proof-demo-6bvk92n7/session

Step 3 — Now tamper with the seal:

  sed -i 's/"terminal_sequence_id": 5/"terminal_sequence_id": 999/' /tmp/stipul-proof-demo-6bvk92n7/session/seal.json

  Or try a different recorded value in seal.json and re-verify.

  sed -i 's/"version": 1/"version": 42/' /tmp/stipul-proof-demo-6bvk92n7/session/seal.json

Step 4 — Re-verify the session:

  stipul verify /tmp/stipul-proof-demo-6bvk92n7/session

Proof complete: enforcement decisions recorded, chained, and sealed.
```

Use the `/tmp/.../session` path shown above as `<session-dir>` in the next two commands.

The demo runs locally with no external dependencies or framework integration.

Copy the `/tmp/.../session` path from the demo output and run:

```bash
stipul verify <session-dir>
```

```text
Verification receipt
Session: 2553f1a1-4f30-4459-8d71-e392f7e99026
Trust: VERIFIED
Chain: INTACT
Seal: VALID
Terminal: seq=5 at 2026-04-03T04:38:25.074446Z
Key: af81a010
```

Use that same `<session-dir>` to render the plain-language report:

```bash
stipul report <session-dir>
```

```text
1. What session is this?
Session ID: aa4373bc-c136-4deb-b462-0648a467555c
Charter ID: d3a00001-0001-0001-0001-000000000001
Time range: 2026-04-09T01:23:07.357093Z to 2026-04-09T01:23:07.370300Z

2. What did the agent try to do?
1. Attempted filesystem.read on path=/docs/report.md.
2. Attempted web.search on egress_target=evil.example.com.
3. Attempted shell.exec with command="rm -rf /".

3. What did Stipul decide for each one?
1. filesystem.read was allowed under the charter's risk class policy. (seq 2)
2. web.search was denied. Reason: not in egress allowlist. Rule: egress not allowed. (seq 3)
3. shell.exec was denied. Reason: never allow tools. Rule: never allow tools. (seq 4)

4. Did anything policy-significant happen?
1. A call was denied by policy. Tool: web.search. Reason: not in egress allowlist. Rule: egress not allowed. Details: egress_target=evil.example.com. (seq 3)
2. A call was denied by policy. Tool: shell.exec. Reason: never allow tools. Rule: never allow tools. Details: command="rm -rf /". (seq 4)

5. Can I trust this record?
Fresh verification only.
Trust: VERIFIED
Chain: INTACT
Seal: VALID
```

## What you just saw

`stipul demo proof` ran a real enforcement session against the packaged demo Charter: one tool was allowed, one was denied by egress policy, and one was denied by a never-allow rule. The session was sealed, verification confirmed that the evidence chain was intact, and tampering caused Stipul to reject the record. Other tools make agents governable. Stipul makes agent actions admissible.

## Architecture

- **Writ** intercepts tool calls at the runtime boundary and applies policy before execution.
- **Charter** defines what an agent is allowed to do, expressed as declarative policy.
- **Chronicle** records every enforcement decision as the authoritative tamper-evident `events.jsonl` chain.
- **Seal** binds the recorded evidence to a cryptographic attestation that verification can check.

## Start your own policy

Run `stipul init` to write a starter `charter.yaml` for your own agent in the current directory.

```bash
stipul init
```

This is the exact starter policy Stipul writes to disk:

```yaml
schema_version: "1.0"
contract_id: "a1000001-0001-0001-0001-000000000001"
parent_contract_id: null
created_at: "2025-01-01T00:00:00Z"
expires_at: "2099-01-01T00:00:00Z"
signed_by: null
identity_agent_id: "agent.my-agent"
identity_code_sha256: null
allowed_tools:
  - "filesystem.read"
  - "filesystem.write"
never_allow_tools:
  - "filesystem.delete"
  - "shell.exec"
tool_risk_classes:
  filesystem.read: "read"
  filesystem.write: "write"
  filesystem.delete: "irreversible"
  shell.exec: "irreversible"
max_tool_calls: 50
max_net_calls: 0
egress_allowlist: []
approval_quorum: 1
```

This policy file defines allowed tools, forbidden tools, egress rules, and call limits for your agent. Agents cannot override it at runtime; Writ enforces it before execution. `stipul demo proof` uses the packaged demo Charter, and `stipul init` creates a starter Charter for your customization.

## When you need this

- A support agent reading files and calling web tools needs an enforceable record of what it read, what outbound targets were denied, and whether that evidence still verifies.
- A coding agent touching filesystem and shell needs hard policy boundaries before it can modify a repository or execute commands in CI.
- An ops agent inspecting secrets and deployments needs sealed evidence that the runtime authorized the same actions later presented for review.

If the answer is "trust me," you need Stipul.

## Claude Code Integration

Use Stipul with Claude Code in review mode, then verify the sealed session afterward.

See the walkthrough: [Claude Code Quickstart](docs/claude-code-quickstart.md)

## Links

PyPI: https://pypi.org/project/stipul/
GitHub: https://github.com/miadco/Stipul
