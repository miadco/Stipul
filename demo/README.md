# Native local demo

Primary invocation: `python3 demo/run.py`

Alternative: `.venv/bin/python demo/run.py`

On systems where `python3` is not available, use `python` instead.

## What you'll see

`Actions` shows the three tool calls and the enforcement outcome for each one.

`Evidence` shows the Chronicle history rendered from the signed `events.jsonl` session log.

`Proof` shows the verification result for the Chronicle chain and the Seal for the preserved session.

## The Charter

[`demo/demo-charter.yaml`](demo-charter.yaml) defines the policy used by the native demo. It allows `filesystem.read`, `filesystem.write`, `filesystem.delete`, and `web.search`, and the demo Charter does not permit `shell.exec`. It marks `filesystem.delete` as `irreversible`, which requires operator approval before execution, and it permits network egress only to `api.example.com` and subdomains of `.trusted.example`.

## What each step demonstrates

1. `filesystem.read`: Allowed. Tool is in the Charter with risk class `read`. Agent receives the result.
2. `web.search via evil.example.com`: Denied. Tool is allowed, but the egress target is not in the Charter's allowlist. This is a policy judgment, not a blocklist.
3. `filesystem.delete`: Approval required. Tool is in the Charter with risk class `irreversible`. Writ creates a pending approval request and denies the call until an operator approves.

## Inspecting the evidence

The session is preserved by default at the path printed by the demo.

- `events.jsonl` — the Chronicle (signed event log)
- `seal.json` — the Seal (cryptographic attestation)
- `.stipul/keys/` — the signing keypair used for the demo session

A developer can manually re-run `stipul verify` and `stipul history` against the preserved session directory:

```bash
.venv/bin/python -m stipul.cli.main verify --session-dir /tmp/stipul-local-demo-xxxxx/session
.venv/bin/python -m stipul.cli.main history --session-dir /tmp/stipul-local-demo-xxxxx/session
```

For commands in this document that use `python3`, substitute `python` instead where appropriate if `python3` is unavailable.

## Cleaning up

```bash
python3 demo/run.py --clean
rm -rf /tmp/stipul-local-demo-*
```

## What this does NOT show

This demo uses direct Python calls to the enforcement proxy. It does not show framework integration. OpenAI Agents SDK and LangGraph integrations exist and are tested separately under `integrations/`. This is the native enforcement path.
