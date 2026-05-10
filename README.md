# Stipul [![CI](https://github.com/miadco/stipul/actions/workflows/ci.yml/badge.svg)](https://github.com/miadco/stipul/actions/workflows/ci.yml)

**Control before action. Proof after.**

Prompts are not policy. Logs are not governance. The boundary is the tool call.

Stipul is an agent authorization and audit platform for tool-using AI systems. It enforces policy on agent actions before execution, records every decision in the Chronicle, and verifies the evidence with a cryptographic Seal.

A prompt is instruction. A Charter is policy.

A tool call requests authority. Writ enforces authorization.

A log describes activity. The Chronicle preserves evidence.

A hash detects tampering. A Seal proves integrity.

![Stipul enforcement boundary](https://raw.githubusercontent.com/miadco/Stipul/main/docs/images/whatever.png)

[Quickstart](#see-it-work) · [Claude Code](docs/claude-code-quickstart.md) · [OpenAI Agents](integrations/openai-agents/) · [LangGraph](integrations/langgraph/) · [PyPI](https://pypi.org/project/stipul/) · [Docs](docs/)

---

## Why you need this

A coding agent can modify files, run commands, inspect secrets, and change repositories. You need policy boundaries before tool access becomes system change.

A support, research, or operations agent can read data and call tools across real workflows. You need enforceable boundaries and verifiable evidence for what was allowed, denied, recorded, and sealed.

A local model reduces provider exposure, but it does not constrain local authority. The model may be local, but the tool call can still affect real files, credentials, services, and systems.

When an agent can act through tools, its authority needs control before execution and proof after.


## How Stipul works


Writ enforces the Charter, records every decision in the Chronicle, and produces a cryptographic Seal.

A Charter defines policy: allowed tools, forbidden tools, egress boundaries, and limits.

Writ enforces the Charter before action. Every tool call is evaluated before execution.

The Chronicle records decisions in the authoritative `events.jsonl` evidence source.

Seal verification checks the evidence record and rejects it if integrity fails.


## What makes Stipul different


**Agent control follows Zero Trust principles.** Stipul does not assume an agent should be trusted because it is local, approved, or useful. Every tool call still has to pass the Charter.

**Policy defaults to least-privilege.** The Charter defines what tools, targets, and actions are allowed instead of relying on prompt wording.

**Authority is checked before execution.** Writ evaluates tool calls before they run, so denied actions do not become cleanup work.

**Decisions become Chronicle evidence.** Allowed and denied actions are recorded as decision evidence in `events.jsonl`.

**Integrity is verified by the Seal.** The Seal lets any verifier confirm evidence integrity and reject tampered records.

## See it work

Install Stipul as a CLI app with pipx (Python 3.10+):

```bash
pipx install stipul
stipul demo proof
```

`stipul demo proof` runs a real enforcement session against the packaged demo Charter. One tool is allowed, one is denied by egress policy, and one is denied by a never-allow rule. The session is sealed, verification confirms that the evidence still holds, and tampering causes Stipul to reject the record.

```text
═══ Stipul Proof Demo ═══

Session: <session-id>

  seq 1  allow   filesystem.read      reason: allowed_tool
  seq 2  deny    web.search           reason: not_in_egress_allowlist
  seq 3  deny    shell.exec           reason: never_allow_tools
  seq 4  close   session_close

Trust: VERIFIED
  Chain: INTACT
  Seal:  VALID
  Decisions: 3
  Fingerprint: <session-id> | INTACT | VALID | 3 decisions | <fingerprint>

═══ Tamper Challenge ═══

The seal records a cryptographic attestation over the session evidence.
Inspect it yourself, verify the session as-is, then change a recorded value and re-verify.

Step 1 — View the current seal:

  cat <session-dir>/seal.json | python3 -m json.tool

Step 2 — Verify the session as-is:

  stipul verify <session-dir>

Expected clean verification:

  Trust: VERIFIED
  Chain: INTACT
  Seal: VALID

Step 3 — Now tamper with the seal:

  sed -i 's/"terminal_sequence_id": 5/"terminal_sequence_id": 999/' <session-dir>/seal.json

  Or try a different recorded value in seal.json and re-verify.

  sed -i 's/"version": 1/"version": 42/' <session-dir>/seal.json

Step 4 — Re-verify the session:

  stipul verify <session-dir>

Expected post-tamper verification:

  Trust: REJECTED
  Chain: INTACT
  Seal: INVALID

Proof complete: enforcement decisions recorded, chained, and sealed.
```

Other tools can describe agent activity. Stipul shows the proof path: governed actions, recorded decisions, and verifiable evidence.

## Integrations

Stipul integrates with existing agent frameworks through a lightweight enforcement boundary:

- **[Claude Code](docs/claude-code-quickstart.md)**: review mode with sealed session verification
- **[OpenAI Agents SDK](integrations/openai-agents/)**: tool-call interception via stdio
- **[LangGraph](integrations/langgraph/)**: enforcement layer for LangChain agent graphs

## Start with proof

Run the packaged demo, inspect the evidence, tamper with the record, and verify that trust flips to rejected. Then run `stipul init` to scaffold a starter Charter for your own agent workflow.

## License

Apache 2.0

[PyPI](https://pypi.org/project/stipul/) · [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md)
