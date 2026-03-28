# Stipul

Your agents act. Can you prove what they did?

## What Stipul does

Stipul is a runtime authorization and evidence layer for AI agents. It intercepts tool calls, enforces policy, and produces a cryptographic proof chain around each decision. Writ enforces the Charter, records every decision in the Chronicle, and produces a cryptographic Seal. One command shows enforcement, evidence, verification, and tamper detection.

## See it work

```bash
pip install stipul
stipul demo proof
```

```text
═══ Stipul Proof Demo ═══

Session: proof-demo

  seq 1  allow   filesystem.read      reason: allowed_tool
  seq 2  deny    web.search           reason: not_in_egress_allowlist
  seq 3  deny    shell.exec           reason: never_allow_tools
  seq 4  close   session_close

Trust: VERIFIED
  Chain: INTACT
  Seal:  VALID
  Decisions: 3
  Fingerprint: proof-demo | INTACT | VALID | 3 decisions | ca7fe08a

═══ Tamper Challenge ═══

To test tamper detection, modify the sealed evidence:
(Verify will show the internal session ID, not "proof-demo". This is the same session.)

  1. Open: /tmp/stipul-proof-demo-6htukemj/session/seal.json
  2. Find the field "terminal_sequence_id"
  3. Change its value (e.g., change 4 to 999)
  4. Save the file
  5. Run:  stipul verify /tmp/stipul-proof-demo-6htukemj/session

Watch Trust: VERIFIED become Trust: REJECTED.

Proof complete: enforcement decisions recorded, chained, and sealed.
```

Follow the tamper challenge, rerun `stipul verify`, and watch the trust verdict flip.
This demo runs locally with no external dependencies or framework integration.

## Architecture

**Writ** intercepts tool calls at the runtime boundary and applies policy before execution.

**Charter** defines what an agent is allowed to do, expressed as declarative rules.

**Chronicle** records every enforcement decision as a tamper-evident event chain.

**Seal** binds the recorded evidence to a cryptographic attestation that verification can check.

## When you need this

If a support agent can read local files and call web tools, you need a record showing which reads were allowed, which outbound requests were denied, and whether that evidence changed after the run. If a coding agent can touch the filesystem and invoke shell commands, you need policy enforcement and a sealed session trail before you let it operate in CI or against a shared repository. If an internal ops agent can inspect tickets, secrets, or deployment tooling, you need verification that the observed tool trace is the same one the runtime authorized.

## Claude Code Integration

Use Stipul to put Claude Code in read-only review mode — allow file reads, block writes and shell commands, verify the session afterward with a sealed receipt.

See the full walkthrough: [Claude Code Quickstart](docs/claude-code-quickstart.md)

## Links

PyPI: https://pypi.org/project/stipul/
GitHub: https://github.com/miadco/stipul
