# Sample Evidence

This directory contains concise, hand-authored fixtures that mirror Stipul's committed Charter, Chronicle, Seal, and verification output schemas.

Read the files in this order:

1. `charter.yaml`: the policy source describing agent identity, allowed tools, prohibited tools, risk classes, argument constraints, budgets, and egress boundaries.
2. `events.jsonl`: the authoritative Chronicle stream with six events for one session.
3. `decisions.jsonl`: the decision projection derived from decision-bearing Chronicle events.
4. `summary.json`: a reviewer summary with event counts, allow count, deny count, and session context.
5. `seal.json`: the Seal payload that binds the session to the terminal event and the event stream digest.
6. `verification-receipt.txt`: reviewer-facing verification output.
7. `verification-report.json`: machine-readable verification status.
8. `manifest.json`: inventory of the sample evidence files.

These fixtures are examples for governance review. They are not generated from a live session and should not be treated as production evidence.

