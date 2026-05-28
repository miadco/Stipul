# ISO/IEC 27001:2022 Mapping

This mapping targets ISO/IEC 27001:2022 control-area language. It avoids legacy ISO/IEC 27001:2013 Annex A.9 framing.

Stipul is not a certification product. These mappings describe how Stipul can help provide evidence within a broader information security management program.

| Control Area | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| Access control | Charter | Charter defines the tools, egress targets, action classes, and identity expectations that an agent may use. These fields can support review of least-privilege authorization design for tool-using agents. |
| Authorization boundaries | Charter, Writ | Writ enforces Charter-defined boundaries before tool execution. This can help provide evidence that agent tool requests were evaluated at a controlled authorization point. |
| Logging | Chronicle | Chronicle `events.jsonl` records event sequence, timestamp, session, tool, risk class, decision, reason, rule, contract identity, input hash, previous hash, and signature. This can support review of agent decision logging. |
| Monitoring | Chronicle, summary, report | Chronicle records and session summaries may support monitoring of denied actions, approval-required actions, egress attempts, budget signals, and policy-significant events. |
| Operational evidence | decisions projection, summary, manifest | `decisions.jsonl`, `summary.json`, and bundle manifests can help provide concise operational evidence derived from the authoritative Chronicle stream. |
| Cryptographic integrity verification | Seal, verification receipt, verification report | Seal binds the session to the terminal event and `events.jsonl` digest. Verification output can help provide evidence that the Chronicle chain and Seal were checked before review. |

## Reviewer Note

Use these mappings as supporting evidence only. Organizational scope, asset inventory, risk assessment, policy ownership, monitoring process, and independent review remain outside this sample pack.

