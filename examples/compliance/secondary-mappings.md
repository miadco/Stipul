# Secondary Framework Mappings

These mappings are intentionally broad. They describe where Stipul outputs may support evidence collection, not framework coverage by themselves.

## NIST CSF 2.0

| Function | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| Govern | Charter, verification report | Charter supports documented agent authority boundaries. Verification reports can support governance review of evidence integrity status. |
| Identify | Charter, sample evidence manifest | Charter can help identify permitted tools, prohibited tools, identity assumptions, egress targets, and budget constraints for an agent workflow. |
| Protect | Writ, Charter | Writ applies pre-execution authorization using Charter-defined boundaries, which may support protection of tools, data paths, and network egress paths. |
| Detect | Chronicle, summary | Chronicle records denied actions, approval-required actions, egress attempts, write attempts, and policy-significant events that may support detection workflows. |
| Respond | Chronicle, verification receipt | Chronicle and verification output can support incident triage by showing what was attempted, what was allowed or denied, and whether the record verified. |
| Recover | Chronicle, Seal, manifest | Stipul supports post-incident evidence review by preserving decision records, integrity verification status, and artifact inventory. It does not execute recovery activities. |

## SOC 2

Use broad Trust Services Criteria language only.

| Area | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| CC6 | Charter, Writ | Charter and Writ may support logical access and authorization evidence for agent tool use. |
| CC7 | Chronicle, summary, verification report | Chronicle and verification output can help provide evidence for operations monitoring and review of anomalous or denied agent activity. |
| CC8 | Charter, Chronicle | Charter changes and resulting Chronicle decisions may support change-related review of agent authorization boundaries when used with an organization's change process. |

## NIST SP 800-53

This mapping is family-level only and does not assign control numbers.

| Family | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| AC | Charter, Writ | Supports access control evidence for tool authorization, prohibited actions, egress boundaries, and identity checks. |
| AU | Chronicle, decisions projection, summary | Can help provide audit and accountability evidence through event records, decision projections, session summaries, and reviewer-friendly reports. |
| SI | Seal, verification report | Supports system and information integrity evidence by verifying evidence integrity and flagging broken or invalid records. |

## OWASP LLM / Agentic AI

This is a risk-theme mapping only, not a formal control mapping.

| Risk Theme | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| excessive agency | Charter, Writ | Charter limits tool authority and Writ applies those limits before execution. |
| unsafe tool use | Charter, Chronicle | Charter defines risk classes and prohibited tools. Chronicle records attempted and denied tool use. |
| unauthorized action execution | Writ, Chronicle | Writ blocks disallowed actions before execution and Chronicle records the decision outcome. |
| weak authorization boundaries | Charter, Writ | Charter and Writ can support stronger runtime authorization boundaries for agent tools. |
| data exfiltration risk | egress_allowlist, net_call events | Charter egress policy and Chronicle network events can help provide evidence for outbound access review. |
| missing auditability | Chronicle, Seal | Chronicle records decisions and Seal verifies evidence integrity for review. |

