# ISO/IEC 42001 Mapping

This mapping uses non-numbered AI management system control-area language only. Refer to ISO/IEC 42001 authoritative text for exact clause references.

Stipul is not a certification product. These mappings describe how Stipul outputs may support an AI management system when used with organizational policies, roles, risk assessments, monitoring, and review processes.

| Control Area | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| AI operational governance | Charter | Charter can help provide evidence that an organization defined permitted agent tools, prohibited tools, identity expectations, risk classes, budgets, and egress boundaries before runtime use. |
| Control execution | Writ, Chronicle | Writ applies Charter decisions before tool execution. Chronicle records each decision, which can support review of whether agent actions were evaluated at the enforcement boundary. |
| Auditability | Chronicle, decisions projection, summary | Chronicle `events.jsonl`, `decisions.jsonl`, and `summary.json` can support audit trails for agent activity, policy decisions, and session-level outcomes. |
| Policy enforcement evidence | Charter, Chronicle, verification receipt | Reviewer evidence can connect stated policy to runtime outcomes by comparing Charter rules with Chronicle decisions and verification results. |
| Evidence integrity | Seal, verification report | Seal and verification output can help provide evidence that the recorded session artifacts were integrity-checked before review. |

## External Reference Note

Precise ISO/IEC 42001 clause references should be added only after review against the ISO/IEC 42001 authoritative text.

