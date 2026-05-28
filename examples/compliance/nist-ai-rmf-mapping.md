# NIST AI RMF Mapping

This mapping uses only the four NIST AI RMF functions: Govern, Map, Measure, and Manage. Stipul can be used within a broader AI risk management program to support evidence collection for tool-using agents.

| Function | Stipul Output | Evidence-Support Mapping |
| --- | --- | --- |
| Govern | Charter, Writ, Seal | Charter documents the agent authority model. Writ applies that authority before tool execution. Seal verifies evidence integrity for the recorded session. Together, these outputs support governance review of agent authority and runtime control operation. |
| Map | Charter | Charter fields such as `allowed_tools`, `never_allow_tools`, `tool_risk_classes`, `argument_constraints`, `max_tool_calls`, `max_net_calls`, and `egress_allowlist` can help identify intended agent capabilities, action boundaries, and risk-relevant operating assumptions. |
| Measure | Chronicle | Chronicle `events.jsonl` records can help measure observed allow, deny, and approval-required decisions, including `event_type`, `tool_name`, `risk_class`, `decision`, `reason`, `rule_triggered`, and `metadata`. |
| Manage | Charter, Writ, Chronicle | Charter policy and Writ enforcement support operational risk treatment by constraining tool use before execution. Chronicle can help provide evidence for follow-up review, exception analysis, and policy tuning. |

## Evidence Notes

- Charter supports documented authority and risk boundary review.
- Writ supports pre-execution control execution.
- Chronicle supports runtime decision evidence.
- Seal supports evidence integrity verification.
- Verification reports support reviewer assessment of whether the evidence chain was intact and sealed.

