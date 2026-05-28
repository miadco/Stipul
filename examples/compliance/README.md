# Compliance & Control Mapping

Stipul provides runtime authorization, decision evidence, and integrity verification that can support security, AI governance, and compliance programs.

Stipul is not a certification product and does not make an organization conform to any framework by itself. These mappings describe how Stipul outputs can help provide evidence for selected control areas when used within a broader governance, risk, and assurance program.

## Core Alignment

### NIST AI RMF

Stipul supports NIST AI RMF governance activities by making agent authority explicit in a Charter, enforcing that authority through Writ before tool execution, recording allow and deny decisions in Chronicle, and using Seal to verify evidence integrity. These outputs may support governance review, risk visibility, runtime measurement, and operational risk management for tool-using AI systems.

### ISO/IEC 42001

Stipul can be used within a broader AI management system to support operational governance of AI agents. Charter policy, Writ enforcement, Chronicle decision records, and Seal verification can help provide evidence for defined authority boundaries, control execution, auditability, and review of AI system operations.

### ISO/IEC 27001:2022

Stipul may support information security management activities around access control, authorization boundaries, logging, monitoring, operational evidence, and cryptographic integrity verification. The evidence pack should be treated as supporting material for an organization's broader ISO/IEC 27001:2022 program, not as a standalone assessment result.

## Additional Framework Mappings

### NIST CSF 2.0

Stipul can support all six NIST CSF 2.0 functions by documenting agent governance decisions, identifying authorized tool boundaries, protecting execution paths through pre-execution authorization, detecting denied or unusual activity through Chronicle records, supporting response review with decision evidence, and supporting post-incident evidence review.

### SOC 2

Stipul may support broad Trust Services Criteria evidence for logical access, system operations, monitoring, and change-related authorization review. Chronicle and Seal outputs can help provide evidence that agent actions were evaluated, recorded, and integrity-checked.

### NIST SP 800-53

Stipul can help provide evidence for family-level access control, audit and accountability, and system and information integrity activities. The mapping is intentionally family-level and does not assign specific control numbers.

### OWASP LLM / Agentic AI Security

Stipul supports risk reduction for agentic systems by constraining excessive agency, unsafe tool use, unauthorized action execution, weak authorization boundaries, data exfiltration risk, and missing auditability. The mapping is risk-theme oriented, not a formal control mapping.

## Evidence Artifacts

Sample reviewer artifacts are in [`sample-evidence/`](sample-evidence/). They are concise, hand-authored fixtures based on Stipul's committed Chronicle, Seal, Charter, and verification output schemas.

## Auditor Guide

Read the evidence chain in this order:

1. Charter: defines the allowed tools, prohibited tools, risk classes, argument constraints, budgets, egress boundaries, and agent identity.
2. Writ: evaluates requested agent tool actions against the Charter before execution.
3. Chronicle: records the resulting allow, deny, or approval-required decisions in `events.jsonl`.
4. Seal: binds the terminal Chronicle event and `events.jsonl` digest into `seal.json`.
5. verify: renders the verification receipt and optional JSON report showing chain status, Seal status, event counts, and failures.

