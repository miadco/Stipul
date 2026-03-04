# AgentShield
AgentShield is a security enforcement layer for AI agent platforms. Operators define a contract before an agent runs, and every tool call is checked against that contract at the execution boundary. The operating model is sign -> enforce -> prove: define and sign constraints, enforce them at runtime, then produce evidence of what was allowed or denied.

## Trust Boundaries
**Token secret isolation:** `AGENTSHIELD_TOKEN_SECRET` must not be present in
the agent runtime environment. If the agent can read this secret, it can mint
valid tokens and bypass the chokepoint. The secret is only permitted in the
MCP Proxy and Server Wrapper process environments. It must be absent from the
agent runtime process env, any agent-accessible filesystem path, and any config
mounted into the agent container or VM.

## Contract Schema
Annotated example contract:

```jsonc
{
  "schema_version": "1.0",           // must be "1.0"
  "contract_id": "<uuid>",           // unique contract identifier (any UUID version)
  "parent_contract_id": "<uuid>",    // null if root contract; links to parent for merge chains
  "created_at": "2025-01-01T00:00:00Z",  // UTC ISO 8601, Z suffix required
  "expires_at": "2025-06-01T00:00:00Z",  // absolute expiry - not a TTL. must be after created_at
  "signed_by": "<key_id>",           // null until Week 3 signing; key ID of signing operator

  "identity": {
    "agent_id": "my-agent-v1",       // stable agent name, pinned at session open
    "code_sha256": "<hex>"           // optional. if set, must match at session open
  },

  "allowed_tools": [                 // explicit allowlist. default-deny: anything not listed is denied
    "read_file",
    "write_file",
    "search_web"
  ],
  "never_allow_tools": [             // permanent prohibitions. deny wins over allowed_tools. always.
    "delete_all_data",
    "send_email"
  ],

  "tool_risk_classes": {             // drives policy decisions. tools absent here default to "write"
    "read_file":  "read",
    "write_file": "write",
    "search_web": "exfil_risk"
  },

  "max_tool_calls": 100,             // hard cap on total tool invocations this session
  "max_net_calls": 20,               // hard cap on network-touching calls this session

  "egress_allowlist": [              // permitted outbound domains
    "api.openai.com",                // exact host match
    ".github.com"                    // suffix match: covers api.github.com, raw.github.com, etc.
                                     // leading dot is required and is what distinguishes suffix from exact
                                     // no wildcards, no ports, no schemes
  ]
}
```

## Policy Rule Table
| Risk Class   | Decision         | Notes                             |
|--------------|------------------|-----------------------------------|
| read         | allow            |                                   |
| write        | allow            | default if tool has no risk class |
| irreversible | require_approval |                                   |
| exfil_risk   | require_approval |                                   |

## Evaluation Order
1. Contract expired -> deny
2. Identity mismatch -> deny
3. Tool in never_allow_tools -> deny
4. Tool not in allowed_tools -> deny
5. Tool call budget exhausted -> deny
6. Network call budget exhausted -> deny
7. Egress domain not allowlisted -> deny
8. Risk class lookup -> allow / require_approval
9. Default -> deny

## Hierarchical Contracts
Child contracts can only restrict parent permissions, never expand them. `merge(parent, child)` validates this across every field and returns all violations together as one `ContractMergeViolation`, not one error at a time.

| Field             | Merge Rule                       |
|-------------------|----------------------------------|
| allowed_tools     | intersection                     |
| never_allow_tools | union                            |
| tool_risk_classes | higher severity wins             |
| max_tool_calls    | min                              |
| max_net_calls     | min                              |
| expires_at        | min (earlier)                    |
| egress_allowlist  | intersection                     |
| identity          | child may restrict, never loosen |

## Quickstart
```bash
pip install -e ".[dev]"
pytest
```

## Signing (Week 3)
Contracts are designed for Ed25519 signing. `to_canonical_dict()` produces the signing input with lexicographically sorted keys, null values removed, and `signed_by` plus `parent_contract_id` excluded from signing scope. Signing implementation ships in Week 3.

## Project Status
| Week | Scope                           | Status   |
|------|---------------------------------|----------|
| 1    | Contract schema + policy engine | ✓ Done   |
| 2    | MCP proxy enforcement           | Upcoming |
| 3    | Signed event stream             | Upcoming |
| 4    | Bypass detection                | Upcoming |
| 5    | CLI packaging                   | Upcoming |
| 6    | OSS launch                      | Upcoming |
