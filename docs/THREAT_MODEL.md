# Threat Model Note

## In Scope

- Contract validation and runtime enforcement at the MCP proxy boundary.
- Signed proxy-observed event streams and derived operator evidence.
- Offline verification of event-chain integrity and decisions projection derivability.
- Bounded, deterministic source scanning for high-signal configuration and coding issues.

## Out of Scope

- Tool response payload inspection.
- Full host or container compromise.
- Filesystem writes performed directly by the agent process.
- Direct API calls, SSH, browser automation, or local scripts that bypass the wrapper/proxy path.
- Formal proof of absence from the heuristic scanner.

## Trust Assumptions

- `AGENTSHIELD_TOKEN_SECRET` is isolated from the agent runtime environment.
- Permit validation secrets stay in trusted operator-controlled environments.
- Operators preserve exported evidence bundles after creation.
- Wrapper coverage claims only apply when `wrapper_log.jsonl` is present and trustworthy.

## Release Integrity Notes

- Build artifacts are validated from both wheel and sdist installs before release.
- Release workflows publish artifact hashes alongside built distributions.
- `summary.json` remains an authoritative copied artifact in export bundles; release-time metadata belongs in the manifest.
