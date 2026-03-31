# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and the project follows Semantic Versioning.

## [Unreleased]

### Added

- Release discipline for build artifacts, changelog tracking, and tag-driven packaging workflows.
- Single-source package versioning, wheel/sdist smoke validation, and release artifact checksums.

## [0.1.1] - 2026-03-31
### Fixed
- Aligned demo charter tool names with demo runner invocations (filesystem.read,
  web.search, shell.exec). Previous charter used mismatched names (file.read,
  file.write), causing all demo decisions to render as not_in_contract denials.
- Updated version assertions in packaging and version tests to 0.1.1.

## [0.1.0] - 2026-03-06

### Added

- Contract schema parsing, canonical hashing, and hierarchical merge validation.
- MCP proxy enforcement, signed event chains, and decisions projection verification.
- Deterministic operator CLI commands for verify, export, lint-contract, simulate, diff, and scan.
- Deterministic evidence bundle export with optional redacted events and optional scan-report inclusion.
- Heuristic, read-only scanner with bounded checks and stable JSON output.

### Security

- Trust boundary documentation, placeholder vulnerability disclosure policy, and scanner-backed release wedge.
