"""Deterministic evidence bundle export for session artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stipul.cli.io import (
    ensure_session_dir,
    read_jsonl,
    sha256_file,
    sha256_bytes,
    write_json,
    write_jsonl,
)
from stipul.charter.contract.schema import Contract
from stipul.scanner import scan_report_from_dict
from stipul.utils.canonical import canonical_json_bytes

_KNOWN_BUNDLE_FILES = {
    "contract.json",
    "decisions.jsonl",
    "events.jsonl",
    "manifest.json",
    "public_key.pem",
    "redacted_events.jsonl",
    "scan_report.json",
    "summary.json",
    "trust_boundaries.json",
}

TRUST_BOUNDARIES = {
    "proxy_proves": [
        "Tool calls routed through the MCP Proxy were evaluated against the supplied charter.",
        "events.jsonl is the authoritative stream for proxy-observed tool and network decisions.",
    ],
    "cannot_prove": [
        "MCP Proxy does not inspect tool response payloads.",
        "File system writes by the agent process are not monitored.",
        (
            "Only tools behind the Server Wrapper are governed. Direct API calls, "
            "local scripts, browser automation, and SSH are outside scope."
        ),
        (
            "Budget tracking relies on event counts. Resource consumption inside "
            "a tool call is not measured."
        ),
    ],
    "coverage_depends_on_wrapper_logging": (
        "Coverage and gap detection depend on wrapper_log.jsonl when present."
    ),
    "response_payloads_inspected": False,
    "agent_filesystem_writes_monitored": False,
}


def export_session_bundle(
    session_dir: Path,
    out_dir: Path,
    *,
    contract: Contract,
    public_key_path: Path | None = None,
    scan_report_path: Path | None = None,
    redact: bool = False,
) -> dict[str, Any]:
    resolved_session_dir = ensure_session_dir(session_dir)
    bundle_dir = Path(out_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    _clear_known_bundle_artifacts(bundle_dir)

    included_files: list[str] = []
    missing_artifacts: list[str] = []

    hashes: dict[str, str] = {}
    extra_manifest_fields: dict[str, Any] = {}

    contract_output = bundle_dir / "contract.json"
    write_json(contract_output, contract.to_canonical_dict(), pretty=True, sort_keys=True)
    included_files.append(contract_output.name)
    hashes[contract_output.name] = sha256_file(contract_output)

    events_path = resolved_session_dir / "events.jsonl"
    if redact:
        original_events_sha256 = sha256_file(events_path)
        redacted_events_path = bundle_dir / "redacted_events.jsonl"
        redacted_events = [_redact_event_metadata(event) for event in read_jsonl(events_path)]
        write_jsonl(redacted_events_path, redacted_events)
        included_files.append(redacted_events_path.name)
        hashes[redacted_events_path.name] = sha256_file(redacted_events_path)
        extra_manifest_fields["original_events_sha256"] = original_events_sha256
        extra_manifest_fields["redacted_events_sha256"] = hashes[redacted_events_path.name]
    else:
        exported_events_path = bundle_dir / "events.jsonl"
        exported_events_path.write_bytes(events_path.read_bytes())
        included_files.append(exported_events_path.name)
        hashes[exported_events_path.name] = sha256_file(exported_events_path)

    for artifact_name in ("decisions.jsonl", "summary.json"):
        source_path = resolved_session_dir / artifact_name
        if source_path.exists():
            output_path = bundle_dir / artifact_name
            output_path.write_bytes(source_path.read_bytes())
            included_files.append(artifact_name)
            hashes[artifact_name] = sha256_file(output_path)
        else:
            missing_artifacts.append(artifact_name)

    if public_key_path is not None:
        public_key_output = bundle_dir / "public_key.pem"
        public_key_output.write_bytes(Path(public_key_path).read_bytes())
        included_files.append(public_key_output.name)
        hashes[public_key_output.name] = sha256_file(public_key_output)
    else:
        missing_artifacts.append("public_key.pem")

    trust_boundaries_path = bundle_dir / "trust_boundaries.json"
    write_json(trust_boundaries_path, TRUST_BOUNDARIES, pretty=True, sort_keys=True)
    included_files.append(trust_boundaries_path.name)
    hashes[trust_boundaries_path.name] = sha256_file(trust_boundaries_path)

    if scan_report_path is not None:
        payload = json.loads(Path(scan_report_path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("scan report JSON must be an object")
        scan_report = scan_report_from_dict(payload)
        scan_report_output = bundle_dir / "scan_report.json"
        write_json(scan_report_output, scan_report.to_dict(), pretty=True, sort_keys=True)
        included_files.append(scan_report_output.name)
        hashes[scan_report_output.name] = sha256_file(scan_report_output)

    sorted_hashes = {name: hashes[name] for name in sorted(hashes)}
    manifest = {
        "exported_at": _deterministic_exported_at(resolved_session_dir, contract),
        "included_files": sorted(included_files),
        "missing_artifacts": sorted(missing_artifacts),
        "session_dir": str(resolved_session_dir.resolve()),
        "top_level_sha256": sha256_bytes(canonical_json_bytes(sorted_hashes)),
        **extra_manifest_fields,
        "hashes": sorted_hashes,
    }
    manifest_path = bundle_dir / "manifest.json"
    write_json(manifest_path, manifest, pretty=True, sort_keys=True)
    return manifest


def _redact_event_metadata(event: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(event)
    metadata = redacted.get("metadata")
    if isinstance(metadata, dict):
        redacted["metadata"] = _redact_leaf_values(metadata)
    return redacted


def _redact_leaf_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_leaf_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_leaf_values(item) for item in value]
    return "[REDACTED]"


def _now_zulu() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clear_known_bundle_artifacts(bundle_dir: Path) -> None:
    for filename in _KNOWN_BUNDLE_FILES:
        path = bundle_dir / filename
        if not path.exists():
            continue
        if path.is_dir():
            raise IsADirectoryError(f"Expected export artifact path to be a file: {path}")
        path.unlink()


def _deterministic_exported_at(session_dir: Path, contract: Contract) -> str:
    summary_timestamp = _summary_session_end(session_dir / "summary.json")
    if summary_timestamp is not None:
        return summary_timestamp

    event_timestamp = _latest_event_timestamp(session_dir / "events.jsonl")
    if event_timestamp is not None:
        return event_timestamp

    return contract.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _summary_session_end(summary_path: Path) -> str | None:
    if not summary_path.exists():
        return None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    session_end = payload.get("session_end")
    normalized = _normalize_utc_timestamp(session_end)
    return normalized


def _latest_event_timestamp(events_path: Path) -> str | None:
    latest: datetime | None = None
    for raw_line in events_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        normalized = _normalize_utc_timestamp(payload.get("timestamp"))
        if normalized is None:
            continue
        parsed = datetime.fromisoformat(normalized[:-1] + "+00:00")
        if latest is None or parsed > latest:
            latest = parsed
    if latest is None:
        return None
    return latest.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_utc_timestamp(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return None
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
