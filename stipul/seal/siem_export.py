"""Deterministic downstream SIEM export derived from authoritative events.jsonl."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stipul.cli.io import ensure_session_dir, read_jsonl, sha256_file, write_json, write_jsonl


def _normalize_optional_str(field: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    return normalized


def _parse_utc_timestamp(field: str, value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 UTC string")
    if not (value.endswith("Z") or value.endswith("+00:00")):
        raise ValueError(f"{field} must end with 'Z' or '+00:00'")
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO 8601 UTC string") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _format_zulu(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SiemExportFilters:
    event_type: str | None = None
    decision: str | None = None
    ingress: str | None = None
    since: str | None = None
    until: str | None = None

    @classmethod
    def create(
        cls,
        *,
        event_type: str | None = None,
        decision: str | None = None,
        ingress: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> SiemExportFilters:
        normalized_since = None
        normalized_until = None
        since_dt = None
        until_dt = None
        if since is not None:
            since_dt = _parse_utc_timestamp("since", since)
            normalized_since = _format_zulu(since_dt)
        if until is not None:
            until_dt = _parse_utc_timestamp("until", until)
            normalized_until = _format_zulu(until_dt)
        if since_dt is not None and until_dt is not None and since_dt > until_dt:
            raise ValueError("since must be <= until")
        return cls(
            event_type=_normalize_optional_str("event_type", event_type),
            decision=_normalize_optional_str("decision", decision),
            ingress=_normalize_optional_str("ingress", ingress),
            since=normalized_since,
            until=normalized_until,
        )

    def to_dict(self) -> dict[str, str | None]:
        return {
            "event_type": self.event_type,
            "decision": self.decision,
            "ingress": self.ingress,
            "since": self.since,
            "until": self.until,
        }


def siem_manifest_path(output_path: str | Path) -> Path:
    return Path(output_path).with_suffix(".manifest.json")


def export_siem_jsonl(
    session_dir: str | Path,
    output_path: str | Path,
    *,
    filters: SiemExportFilters | None = None,
) -> dict[str, Any]:
    resolved_session_dir = ensure_session_dir(Path(session_dir))
    events_path = resolved_session_dir / "events.jsonl"
    siem_output_path = Path(output_path)

    if siem_output_path.resolve() == events_path.resolve():
        raise ValueError("siem_out must not overwrite authoritative events.jsonl")

    active_filters = filters or SiemExportFilters.create()
    source_events_sha256 = sha256_file(events_path)
    source_events = read_jsonl(events_path)
    filtered_events = [
        event
        for event in source_events
        if _event_matches_filters(event, active_filters)
    ]
    flattened_records = [_flatten_event(event) for event in filtered_events]
    write_jsonl(siem_output_path, flattened_records)

    manifest = _build_manifest(
        source_events=source_events,
        filtered_events=filtered_events,
        source_events_sha256=source_events_sha256,
        filters=active_filters,
    )
    write_json(
        siem_manifest_path(siem_output_path),
        manifest,
        pretty=True,
        sort_keys=True,
    )
    return manifest


def _event_matches_filters(
    event: dict[str, Any],
    filters: SiemExportFilters,
) -> bool:
    if filters.event_type is not None and event.get("event_type") != filters.event_type:
        return False
    if filters.decision is not None and event.get("decision") != filters.decision:
        return False

    metadata = event.get("metadata")
    ingress = metadata.get("ingress") if isinstance(metadata, dict) else None
    if filters.ingress is not None and ingress != filters.ingress:
        return False

    if filters.since is not None or filters.until is not None:
        timestamp = event.get("timestamp")
        event_time = _parse_utc_timestamp("event timestamp", str(timestamp))
        if filters.since is not None and event_time < _parse_utc_timestamp("since", filters.since):
            return False
        if filters.until is not None and event_time > _parse_utc_timestamp("until", filters.until):
            return False

    return True


def _flatten_event(event: dict[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {
        key: value
        for key, value in sorted(event.items())
        if key != "metadata"
    }
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        _flatten_mapping(flattened, metadata, prefix="metadata")
    return flattened


def _flatten_mapping(
    output: dict[str, Any],
    payload: dict[str, Any],
    *,
    prefix: str,
) -> None:
    for key in sorted(payload):
        value = payload[key]
        normalized_key = f"{prefix}_{key}"
        if isinstance(value, dict):
            _flatten_mapping(output, value, prefix=normalized_key)
        else:
            output[normalized_key] = value


def _build_manifest(
    *,
    source_events: list[dict[str, Any]],
    filtered_events: list[dict[str, Any]],
    source_events_sha256: str,
    filters: SiemExportFilters,
) -> dict[str, Any]:
    source_identity = source_events[0] if source_events else {}
    exported_at = _latest_event_timestamp(filtered_events)
    if exported_at is None:
        exported_at = _latest_event_timestamp(source_events)
    return {
        "format": "jsonl",
        "source_events_sha256": source_events_sha256,
        "exported_at": exported_at,
        "applied_filters": filters.to_dict(),
        "source_session_id": source_identity.get("session_id"),
        "source_contract_id": source_identity.get("contract_id"),
        "source_contract_hash": source_identity.get("contract_hash"),
        "source_event_count": len(source_events),
        "exported_event_count": len(filtered_events),
    }


def _latest_event_timestamp(events: list[dict[str, Any]]) -> str | None:
    latest: datetime | None = None
    for event in events:
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, str):
            continue
        parsed = _parse_utc_timestamp("event timestamp", timestamp)
        if latest is None or parsed > latest:
            latest = parsed
    if latest is None:
        return None
    return _format_zulu(latest)


__all__ = ["SiemExportFilters", "export_siem_jsonl", "siem_manifest_path"]
