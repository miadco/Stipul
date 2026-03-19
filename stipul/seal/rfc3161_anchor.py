"""Optional RFC 3161 timestamp anchoring for deterministic export bundles."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from asn1crypto import cms, parser, tsp

from stipul.cli.io import read_json, write_json

_DEFAULT_TIMEOUT_SECONDS = 20.0
_TIMESTAMP_REQUEST_CONTENT_TYPE = "application/timestamp-query"
_TIMESTAMP_REPLY_CONTENT_TYPE = "application/timestamp-reply"


def rfc3161_receipt_path(bundle_dir: str | Path) -> Path:
    return Path(bundle_dir) / "rfc3161_receipt.json"


def timestamp_export_bundle_rfc3161(
    bundle_dir: str | Path,
    tsa_url: str,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    resolved_bundle_dir = Path(bundle_dir)
    manifest_path = resolved_bundle_dir / "manifest.json"
    manifest = _load_manifest(manifest_path)
    _ensure_non_redacted_bundle(resolved_bundle_dir, manifest)

    top_level_sha256 = _load_top_level_sha256(manifest, manifest_path)
    message_imprint = bytes.fromhex(top_level_sha256)
    request_der = _build_timestamp_request(message_imprint)
    receipt_content_type, response_der = _post_timestamp_request(
        tsa_url,
        request_der,
        timeout_seconds=timeout_seconds,
    )
    parsed = _parse_timestamp_response(
        response_der,
        expected_message_imprint=message_imprint,
    )
    receipt = {
        "tsa_url": tsa_url,
        "manifest_path": str(manifest_path.resolve()),
        "anchored_top_level_sha256": top_level_sha256,
        "message_imprint_algorithm": "sha256",
        "message_imprint_hex": top_level_sha256,
        "receipt_content_type": receipt_content_type,
        "timestamp_token_der_base64": base64.b64encode(parsed["timestamp_token_der"]).decode("ascii"),
    }
    for field in ("tsa_gen_time", "serial_number", "policy"):
        value = parsed.get(field)
        if value is not None:
            receipt[field] = value

    write_json(
        rfc3161_receipt_path(resolved_bundle_dir),
        receipt,
        pretty=True,
        sort_keys=True,
    )
    return receipt


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"manifest.json must be a JSON object: {path}")
    return payload


def _ensure_non_redacted_bundle(bundle_dir: Path, manifest: dict[str, Any]) -> None:
    if (bundle_dir / "redacted_events.jsonl").exists() or "original_events_sha256" in manifest:
        raise ValueError("RFC 3161 timestamping only supports non-redacted export bundles")
    if not (bundle_dir / "events.jsonl").exists():
        raise ValueError("RFC 3161 timestamping requires bundle events.jsonl")


def _load_top_level_sha256(manifest: dict[str, Any], manifest_path: Path) -> str:
    digest = manifest.get("top_level_sha256")
    if not isinstance(digest, str):
        raise ValueError(f"manifest.json missing top_level_sha256: {manifest_path}")
    normalized = digest.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError(f"manifest.json top_level_sha256 must be a lowercase hex digest: {manifest_path}")
    return normalized


def _build_timestamp_request(message_imprint: bytes) -> bytes:
    request = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": message_imprint,
            },
            "cert_req": True,
        }
    )
    return request.dump()


def _post_timestamp_request(
    tsa_url: str,
    request_der: bytes,
    *,
    timeout_seconds: float,
) -> tuple[str | None, bytes]:
    request = Request(
        tsa_url,
        data=request_der,
        headers={
            "Content-Type": _TIMESTAMP_REQUEST_CONTENT_TYPE,
            "Accept": _TIMESTAMP_REPLY_CONTENT_TYPE,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            content_type = _normalize_content_type(response.headers.get("Content-Type"))
            return content_type, response.read()
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        detail = f": {body}" if body else ""
        raise ValueError(f"TSA HTTP failure {exc.code}{detail}") from exc
    except URLError as exc:
        raise OSError(f"TSA HTTP failure: {exc.reason}") from exc


def _normalize_content_type(value: str | None) -> str | None:
    if value is None:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _parse_timestamp_response(
    response_der: bytes,
    *,
    expected_message_imprint: bytes,
) -> dict[str, Any]:
    try:
        response = tsp.TimeStampResp.load(response_der)
    except Exception as exc:
        raise ValueError(f"Malformed RFC 3161 response: {exc}") from exc

    status_info = response["status"]
    status = status_info["status"].native
    if status != "granted":
        status_parts = [f"TSA response status {status}"]
        status_strings = status_info["status_string"].native if status_info["status_string"].native else []
        if status_strings:
            status_parts.append(", ".join(status_strings))
        fail_info = status_info["fail_info"].native
        if fail_info:
            if isinstance(fail_info, set):
                status_parts.append(",".join(sorted(fail_info)))
            else:
                status_parts.append(str(fail_info))
        raise ValueError(": ".join(part for part in status_parts if part))

    token = response["time_stamp_token"]
    if token.contents is None:
        raise ValueError("Malformed RFC 3161 response: missing time_stamp_token")
    if token["content_type"].native != "signed_data":
        raise ValueError(f"Malformed RFC 3161 response: unexpected token content type {token['content_type'].native}")

    signed_data = token["content"]
    tst_info = _extract_tst_info(signed_data["encap_content_info"])
    message_imprint = tst_info["message_imprint"]
    algorithm = message_imprint["hash_algorithm"]["algorithm"]
    if algorithm != "sha256":
        raise ValueError(f"Malformed RFC 3161 response: unexpected message imprint algorithm {algorithm}")
    if message_imprint["hashed_message"] != expected_message_imprint:
        raise ValueError("Malformed RFC 3161 response: message imprint does not match anchored bundle hash")

    gen_time = tst_info.get("gen_time")
    return {
        "timestamp_token_der": token.dump(),
        "tsa_gen_time": _format_zulu(gen_time) if isinstance(gen_time, datetime) else None,
        "serial_number": str(tst_info["serial_number"]),
        "policy": tst_info["policy"],
    }


def _extract_tst_info(encap_content_info: cms.ContentInfo) -> dict[str, Any]:
    outer = parser.parse(encap_content_info.dump())
    outer_contents = outer[4]
    first_child = parser.parse(outer_contents)
    oid_bytes = first_child[3] + first_child[4]
    content_type = cms.ContentType.load(oid_bytes).native
    if content_type != "tst_info":
        raise ValueError(f"Malformed RFC 3161 response: unexpected encapsulated content type {content_type}")
    tst_info_der = outer_contents[len(oid_bytes) :]
    if not tst_info_der:
        raise ValueError("Malformed RFC 3161 response: missing TSTInfo payload")
    try:
        return tsp.TSTInfo.load(tst_info_der).native
    except Exception as exc:
        raise ValueError(f"Malformed RFC 3161 response: invalid TSTInfo payload: {exc}") from exc


def _format_zulu(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = ["rfc3161_receipt_path", "timestamp_export_bundle_rfc3161"]
