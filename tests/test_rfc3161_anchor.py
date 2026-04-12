from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from asn1crypto import cms, tsp

from stipul.seal.exporter import export_session_bundle
from stipul.seal.rfc3161_anchor import timestamp_export_bundle_rfc3161
from tests.cli_support import create_signed_session


def _build_timestamp_response(
    message_imprint: bytes,
    *,
    status: str = "granted",
    status_string: list[str] | None = None,
) -> bytes:
    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.5",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": message_imprint,
            },
            "serial_number": 123,
            "gen_time": datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        }
    )
    token = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": cms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [{"algorithm": "sha256"}],
                    "encap_content_info": cms.ContentInfo(
                        {"content_type": "tst_info", "content": tst_info}
                    ),
                    "signer_infos": [],
                }
            ),
        }
    )
    response = tsp.TimeStampResp(
        {
            "status": {
                "status": status,
                "status_string": status_string,
            },
            "time_stamp_token": token,
        }
    )
    return response.dump()


def test_timestamp_export_bundle_builds_request_from_bundle_hash_and_writes_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    bundle_dir = tmp_path / "bundle"
    manifest = export_session_bundle(
        artifacts.session_dir,
        bundle_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )
    captured: dict[str, object] = {}

    def fake_post_timestamp_request(
        tsa_url: str,
        request_der: bytes,
        *,
        timeout_seconds: float,
    ) -> tuple[str | None, bytes]:
        captured["tsa_url"] = tsa_url
        captured["request_der"] = request_der
        captured["timeout_seconds"] = timeout_seconds
        return (
            "application/timestamp-reply",
            _build_timestamp_response(bytes.fromhex(manifest["top_level_sha256"])),
        )

    monkeypatch.setattr(
        "stipul.seal.rfc3161_anchor._post_timestamp_request",
        fake_post_timestamp_request,
    )

    receipt = timestamp_export_bundle_rfc3161(bundle_dir, "https://tsa.example")

    request = tsp.TimeStampReq.load(captured["request_der"])
    assert request.native["message_imprint"]["hash_algorithm"]["algorithm"] == "sha256"
    assert request.native["message_imprint"]["hashed_message"] == bytes.fromhex(
        manifest["top_level_sha256"]
    )
    assert request.native["cert_req"] is True
    assert captured["tsa_url"] == "https://tsa.example"

    receipt_path = bundle_dir / "rfc3161_receipt.json"
    assert receipt_path.exists()
    persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert persisted == receipt
    assert receipt["anchored_top_level_sha256"] == manifest["top_level_sha256"]
    assert receipt["message_imprint_hex"] == manifest["top_level_sha256"]
    assert receipt["message_imprint_algorithm"] == "sha256"
    assert receipt["receipt_content_type"] == "application/timestamp-reply"
    assert receipt["tsa_gen_time"] == "2026-01-01T00:00:01Z"
    assert receipt["serial_number"] == "123"
    assert receipt["policy"] == "1.2.3.4.5"


def test_timestamp_export_bundle_refuses_redacted_bundles(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    bundle_dir = tmp_path / "bundle"
    export_session_bundle(
        artifacts.session_dir,
        bundle_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
        redact=True,
    )

    with pytest.raises(
        ValueError,
        match="RFC 3161 timestamping only supports non-redacted export bundles",
    ):
        timestamp_export_bundle_rfc3161(bundle_dir, "https://tsa.example")


def test_timestamp_export_bundle_rejects_non_http_tsa_url_before_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    bundle_dir = tmp_path / "bundle"
    export_session_bundle(
        artifacts.session_dir,
        bundle_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    monkeypatch.setattr(
        "stipul.seal.rfc3161_anchor._post_timestamp_request",
        lambda *args, **kwargs: pytest.fail("network helper should not be called for invalid TSA URLs"),
    )

    with pytest.raises(ValueError, match="TSA URL must use http or https"):
        timestamp_export_bundle_rfc3161(bundle_dir, "file:///tmp/tsa")


def test_timestamp_export_bundle_rejects_non_granted_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    bundle_dir = tmp_path / "bundle"
    export_session_bundle(
        artifacts.session_dir,
        bundle_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    rejection = _build_timestamp_response(
        bytes.fromhex(
            json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))["top_level_sha256"]
        ),
        status="rejection",
        status_string=["tsa policy rejected request"],
    )

    monkeypatch.setattr(
        "stipul.seal.rfc3161_anchor._post_timestamp_request",
        lambda *args, **kwargs: ("application/timestamp-reply", rejection),
    )

    with pytest.raises(ValueError, match="TSA response status rejection"):
        timestamp_export_bundle_rfc3161(bundle_dir, "https://tsa.example")


def test_timestamp_export_bundle_rejects_malformed_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    bundle_dir = tmp_path / "bundle"
    export_session_bundle(
        artifacts.session_dir,
        bundle_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
    )

    monkeypatch.setattr(
        "stipul.seal.rfc3161_anchor._post_timestamp_request",
        lambda *args, **kwargs: ("application/timestamp-reply", b"not-der"),
    )

    with pytest.raises(ValueError, match="Malformed RFC 3161 response"):
        timestamp_export_bundle_rfc3161(bundle_dir, "https://tsa.example")
