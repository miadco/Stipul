from __future__ import annotations

import json
from pathlib import Path

from stipul.seal.exporter import export_session_bundle
from tests.cli_support import create_signed_session


def test_export_includes_scan_report(tmp_path: Path) -> None:
    artifacts = create_signed_session(tmp_path, include_decisions=True, include_summary=True)
    scan_report_path = tmp_path / "scan.json"
    scan_report_path.write_text(
        json.dumps(
            {
                "target": "/tmp/example",
                "scanned_files": 1,
                "skipped_files": 0,
                "findings": [
                    {
                        "finding_id": "AS-SCAN-012",
                        "category": "security_policy",
                        "severity": "info",
                        "title": "Repository is missing SECURITY.md",
                        "description": "The repository root does not contain a SECURITY.md disclosure policy.",
                        "recommendation": "Add SECURITY.md.",
                        "file_path": "SECURITY.md",
                        "line_start": None,
                        "line_end": None,
                        "evidence": ["SECURITY.md not found at scan root"],
                    }
                ],
                "summary": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 1,
                },
                "scanner_version": "1",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "bundle"

    manifest = export_session_bundle(
        artifacts.session_dir,
        out_dir,
        contract=artifacts.contract,
        public_key_path=artifacts.keypair.public_key_path,
        scan_report_path=scan_report_path,
    )

    assert "scan_report.json" in manifest["included_files"]
    assert "scan_report.json" in manifest["hashes"]
    assert (out_dir / "scan_report.json").exists()
