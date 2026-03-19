from __future__ import annotations

from pathlib import Path

from stipul.scanner import MCPScanner


def test_scan_core_finds_bounded_high_signal_issues(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (repo / "runner.py").write_text(
        "import subprocess\n"
        "def run(cmd: str) -> None:\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "wrapper_handler.py").write_text(
        "def handle(headers: dict[str, str]) -> str:\n"
        '    token = headers["Authorization"]\n'
        "    return token\n",
        encoding="utf-8",
    )
    (repo / "secrets.py").write_text(
        'API_KEY = "sk-1234567890abcdef1234567890"\n',
        encoding="utf-8",
    )
    (repo / "contract.json").write_text(
        '{\n  "allowed_tools": ["*"],\n  "egress_allowlist": ["api.example.com"]\n}\n',
        encoding="utf-8",
    )
    (repo / "large.md").write_bytes(b"x" * 2048)

    report = MCPScanner(max_file_bytes=1024).scan_path(repo)

    finding_pairs = {(finding.finding_id, finding.severity) for finding in report.findings}
    assert ("AS-SCAN-002", "critical") in finding_pairs
    assert ("AS-SCAN-003", "high") in finding_pairs
    assert ("AS-SCAN-004", "high") in finding_pairs
    assert ("AS-SCAN-005", "high") in finding_pairs
    assert report.scanned_files == 5
    assert report.skipped_files == 1


def test_scan_core_redacts_secret_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    secret_value = "sk-1234567890abcdef1234567890"
    (repo / "secrets.py").write_text(f'SERVICE_KEY = "{secret_value}"\n', encoding="utf-8")

    report = MCPScanner().scan_path(repo)

    secret_finding = next(finding for finding in report.findings if finding.finding_id == "AS-SCAN-004")
    evidence_text = "\n".join(secret_finding.evidence)
    assert secret_value not in evidence_text
    assert "sk-1..." in evidence_text


def test_scan_core_missing_security_md_reports_info(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "notes.md").write_text("hello\n", encoding="utf-8")

    report = MCPScanner().scan_path(repo)

    security_finding = next(finding for finding in report.findings if finding.finding_id == "AS-SCAN-012")
    assert security_finding.severity == "info"
