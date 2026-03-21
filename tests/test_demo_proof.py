from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from tests.cli_support import run_cli


def _session_dir_from_output(stdout: str) -> Path:
    match = re.search(
        r"^\s*\.venv/bin/python -m stipul\.cli\.main verify (?P<session>.+)$",
        stdout,
        re.MULTILINE,
    )
    assert match is not None
    return Path(match.group("session").strip())


def test_demo_proof_prints_verified_receipt_and_tamper_payoff() -> None:
    result = run_cli("demo", "proof")

    assert result.returncode == 0
    assert "Session: proof-demo" in result.stdout
    assert "reason: allowed_tool" in result.stdout
    assert "Trust: VERIFIED" in result.stdout
    assert "  Decisions: 3" in result.stdout
    assert "Step 1 — View the current seal:" in result.stdout
    assert "Step 2 — Verify the session as-is:" in result.stdout
    assert "Step 3 — Now tamper with the seal:" in result.stdout
    assert "Step 4 — Re-verify the session:" in result.stdout
    assert "Watch Trust: VERIFIED become Trust: REJECTED." not in result.stdout
    assert "Proof complete" in result.stdout

    session_dir = _session_dir_from_output(result.stdout)
    seal_path = session_dir / "seal.json"

    try:
        assert session_dir.is_absolute()
        assert session_dir.exists()
        assert seal_path.exists()
        assert str(seal_path) in result.stdout

        seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
        assert (
            f"sed -i 's/\"terminal_sequence_id\": {seal_payload['terminal_sequence_id']}"
            f"/\"terminal_sequence_id\": 999/' {seal_path}"
        ) in result.stdout
        assert f"sed -i 's/\"version\": 1/\"version\": 42/' {seal_path}" in result.stdout
        seal_payload["terminal_sequence_id"] = 999
        seal_path.write_text(
            json.dumps(seal_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        verify_result = run_cli("verify", str(session_dir))

        assert verify_result.returncode == 2
        assert "Trust: REJECTED" in verify_result.stdout
        assert "Chain: INTACT" in verify_result.stdout
        assert "Seal: INVALID" in verify_result.stdout
    finally:
        shutil.rmtree(session_dir.parent, ignore_errors=True)
