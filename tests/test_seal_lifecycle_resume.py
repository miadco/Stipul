from __future__ import annotations

import json
from pathlib import Path

import pytest

from stipul.chronicle.signing.verifier import verify_chain as _verify_chronicle_chain
from stipul.seal.verifier import verify_seal
from stipul.writ.proxy.server import ProxyServer
from tests.cli_support import DEFAULT_SESSION_ID, write_contract_file


def _read_events(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.signed_chain
def test_resume_after_sealed_close_rewrites_seal_for_new_terminal_event(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("STIPUL_TOKEN_SECRET", "test-secret")

    contract_path, contract = write_contract_file(tmp_path)
    session_dir = tmp_path / "session"
    session_dir.mkdir(parents=True, exist_ok=True)
    events_path = session_dir / "events.jsonl"

    first_proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=events_path,
    )
    try:
        initial_events = _read_events(events_path)
        assert len(initial_events) == 1
        assert initial_events[0]["event_type"] == "session_open"
    finally:
        first_proxy.close()

    first_events = _read_events(events_path)
    first_seal = json.loads((session_dir / "seal.json").read_text(encoding="utf-8"))
    assert len(first_events) == 2
    assert first_events[-1]["event_type"] == "session_close"
    assert first_seal["terminal_sequence_id"] == 2

    resumed_proxy = ProxyServer.from_contract_path(
        contract_path,
        session_id=DEFAULT_SESSION_ID,
        events_path=events_path,
    )
    try:
        response = resumed_proxy.handle_tool_call(
            {"tool_name": "filesystem.write", "inputs": {"path": "out.txt", "content": "x"}},
            lambda _request: {"ok": True},
        )
        assert response == {"ok": True}
    finally:
        resumed_proxy.close()

    events = _read_events(events_path)
    seal = json.loads((session_dir / "seal.json").read_text(encoding="utf-8"))
    chain_result = _verify_chronicle_chain(
        events_path,
        resumed_proxy.event_logger.signing_key.public_key,
        contract,
    )
    seal_result = verify_seal(
        session_dir,
        resumed_proxy.event_logger.signing_key.public_key,
        contract,
    )

    assert len(events) == 4
    assert events[-1]["event_type"] == "session_close"
    assert seal["terminal_sequence_id"] == len(events)
    assert seal["terminal_sequence_id"] != 2
    assert chain_result.status == "INTACT"
    assert seal_result.status == "VALID"
