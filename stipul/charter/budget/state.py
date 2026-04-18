"""Persistence for budget state."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from stipul.charter.budget.tracker import BudgetTracker
from stipul.exceptions import BudgetExhaustedError
from stipul.utils.canonical import canonical_json_bytes


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def save_budget_state(state_dir: Path, tracker: BudgetTracker, session_id: str) -> None:
    path = Path(state_dir) / "budget_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / "budget_state.json.tmp"

    payload = {
        "session_id": session_id,
        "max_tool_calls": tracker.max_tool_calls,
        "max_net_calls": tracker.max_net_calls,
        "tool_calls_used": tracker.tool_calls_used,
        "net_calls_used": tracker.net_calls_used,
        "tokens_used": tracker.tokens_used,
        "dollars_used": tracker.dollars_used,
        "exhausted": tracker.exhausted,
        "exhausted_dimension": tracker.exhausted_dimension,
        "exhausted_at": tracker.exhausted_at,
        "saved_at": _utcnow_iso(),
    }

    tmp_path.write_bytes(canonical_json_bytes(payload) + b"\n")
    os.replace(tmp_path, path)


def load_budget_state(state_dir: Path, session_id: str) -> BudgetTracker | None:
    path = Path(state_dir) / "budget_state.json"
    if not path.exists():
        return None

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None

    if payload.get("session_id") != session_id:
        return None

    if payload.get("exhausted") is True:
        raise BudgetExhaustedError(
            "Budget exhausted in prior session. Start a new session with a new charter."
        )

    return BudgetTracker(
        max_tool_calls=payload.get("max_tool_calls"),
        max_net_calls=payload.get("max_net_calls"),
        tool_calls_used=int(payload.get("tool_calls_used", 0)),
        net_calls_used=int(payload.get("net_calls_used", 0)),
        tokens_used=int(payload.get("tokens_used", 0)),
        dollars_used=float(payload.get("dollars_used", 0.0)),
        exhausted=bool(payload.get("exhausted", False)),
        exhausted_dimension=payload.get("exhausted_dimension"),
        exhausted_at=payload.get("exhausted_at"),
    )
