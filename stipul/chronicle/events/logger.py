"""Thread-safe Event Stream logger."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from stipul.chronicle.events.models import CanonicalEvent
from stipul.chronicle.events.store import EventStore
from stipul.writ.proxy.session_head import read_session_head, write_session_head
from stipul.chronicle.signing.keys import RuntimeKeyPair
from stipul.chronicle.signing.signer import sign_event
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash


class EventWriteError(Exception):
    """Raised when appending an event to storage fails."""


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_full_event_payload(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(event)).hexdigest()


@dataclass
class EventLogger:
    """Generate, sign, and append canonical events with monotonic sequence ids."""

    store: EventStore
    session_id: str
    contract_id: str
    contract_hash: str
    signing_key: RuntimeKeyPair
    state_dir: Path
    prev_chain_terminal_hash: str | None = None
    prev_session_id: str | None = None
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _sequence_id: int = field(default=0, init=False)
    _last_event_timestamp: str | None = field(default=None, init=False)
    _last_event_hash: str | None = field(default=None, init=False)
    _pending_prev_unsigned_terminal_hash: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir)
        self._bootstrap_state()

    @property
    def last_event_timestamp(self) -> str | None:
        return self._last_event_timestamp

    def _bootstrap_state(self) -> None:
        head = read_session_head(self.state_dir)
        if head is not None and head.get("session_id") == self.session_id:
            self._sequence_id = int(head["sequence_id"])
            self._last_event_hash = str(head["event_hash"]).lower()
            return

        # No usable head: start a fresh signed chain and only retain sequence continuity.
        if not self.store.path.exists():
            return

        last_sequence = 0
        last_timestamp: str | None = None
        saw_signed = False
        last_unsigned_hash: str | None = None

        with self.store.path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                seq = event.get("sequence_id")
                if isinstance(seq, int) and seq > last_sequence:
                    last_sequence = seq
                    timestamp = event.get("timestamp")
                    if isinstance(timestamp, str):
                        last_timestamp = timestamp
                if event.get("signature") is None:
                    last_unsigned_hash = _hash_full_event_payload(event)
                else:
                    saw_signed = True

        self._sequence_id = last_sequence
        self._last_event_timestamp = last_timestamp
        if not saw_signed and last_unsigned_hash is not None:
            self._pending_prev_unsigned_terminal_hash = last_unsigned_hash

    def _read_file_session_id(self) -> str | None:
        if not self.store.path.exists():
            return None
        with self.store.path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception as exc:
                    raise EventWriteError("events.jsonl first line is malformed JSON") from exc
                if not isinstance(payload, dict):
                    raise EventWriteError("events.jsonl first line must be a JSON object")
                value = payload.get("session_id")
                if not isinstance(value, str) or not value:
                    raise EventWriteError("events.jsonl first line missing session_id")
                return value
        return None

    def _assert_session_boundary(self) -> None:
        file_session_id = self._read_file_session_id()
        if file_session_id is None:
            return
        if file_session_id != self.session_id:
            raise EventWriteError(
                "fatal write error: events.jsonl session_id mismatch. "
                f"file has '{file_session_id}', logger has '{self.session_id}'."
            )

    def _build_payload(self, event_kwargs: dict[str, Any], sequence_id: int) -> dict[str, Any]:
        payload = dict(event_kwargs)
        payload["sequence_id"] = sequence_id
        payload["timestamp"] = _now_iso_utc()
        payload["session_id"] = self.session_id
        payload["contract_id"] = self.contract_id
        payload["contract_hash"] = self.contract_hash
        payload["key_id"] = self.signing_key.key_id
        payload["algorithm"] = self.signing_key.algorithm
        payload["key_created_at"] = self.signing_key.key_created_at
        payload["prev_hash"] = self._last_event_hash or self.contract_hash

        if self._last_event_hash is None:
            if self._pending_prev_unsigned_terminal_hash is not None:
                payload["prev_unsigned_terminal_hash"] = self._pending_prev_unsigned_terminal_hash
            else:
                payload.pop("prev_unsigned_terminal_hash", None)

            if self.prev_chain_terminal_hash is not None and self.prev_session_id is not None:
                payload["prev_chain_terminal_hash"] = self.prev_chain_terminal_hash
                payload["prev_session_id"] = self.prev_session_id
            else:
                payload.pop("prev_chain_terminal_hash", None)
                payload.pop("prev_session_id", None)
        else:
            payload.pop("prev_unsigned_terminal_hash", None)
            payload.pop("prev_chain_terminal_hash", None)
            payload.pop("prev_session_id", None)
        return payload

    def log_event(self, event_kwargs: dict[str, Any]) -> CanonicalEvent:
        """Validate, sequence, sign, persist, and return a canonical event."""
        with self._lock:
            self._assert_session_boundary()

            expected_sequence = self._sequence_id + 1
            if "sequence_id" in event_kwargs and event_kwargs["sequence_id"] != expected_sequence:
                raise ValueError(
                    f"sequence_id gap detected: expected {expected_sequence}, "
                    f"got {event_kwargs['sequence_id']}"
                )

            if "session_id" in event_kwargs and event_kwargs["session_id"] != self.session_id:
                raise EventWriteError(
                    f"fatal write error: event session_id {event_kwargs['session_id']} "
                    f"does not match logger session_id {self.session_id}"
                )

            payload = self._build_payload(event_kwargs, expected_sequence)
            payload["signature"] = sign_event(payload, self.signing_key.private_key)
            event = CanonicalEvent(**payload)
            event_dict = event.to_dict()
            line = canonical_json_bytes(event_dict).decode("utf-8")

            try:
                self.store.append(line)
                write_session_head(self.state_dir, event_dict)
            except Exception as exc:
                raise EventWriteError("failed to append signed event") from exc

            self._sequence_id = expected_sequence
            self._last_event_timestamp = event.timestamp
            self._last_event_hash = compute_prev_hash(event_dict)
            if "prev_unsigned_terminal_hash" in event_dict:
                self._pending_prev_unsigned_terminal_hash = None
            return event
