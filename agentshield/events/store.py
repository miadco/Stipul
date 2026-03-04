"""Append-only JSONL event storage."""

from __future__ import annotations

from pathlib import Path


class EventStore:
    """Manage append-only writes to an events.jsonl file."""

    def __init__(self, path: str | Path = "events.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, line: str) -> None:
        if not isinstance(line, str):
            raise TypeError("line must be a string")

        to_write = line if line.endswith("\n") else f"{line}\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(to_write)
