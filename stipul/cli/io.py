"""CLI IO helpers for stable JSON, JSONL, and path handling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CLIError(RuntimeError):
    """User-facing CLI error with an associated exit code."""

    def __init__(self, message: str, exit_code: int = 3) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


def read_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"JSON file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: line {exc.lineno} column {exc.colno}") from exc


def write_json(path: Path, data: Any, *, pretty: bool, sort_keys: bool) -> None:
    payload = json.dumps(
        data,
        indent=2 if pretty else None,
        sort_keys=sort_keys,
        separators=None if pretty else (",", ":"),
    )
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(f"{payload}\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    input_path = Path(path)
    try:
        raw_lines = input_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"JSONL file not found: {path}") from exc

    for line_number, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSONL in {path}: line {line_number} column {exc.colno}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Invalid JSONL in {path}: line {line_number} is not an object")
        output.append(payload)
    return output


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(record, sort_keys=True, separators=(",", ":"))
        for record in records
    ]
    output_path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def ensure_session_dir(path: Path) -> Path:
    session_dir = Path(path)
    if not session_dir.exists():
        raise ValueError(f"Session directory does not exist: {session_dir}")
    if not session_dir.is_dir():
        raise ValueError(f"Session directory is not a directory: {session_dir}")
    events_path = session_dir / "events.jsonl"
    if not events_path.exists():
        raise ValueError(f"Session directory missing events.jsonl: {session_dir}")
    if not events_path.is_file():
        raise ValueError(f"Session events path is not a file: {events_path}")
    return session_dir


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
