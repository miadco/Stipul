"""State-directory session lock management."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import IO

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised on non-POSIX platforms only
    fcntl = None  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)
_UNSUPPORTED_WARNING = (
    "Session locking is not supported on this platform. "
    "Do not run multiple proxy instances against the same state directory."
)
_LOCK_CONFLICT_MESSAGE = (
    "Another proxy instance is running in this state directory. "
    "Only one active session per state directory is permitted."
)

_PROCESS_LOCK = Lock()
_PROCESS_LOCKED_DIRS: set[Path] = set()


class SessionLockError(RuntimeError):
    """Raised when session lock acquisition fails."""


@dataclass
class FileLock:
    """Represents a held session lock file handle."""

    state_dir: Path
    path: Path
    handle: IO[str]
    supported: bool
    released: bool = False


def acquire_session_lock(state_dir: Path) -> FileLock:
    """Acquire exclusive state-dir lock for the session lifetime."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "session.lock"
    handle = lock_path.open("a+", encoding="utf-8")

    with _PROCESS_LOCK:
        if state_dir in _PROCESS_LOCKED_DIRS:
            handle.close()
            raise SessionLockError(_LOCK_CONFLICT_MESSAGE)

        if fcntl is None:
            _LOGGER.warning(_UNSUPPORTED_WARNING)
            _PROCESS_LOCKED_DIRS.add(state_dir)
            return FileLock(
                state_dir=state_dir,
                path=lock_path,
                handle=handle,
                supported=False,
            )

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise SessionLockError(_LOCK_CONFLICT_MESSAGE) from exc
        except Exception:
            handle.close()
            raise

        _PROCESS_LOCKED_DIRS.add(state_dir)
        return FileLock(
            state_dir=state_dir,
            path=lock_path,
            handle=handle,
            supported=True,
        )


def release_session_lock(lock: FileLock) -> None:
    """Release session lock and close lock file handle."""
    if lock.released:
        return

    try:
        if lock.supported and fcntl is not None:
            fcntl.flock(lock.handle.fileno(), fcntl.LOCK_UN)
    finally:
        lock.handle.close()
        lock.released = True
        with _PROCESS_LOCK:
            _PROCESS_LOCKED_DIRS.discard(lock.state_dir)
