"""Key lifecycle management for the Signing Layer."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_LOGGER = logging.getLogger(__name__)

_KEYS_DIR_MODE = 0o700
_PRIVATE_KEY_MODE = 0o600
_PUBLIC_KEY_MODE = 0o644
_METADATA_MODE = 0o600
_KEY_PREFIX = "runtime_"
_PRIVATE_SUFFIX = ".pem"
_PUBLIC_SUFFIX = ".pub"
_METADATA_SUFFIX = ".meta.json"


class KeyNotFoundError(FileNotFoundError):
    """Raised when a runtime signing key cannot be found."""


class KeyMetadataError(RuntimeError):
    """Raised when runtime key metadata is missing or malformed."""


@dataclass(frozen=True)
class RuntimeKeyPair:
    """Runtime signing key pair and identity metadata."""

    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    algorithm: str
    key_created_at: str
    private_key_path: Path
    public_key_path: Path
    metadata_path: Path


def default_keys_dir() -> Path:
    return Path.home() / ".stipul" / "keys"


def _ensure_dir_mode(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, _KEYS_DIR_MODE)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _runtime_key_stem(key_id: str) -> str:
    return f"{_KEY_PREFIX}{key_id}"


def _private_key_path(keys_dir: Path, key_id: str) -> Path:
    return keys_dir / f"{_runtime_key_stem(key_id)}{_PRIVATE_SUFFIX}"


def _public_key_path(keys_dir: Path, key_id: str) -> Path:
    return keys_dir / f"{_runtime_key_stem(key_id)}{_PUBLIC_SUFFIX}"


def _metadata_path(keys_dir: Path, key_id: str) -> Path:
    return keys_dir / f"{_runtime_key_stem(key_id)}{_METADATA_SUFFIX}"


def _write_bytes(path: Path, payload: bytes, mode: int) -> None:
    path.write_bytes(payload)
    os.chmod(path, mode)


def _atomic_write_json(path: Path, payload: dict[str, str], mode: int) -> None:
    tmp_path = path.parent / f"{path.name}.tmp"
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    tmp_path.write_text(f"{serialized}\n", encoding="utf-8")
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)
    os.chmod(path, mode)


def _public_key_raw_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def get_key_id(public_key: Ed25519PublicKey) -> str:
    """Return key id as first 8 chars of SHA-256(public key bytes)."""
    return hashlib.sha256(_public_key_raw_bytes(public_key)).hexdigest()[:8]


def _parse_key_id_from_private_key_path(path: Path) -> str | None:
    if not path.name.startswith(_KEY_PREFIX) or not path.name.endswith(_PRIVATE_SUFFIX):
        return None
    key_id = path.name[len(_KEY_PREFIX) : -len(_PRIVATE_SUFFIX)]
    if len(key_id) != 8:
        return None
    if any(ch not in "0123456789abcdefABCDEF" for ch in key_id):
        return None
    return key_id.lower()


def _load_metadata(keys_dir: Path, key_id: str) -> tuple[str, str]:
    metadata_path = _metadata_path(keys_dir, key_id)
    if not metadata_path.exists():
        message = (
            f"Key metadata missing for key_id `{key_id}`. "
            "Re-generate key with `stipul rotate-key`."
        )
        _LOGGER.error(message)
        raise KeyMetadataError(message)

    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise KeyMetadataError(f"invalid key metadata file: {metadata_path}") from exc

    algorithm = payload.get("algorithm")
    created_at = payload.get("created_at")
    stored_key_id = payload.get("key_id")

    if stored_key_id != key_id:
        raise KeyMetadataError(
            f"key metadata key_id mismatch: expected {key_id}, found {stored_key_id}"
        )
    if algorithm != "ed25519":
        raise KeyMetadataError(
            f"unsupported key algorithm in metadata: {algorithm!r} (expected 'ed25519')"
        )
    if not isinstance(created_at, str) or not created_at:
        raise KeyMetadataError("key metadata created_at must be non-empty ISO 8601 string")

    return algorithm, created_at


def _build_runtime_keypair(keys_dir: Path, key_id: str) -> RuntimeKeyPair:
    private_path = _private_key_path(keys_dir, key_id)
    public_path = _public_key_path(keys_dir, key_id)
    metadata_path = _metadata_path(keys_dir, key_id)

    if not private_path.exists():
        raise KeyNotFoundError(f"missing private key: {private_path}")
    if not public_path.exists():
        raise KeyNotFoundError(f"missing public key: {public_path}")

    private_candidate = serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=None,
    )
    if not isinstance(private_candidate, Ed25519PrivateKey):
        raise ValueError(f"private key is not Ed25519: {private_path}")

    public_candidate = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(public_candidate, Ed25519PublicKey):
        raise ValueError(f"public key is not Ed25519: {public_path}")

    computed_key_id = get_key_id(public_candidate)
    if computed_key_id != key_id:
        raise ValueError(
            "key_id mismatch for loaded keypair: "
            f"expected {key_id}, computed {computed_key_id}"
        )

    algorithm, key_created_at = _load_metadata(keys_dir, key_id)
    return RuntimeKeyPair(
        key_id=key_id,
        private_key=private_candidate,
        public_key=public_candidate,
        algorithm=algorithm,
        key_created_at=key_created_at,
        private_key_path=private_path,
        public_key_path=public_path,
        metadata_path=metadata_path,
    )


def load_key(key_id: str, keys_dir: str | Path | None = None) -> RuntimeKeyPair:
    """Load an existing runtime keypair by key id."""
    if not isinstance(key_id, str) or len(key_id) != 8:
        raise ValueError("key_id must be an 8-character hexadecimal string")

    normalized_key_id = key_id.lower()
    if any(ch not in "0123456789abcdef" for ch in normalized_key_id):
        raise ValueError("key_id must be an 8-character hexadecimal string")

    key_dir = Path(keys_dir) if keys_dir is not None else default_keys_dir()
    return _build_runtime_keypair(key_dir, normalized_key_id)


def load_latest_keypair(keys_dir: str | Path | None = None) -> RuntimeKeyPair | None:
    """Load the newest runtime keypair from storage, if present."""
    key_dir = Path(keys_dir) if keys_dir is not None else default_keys_dir()
    if not key_dir.exists():
        return None

    candidates = sorted(
        key_dir.glob(f"{_KEY_PREFIX}*{_PRIVATE_SUFFIX}"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for private_path in candidates:
        key_id = _parse_key_id_from_private_key_path(private_path)
        if key_id is None:
            continue
        return _build_runtime_keypair(key_dir, key_id)
    return None


def generate_keypair(keys_dir: str | Path | None = None) -> RuntimeKeyPair:
    """Generate and persist a new runtime Ed25519 keypair."""
    key_dir = Path(keys_dir) if keys_dir is not None else default_keys_dir()
    _ensure_dir_mode(key_dir)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = get_key_id(public_key)
    created_at = _utc_now_iso()

    private_path = _private_key_path(key_dir, key_id)
    public_path = _public_key_path(key_dir, key_id)
    metadata_path = _metadata_path(key_dir, key_id)

    _write_bytes(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        _PRIVATE_KEY_MODE,
    )
    _write_bytes(
        public_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        _PUBLIC_KEY_MODE,
    )
    _atomic_write_json(
        metadata_path,
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "created_at": created_at,
        },
        _METADATA_MODE,
    )

    return RuntimeKeyPair(
        key_id=key_id,
        private_key=private_key,
        public_key=public_key,
        algorithm="ed25519",
        key_created_at=created_at,
        private_key_path=private_path,
        public_key_path=public_path,
        metadata_path=metadata_path,
    )


def load_or_create_keypair(keys_dir: str | Path | None = None) -> RuntimeKeyPair:
    """Load existing keypair or create one on first startup."""
    existing = load_latest_keypair(keys_dir)
    if existing is not None:
        return existing
    return generate_keypair(keys_dir)


def _archive_runtime_keypair(keys_dir: Path, key_id: str) -> None:
    archived_dir = keys_dir / "archived"
    _ensure_dir_mode(archived_dir)

    suffixes = (_PRIVATE_SUFFIX, _PUBLIC_SUFFIX, _METADATA_SUFFIX)
    for suffix in suffixes:
        source_path = keys_dir / f"{_runtime_key_stem(key_id)}{suffix}"
        if not source_path.exists():
            continue
        destination_path = archived_dir / source_path.name
        if destination_path.exists():
            timestamp = int(datetime.now(timezone.utc).timestamp())
            destination_path = archived_dir / f"{source_path.stem}_{timestamp}{source_path.suffix}"
        shutil.move(str(source_path), str(destination_path))


def rotate_key(keys_dir: str | Path | None = None) -> RuntimeKeyPair:
    """Archive current runtime keypair and generate a new one."""
    key_dir = Path(keys_dir) if keys_dir is not None else default_keys_dir()
    _ensure_dir_mode(key_dir)

    current = load_latest_keypair(key_dir)
    if current is not None:
        _archive_runtime_keypair(key_dir, current.key_id)

    return generate_keypair(key_dir)
