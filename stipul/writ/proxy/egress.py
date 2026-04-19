"""Egress helpers shared by proxy ingress and policy evaluation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlparse

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_hostname(hostname: str) -> str | None:
    host = hostname.strip().rstrip(".")
    if not host:
        return None

    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(ascii_host) > 253:
        return None

    labels = ascii_host.split(".")
    if any(not label or not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return ascii_host


def normalize_egress_target(raw_target: str) -> str | None:
    """Parse a raw egress target and return a normalized hostname."""
    if not isinstance(raw_target, str):
        return None

    target = raw_target.strip()
    if not target:
        return None

    candidate = target if "://" in target else f"//{target}"
    try:
        parsed = urlparse(candidate)
        _ = parsed.port
    except ValueError:
        return None

    if "://" in target:
        if not parsed.scheme or not parsed.netloc:
            return None
    elif not parsed.netloc:
        return None

    if parsed.username is not None or parsed.password is not None:
        return None

    if parsed.hostname is None:
        return None
    return _normalize_hostname(parsed.hostname)


def _normalize_allowlist_entry(entry: str) -> tuple[str, bool] | None:
    normalized_entry = entry.strip().lower()
    if not normalized_entry:
        return None
    if normalized_entry.startswith("."):
        suffix = _normalize_hostname(normalized_entry[1:])
        if suffix is None:
            return None
        return suffix, True

    exact_host = _normalize_hostname(normalized_entry)
    if exact_host is None:
        return None
    return exact_host, False


def is_egress_allowed(normalized_hostname: str, allowlist: Iterable[str]) -> bool:
    """Match a normalized hostname against exact-host and leading-dot suffix entries."""
    for entry in allowlist:
        normalized_entry = _normalize_allowlist_entry(entry)
        if normalized_entry is None:
            continue

        allowed_host, is_suffix = normalized_entry
        if is_suffix:
            if normalized_hostname.endswith(f".{allowed_host}"):
                return True
            continue

        if normalized_hostname == allowed_host:
            return True

    return False
