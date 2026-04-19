from __future__ import annotations

import pytest

from stipul.writ.proxy.egress import is_egress_allowed, normalize_egress_target


@pytest.mark.parametrize(
    ("raw_target", "expected"),
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("https://api.example.com", "api.example.com"),
        ("https://example.com:8080/path?q=1#frag", "example.com"),
        ("example.com:443", "example.com"),
        ("", None),
        ("://garbage", None),
    ],
)
def test_normalize_egress_target(raw_target: str, expected: str | None) -> None:
    assert normalize_egress_target(raw_target) == expected


@pytest.mark.parametrize(
    ("allowlist", "target", "expected"),
    [
        (["example.com"], "example.com", True),
        (["example.com"], "api.example.com", False),
        ([".example.com"], "api.example.com", True),
        ([".example.com"], "deep.sub.example.com", True),
        ([".example.com"], "example.com", False),
        (["example.com"], "example.com.evil.net", False),
        ([], "example.com", False),
    ],
)
def test_is_egress_allowed_matches_charter_semantics(
    allowlist: list[str],
    target: str,
    expected: bool,
) -> None:
    normalized_target = normalize_egress_target(target)
    assert normalized_target is not None
    assert is_egress_allowed(normalized_target, allowlist) is expected
