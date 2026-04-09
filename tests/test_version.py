from __future__ import annotations

import stipul


def test_package_exposes_authoritative_version() -> None:
    assert stipul.__version__ == "0.2.2"
