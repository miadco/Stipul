from __future__ import annotations

import agentshield


def test_package_exposes_authoritative_version() -> None:
    assert agentshield.__version__ == "0.1.0"
