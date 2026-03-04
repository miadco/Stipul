from __future__ import annotations

from agentshield.proxy.egress import check_egress


def test_egress_exact_domain_allowed(contract):
    allowed, reason = check_egress("api.example.com", contract)
    assert allowed is True
    assert reason == "allowed"


def test_egress_subdomain_of_allowlisted_domain_allowed(contract):
    allowed, reason = check_egress("sub.api.example.com", contract)
    assert allowed is True
    assert reason == "allowed"


def test_egress_suffix_entry_allows_subdomain(contract):
    allowed, reason = check_egress("logs.trusted.example", contract)
    assert allowed is True
    assert reason == "allowed"


def test_egress_denied_when_not_allowlisted(contract):
    allowed, reason = check_egress("evil.example.org", contract)
    assert allowed is False
    assert reason == "not_in_egress_allowlist"
