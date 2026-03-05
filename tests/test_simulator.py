from __future__ import annotations

import copy

from agentshield.contract.schema import Contract
from agentshield.simulation.simulator import PolicySimulator


def test_simulate_no_changes(contract, make_test_events):
    simulator = PolicySimulator()
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    summary = simulator.simulate(events_path, contract)

    assert summary.total_evaluated == 1
    assert summary.changed_count == 0
    assert summary.records[0].changed is False


def test_simulate_allow_to_deny(base_dict, make_test_events):
    simulator = PolicySimulator()
    payload = copy.deepcopy(base_dict)
    payload["allowed_tools"] = ["web.search"]
    contract = Contract.from_dict(payload)
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    summary = simulator.simulate(events_path, contract)

    assert summary.changed_count == 1
    assert summary.records[0].simulated_decision == "deny"
    assert summary.records[0].simulated_reason == "not_in_contract"


def test_simulate_deny_to_allow(base_dict, make_test_events):
    simulator = PolicySimulator()
    payload = copy.deepcopy(base_dict)
    payload["allowed_tools"] = sorted(set(payload["allowed_tools"]) | {"debug.inspect"})
    payload["tool_risk_classes"]["debug.inspect"] = "write"
    contract = Contract.from_dict(payload)
    events_path = make_test_events(
        [
            {
                "tool_name": "debug.inspect",
                "decision": "deny",
                "reason": "not_in_contract",
            }
        ]
    )

    summary = simulator.simulate(events_path, contract)

    assert summary.changed_count == 1
    assert summary.records[0].simulated_decision == "allow"
    assert summary.records[0].simulated_reason == "risk_class"


def test_simulate_allow_to_require_approval(base_dict, make_test_events):
    simulator = PolicySimulator()
    payload = copy.deepcopy(base_dict)
    payload["tool_risk_classes"]["filesystem.write"] = "irreversible"
    contract = Contract.from_dict(payload)
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    summary = simulator.simulate(events_path, contract)

    assert summary.changed_count == 1
    assert summary.records[0].simulated_decision == "require_approval"
    assert summary.records[0].simulated_reason == "risk_class"


def test_diff_returns_only_changed_records(base_dict, make_test_events):
    simulator = PolicySimulator()
    contract_a = Contract.from_dict(base_dict)
    payload_b = copy.deepcopy(base_dict)
    payload_b["tool_risk_classes"]["filesystem.write"] = "irreversible"
    contract_b = Contract.from_dict(payload_b)
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            },
            {
                "tool_name": "web.search",
                "decision": "allow",
                "reason": "risk_class",
            },
        ]
    )

    diff = simulator.diff(events_path, contract_a, contract_b)

    assert diff.total_evaluated == 2
    assert diff.changed_count == 1
    assert len(diff.records) == 1
    assert diff.records[0].tool_name == "filesystem.write"


def test_formatters_include_headers_and_detail_line(contract, make_test_events):
    simulator = PolicySimulator()
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    summary = simulator.simulate(events_path, contract)
    diff = simulator.diff(events_path, contract, contract)

    formatted_summary = simulator.format_results(summary)
    formatted_diff = simulator.format_diff(diff)

    assert "Simulation Results" in formatted_summary
    assert "seq=1" in formatted_summary
    assert "Simulation Diff" in formatted_diff


def test_simulate_is_deterministic(contract, make_test_events):
    simulator = PolicySimulator()
    events_path = make_test_events(
        [
            {
                "tool_name": "filesystem.write",
                "decision": "allow",
                "reason": "risk_class",
            }
        ]
    )

    first = simulator.simulate(events_path, contract)
    second = simulator.simulate(events_path, contract)

    assert first == second
