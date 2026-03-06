"""MCP Proxy server orchestration."""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
from typing import Any, Callable, Mapping

from stipul.charter.budget import (
    BudgetTracker,
    DecayAnomaly,
    DecayDetector,
    load_budget_state,
    save_budget_state,
)
from stipul.writ.breakglass import BreakGlassEvent, BreakGlassManager
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.writ.detection.bypass import BypassDetector
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.events.summary import SessionSummary
from stipul.health.endpoint import HealthEndpoint
from stipul.charter.permits import ExceptionPermit, PermitManager, load_permit_secret
from stipul.writ.proxy.circuit_breaker import CircuitBreaker
from stipul.writ.proxy.egress import check_egress
from stipul.writ.proxy.interceptor import InterceptResult, intercept
from stipul.writ.proxy.session import SessionState
from stipul.writ.proxy.session_lock import FileLock, acquire_session_lock, release_session_lock
from stipul.writ.proxy.startup import check_secret_isolation
from stipul.chronicle.signing.keys import load_or_create_keypair
from stipul.charter.token.mint import mint_token
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash

_LOGGER = logging.getLogger(__name__)


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _risk_to_wire(risk: str) -> str:
    return risk.replace("_", "-")


def _structured_error(reason: str, tool_name: str) -> dict[str, str]:
    return {
        "decision": "deny",
        "reason": reason,
        "tool_name": tool_name,
    }


def _safe_tool_name(raw_request: Mapping[str, Any]) -> str:
    tool_name = raw_request.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        return tool_name
    return "unknown_tool"


def _safe_inputs(raw_request: Mapping[str, Any]) -> dict[str, Any]:
    value = raw_request.get("inputs", raw_request.get("input", {}))
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return {"value": value}


def _input_hash(raw_request: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(_safe_inputs(raw_request))).hexdigest()


def _agent_identity_hash(agent_id: str, code_sha256: str | None) -> str:
    payload = {"agent_id": agent_id, "code_sha256": code_sha256}
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _extract_egress_target(raw_request: Mapping[str, Any]) -> str | None:
    inputs = _safe_inputs(raw_request)
    if isinstance(inputs, dict):
        target = inputs.get("egress_target")
        if isinstance(target, str) and target:
            return target
    return None


def _merge_headers(raw_request: Mapping[str, Any], token: str) -> dict[str, Any]:
    forwarded = dict(raw_request)
    headers = dict(raw_request.get("headers", {}))
    headers["Authorization"] = f"Bearer {token}"
    forwarded["headers"] = headers
    return forwarded


def _read_first_session_id(events_path: Path) -> str | None:
    if not events_path.exists():
        return None
    with events_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("events.jsonl first line must be a JSON object")
            value = payload.get("session_id")
            if not isinstance(value, str) or not value:
                raise ValueError("events.jsonl first line missing session_id")
            return value
    return None


def _is_base64_signature(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return False
    return True


def _last_parseable_signed_event_hash(events_path: Path) -> str | None:
    last_hash: str | None = None
    if not events_path.exists():
        return None
    with events_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if not _is_base64_signature(payload.get("signature")):
                continue
            last_hash = compute_prev_hash(payload)
    return last_hash


def _rename_for_session_boundary(events_path: Path, old_session_id: str) -> Path:
    safe_session = old_session_id if old_session_id else "unknown"
    target = events_path.with_name(f"events_{safe_session}.jsonl")
    if not target.exists():
        events_path.rename(target)
        return target

    counter = 1
    while True:
        candidate = events_path.with_name(f"events_{safe_session}_{counter}.jsonl")
        if not candidate.exists():
            events_path.rename(candidate)
            return candidate
        counter += 1


def _prepare_events_file(events_path: Path, session_id: str) -> tuple[str | None, str | None]:
    events_path.parent.mkdir(parents=True, exist_ok=True)
    if not events_path.exists():
        events_path.touch()
        return None, None
    first_session_id = _read_first_session_id(events_path)
    if first_session_id is None:
        return None, None
    if first_session_id != session_id:
        archived_path = _rename_for_session_boundary(events_path, first_session_id)
        previous_chain_hash = _last_parseable_signed_event_hash(archived_path)
        events_path.touch()
        if previous_chain_hash is None:
            return None, None
        return first_session_id, previous_chain_hash
    return None, None


@dataclass
class ProxyServer:
    """Runtime Enforcement Proxy for Week 2."""

    contract: Contract
    event_logger: EventLogger
    session_id: str
    passthrough: bool = False
    interactive: bool = False
    allow_read_fail_open: bool = False
    requesting_agent_id: str | None = None
    requesting_code_sha256: str | None = None
    session_lock: FileLock | None = None
    state_dir: Path | None = None
    budget_tracker: BudgetTracker | None = None
    decay_detector: DecayDetector | None = None
    active_permits: list[ExceptionPermit] = field(default_factory=list)
    active_breakglass: BreakGlassEvent | None = None

    def __post_init__(self) -> None:
        self._tool_calls_made = 0
        self._net_calls_made = 0
        self._session_start = datetime.now(timezone.utc)
        self.state_dir = Path(self.state_dir or self.event_logger.store.path.parent)
        self._contract_hash = compute_contract_hash(self.contract)
        self.budget_tracker = self.budget_tracker or BudgetTracker.from_contract(self.contract)
        self.decay_detector = self.decay_detector or DecayDetector.from_contract(
            self.contract,
            self._session_start,
        )
        self._agent_id = self.requesting_agent_id or self.contract.identity_agent_id
        self._agent_identity_hash = _agent_identity_hash(
            self._agent_id,
            self.requesting_code_sha256,
        )
        self.health = HealthEndpoint(contract_id=self.contract.contract_id)
        self.circuit_breaker = CircuitBreaker(
            allow_read_fail_open=self.allow_read_fail_open,
            on_state_change=self._on_circuit_state_change,
        )
        self._permit_secret: bytes | None = None
        if self.active_permits:
            self._permit_secret = load_permit_secret()

        if self.passthrough:
            print("⚠ PASSTHROUGH MODE — enforcement disabled")

    def close(self) -> None:
        if self.session_lock is None:
            return
        release_session_lock(self.session_lock)
        self.session_lock = None

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        try:
            self.close()
        except Exception as exc:
            _LOGGER.debug("ProxyServer cleanup failed during __del__", exc_info=exc)

    def session_close(
        self,
        state: SessionState,
        session_end: datetime,
        chain_result: Any,
    ) -> SessionSummary:
        """
        Close a session by emitting a summary and decisions projection.

        Execution order:
        1. Build summary from events and runtime budget state
        2. Write summary JSON
        3. Emit summary event through EventLogger
        4. Generate and write decisions projection
        5. Verify decisions projection and warn on mismatch
        6. Mark state as closed
        """
        from stipul.chronicle.events.decisions import (
            generate_decisions,
            verify_decisions,
            write_decisions,
        )
        from stipul.chronicle.events.summary import (
            build_summary,
            summary_to_event,
            write_summary_json,
        )

        if not isinstance(state, SessionState):
            raise TypeError("state must be SessionState")
        if session_end.tzinfo is None:
            raise ValueError("session_end must be UTC-aware")
        if state.closed:
            raise RuntimeError("Session is already closed")

        tracker = self.budget_tracker
        if tracker is None:
            budget_consumed = {
                "tool_calls": float(state.budget_consumed.get("tool_calls", state.tool_calls_used)),
                "net_calls": float(state.budget_consumed.get("net_calls", state.net_calls_used)),
            }
            budget_exhaustion_timestamp: str | None = None
        else:
            budget_consumed = {
                "tool_calls": float(tracker.tool_calls_used),
                "net_calls": float(tracker.net_calls_used),
            }
            budget_exhaustion_timestamp = tracker.exhausted_at if tracker.exhausted else None

        coverage_fields: dict[str, Any] | None = None
        state_dir = Path(getattr(self, "state_dir", state.events_path.parent) or state.events_path.parent)
        wrapper_log_path = state_dir / "wrapper_log.jsonl"
        if wrapper_log_path.exists():
            detector = BypassDetector(state.events_path, wrapper_log_path)
            report = detector.detect(state.session_start, session_end)
            coverage_fields = detector.to_summary_fields(report)
            for gap_payload in detector.emit_gap_events(report.gaps):
                gap_hash_payload = {
                    "tool_name": gap_payload["tool_name"],
                    "reason": gap_payload["reason"],
                    "metadata": gap_payload["metadata"],
                }
                self.event_logger.log_event(
                    {
                        **gap_payload,
                        "agent_identity": self._agent_identity_hash,
                        "input_hash": hashlib.sha256(
                            canonical_json_bytes(gap_hash_payload)
                        ).hexdigest(),
                    }
                )

        summary = build_summary(
            events_path=state.events_path,
            contract=self.contract,
            session_id=state.session_id,
            session_start=state.session_start,
            session_end=session_end,
            chain_result=chain_result,
            budget_consumed=budget_consumed,
            budget_exhaustion_timestamp=budget_exhaustion_timestamp,
            coverage_fields=coverage_fields,
        )

        write_summary_json(summary, state.summary_path)
        event_payload = summary_to_event(summary, agent_identity=self._agent_identity_hash)
        self.event_logger.log_event(event_payload)

        decisions = generate_decisions(state.events_path)
        write_decisions(decisions, state.decisions_path)
        verification = verify_decisions(state.events_path, state.decisions_path)
        if not verification.is_valid:
            _LOGGER.warning(
                "decisions.jsonl failed post-write verification. %s mismatches. "
                "events.jsonl is authoritative.",
                len(verification.mismatches),
            )

        state.budget_consumed = budget_consumed
        state.tool_calls_used = int(budget_consumed["tool_calls"])
        state.net_calls_used = int(budget_consumed["net_calls"])
        state.closed = True
        return summary

    @classmethod
    def from_contract_path(
        cls,
        contract_path: str | Path,
        *,
        session_id: str,
        events_path: str | Path = "events.jsonl",
        passthrough: bool = False,
        interactive: bool = False,
        allow_read_fail_open: bool = False,
        requesting_agent_id: str | None = None,
        requesting_code_sha256: str | None = None,
        agent_pid: int | None = None,
        inspect_current_process_agent_env: bool = False,
    ) -> ProxyServer:
        resolved_events_path = Path(events_path)
        state_dir = resolved_events_path.parent
        lock = acquire_session_lock(state_dir)
        try:
            check_secret_isolation(
                agent_pid=agent_pid,
                inspect_current_process=inspect_current_process_agent_env,
            )
            previous_session_id, previous_chain_hash = _prepare_events_file(
                resolved_events_path,
                session_id,
            )
            contract = load_contract(contract_path)
            budget_tracker = load_budget_state(state_dir, session_id)
            if budget_tracker is None:
                budget_tracker = BudgetTracker.from_contract(contract)
            decay_detector = DecayDetector.from_contract(
                contract,
                datetime.now(timezone.utc),
            )
            keypair = load_or_create_keypair()
            store = EventStore(resolved_events_path)
            logger = EventLogger(
                store=store,
                session_id=session_id,
                contract_id=contract.contract_id,
                contract_hash=compute_contract_hash(contract),
                signing_key=keypair,
                state_dir=state_dir,
                prev_chain_terminal_hash=previous_chain_hash,
                prev_session_id=previous_session_id,
            )
            return cls(
                contract=contract,
                event_logger=logger,
                session_id=session_id,
                passthrough=passthrough,
                interactive=interactive,
                allow_read_fail_open=allow_read_fail_open,
                requesting_agent_id=requesting_agent_id,
                requesting_code_sha256=requesting_code_sha256,
                session_lock=lock,
                state_dir=state_dir,
                budget_tracker=budget_tracker,
                decay_detector=decay_detector,
            )
        except Exception:
            release_session_lock(lock)
            raise

    def _on_circuit_state_change(self, reason: str) -> None:
        self.health.set_circuit_open(reason == "circuit_breaker_open")
        decision = "deny" if reason == "circuit_breaker_open" else "allow"
        try:
            event = self.event_logger.log_event(
                {
                    "event_type": "elev_op",
                    "tool_name": "__proxy__",
                    "risk_class": "write",
                    "decision": decision,
                    "reason": reason,
                    "agent_identity": self._agent_identity_hash,
                    "input_hash": hashlib.sha256(canonical_json_bytes({"reason": reason})).hexdigest(),
                }
            )
            self.health.update_last_event_timestamp(event.timestamp)
        except Exception as exc:
            # Health/circuit transitions should not crash request handling.
            _LOGGER.debug("Failed to log circuit state change event", exc_info=exc)

    def _log_decision(
        self,
        *,
        event_type: str,
        tool_name: str,
        risk_class: str,
        decision: str,
        reason: str,
        input_hash: str,
    ) -> None:
        event = self.event_logger.log_event(
            {
                "event_type": event_type,
                "tool_name": tool_name,
                "risk_class": _risk_to_wire(risk_class),
                "decision": decision,
                "reason": reason,
                "agent_identity": self._agent_identity_hash,
                "input_hash": input_hash,
            }
        )
        self.health.update_last_event_timestamp(event.timestamp)

    def _approval_prompt(self, tool_name: str) -> bool:
        reply = input(f"Approve tool '{tool_name}'? [y/N]: ").strip().lower()
        return reply in {"y", "yes"}

    def _save_budget_state(self) -> None:
        if self.budget_tracker is None:
            return
        save_budget_state(
            Path(self.state_dir or self.event_logger.store.path.parent),
            self.budget_tracker,
            self.session_id,
        )

    def _emit_budget_exhausted_event(self, *, input_hash: str) -> None:
        if self.budget_tracker is None:
            return
        event = self.event_logger.log_event(
            {
                "event_type": "budget_exhausted",
                "tool_name": "__budget__",
                "risk_class": "write",
                "decision": "deny",
                "reason": "budget_exhausted",
                "agent_identity": self._agent_identity_hash,
                "input_hash": input_hash,
                "metadata": {
                    "max_tool_calls": self.budget_tracker.max_tool_calls,
                    "max_net_calls": self.budget_tracker.max_net_calls,
                    "tool_calls_used": self.budget_tracker.tool_calls_used,
                    "net_calls_used": self.budget_tracker.net_calls_used,
                    "exhausted_dimension": self.budget_tracker.exhausted_dimension,
                    "exhausted_at": self.budget_tracker.exhausted_at,
                },
            }
        )
        self.health.update_last_event_timestamp(event.timestamp)

    def _emit_budget_anomaly_event(self, *, anomaly: DecayAnomaly, input_hash: str) -> None:
        event = self.event_logger.log_event(
            {
                "event_type": "budget_anomaly",
                "tool_name": "__budget__",
                "risk_class": "write",
                "decision": "allow",
                "reason": "budget_anomaly",
                "agent_identity": self._agent_identity_hash,
                "input_hash": input_hash,
                "metadata": {
                    "dimension": anomaly.dimension,
                    "spend_fraction": anomaly.spend_fraction,
                    "time_fraction": anomaly.time_fraction,
                    "burn_rate": anomaly.burn_rate,
                    "projected_exhaustion_seconds": anomaly.projected_exhaustion_seconds,
                },
            }
        )
        self.health.update_last_event_timestamp(event.timestamp)

    def _intercept_request(self, raw_request: Mapping[str, Any]) -> dict[str, Any]:
        egress_target = _extract_egress_target(raw_request)
        current_time = _now_iso_utc()
        state = {
            "tool_calls_made": self._tool_calls_made,
            "net_calls_made": self._net_calls_made,
            "current_time": current_time,
            "requesting_agent_id": self._agent_id,
            "requesting_code_sha256": self.requesting_code_sha256,
            "egress_target": egress_target,
        }
        return {**dict(raw_request), "state": state}

    def _emit_override_event(
        self,
        *,
        tool_name: str,
        risk_class: str,
        reason: str,
        input_hash: str,
        metadata: dict[str, Any],
    ) -> None:
        event = self.event_logger.log_event(
            {
                "event_type": "elev_op",
                "tool_name": tool_name,
                "risk_class": risk_class,
                "decision": "allow",
                "reason": reason,
                "agent_identity": self._agent_identity_hash,
                "input_hash": input_hash,
                "metadata": metadata,
            }
        )
        self.health.update_last_event_timestamp(event.timestamp)

    def _forward_allowed_tool_call(
        self,
        raw_request: Mapping[str, Any],
        forward_call: Callable[[Mapping[str, Any]], Any],
        *,
        tool_name: str,
        risk_class: str,
        reason: str,
        input_hash: str,
        egress_target: str | None,
        override_metadata: dict[str, Any] | None = None,
    ) -> Any:
        if override_metadata is not None:
            self._emit_override_event(
                tool_name=tool_name,
                risk_class=risk_class,
                reason=reason,
                input_hash=input_hash,
                metadata=override_metadata,
            )
        token = mint_token(
            tool_name=tool_name,
            scope="tool.execute",
            ttl=60,
            session_id=self.session_id,
            contract_id=self.contract.contract_id,
        )
        forwarded_request = _merge_headers(raw_request, token)
        response = forward_call(forwarded_request)
        self._log_decision(
            event_type="tool_call",
            tool_name=tool_name,
            risk_class=risk_class,
            decision="allow",
            reason=reason,
            input_hash=input_hash,
        )
        self._tool_calls_made += 1
        if egress_target is not None:
            self._net_calls_made += 1
        return response

    def handle_tool_call(
        self,
        raw_request: Mapping[str, Any],
        forward_call: Callable[[Mapping[str, Any]], Any],
    ) -> Any:
        """Evaluate, enforce, log, and forward a tool call."""
        tool_name = _safe_tool_name(raw_request)
        input_hash = _input_hash(raw_request)
        egress_target = _extract_egress_target(raw_request)

        if self.passthrough:
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class="write",
                decision="allow",
                reason="passthrough",
                input_hash=input_hash,
            )
            response = forward_call(raw_request)
            self._tool_calls_made += 1
            if egress_target is not None:
                self._net_calls_made += 1
            return response

        if self.budget_tracker is None or self.decay_detector is None:
            _LOGGER.error("Budget monitor is not initialized; denying call")
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class="write",
                decision="deny",
                reason="proxy_degraded",
                input_hash=input_hash,
            )
            return _structured_error("proxy_degraded", tool_name)

        budget_checks = [self.budget_tracker.check_and_decrement("tool")]
        if egress_target is not None:
            budget_checks.append(self.budget_tracker.check_and_decrement("net"))

        for budget_result in budget_checks:
            if budget_result.allowed:
                continue
            if budget_result.first_exhaustion:
                self._emit_budget_exhausted_event(input_hash=input_hash)
                self._save_budget_state()
            self._log_decision(
                event_type="net_call"
                if budget_result.dimension == "net_calls"
                else "tool_call",
                tool_name=tool_name,
                risk_class="write",
                decision="deny",
                reason="budget_exhausted",
                input_hash=input_hash,
            )
            return _structured_error("budget_exhausted", tool_name)

        anomaly = self.decay_detector.check(self.budget_tracker)
        if anomaly is not None:
            self._emit_budget_anomaly_event(anomaly=anomaly, input_hash=input_hash)

        self._save_budget_state()

        risk_hint = self.contract.tool_risk_classes.get(tool_name)
        risk_hint_wire = _risk_to_wire(risk_hint.value if risk_hint else "write")

        current_time = datetime.now(timezone.utc)
        if self.active_breakglass is not None:
            breakglass_manager = BreakGlassManager(self.contract)
            if breakglass_manager.check_tool_against_breakglass(
                self.active_breakglass,
                tool_name,
                current_time,
            ):
                return self._forward_allowed_tool_call(
                    raw_request,
                    forward_call,
                    tool_name=tool_name,
                    risk_class=risk_hint_wire,
                    reason="breakglass_active",
                    input_hash=input_hash,
                    egress_target=egress_target,
                    override_metadata={
                        "override_type": "breakglass",
                        "breakglass_id": self.active_breakglass.breakglass_id,
                        "triggered_by": self.active_breakglass.triggered_by,
                        "triggered_at": self.active_breakglass.triggered_at,
                        "expires_at": self.active_breakglass.expires_at,
                        "scope": self.active_breakglass.scope,
                    },
                )

        if self.active_permits:
            permit_secret = self._permit_secret
            if permit_secret is None:
                raise RuntimeError("permit secret not initialized")
            permit_manager = PermitManager(
                contract=self.contract,
                secret=permit_secret,
                session_id=self.session_id,
            )
            for permit in self.active_permits:
                validation = permit_manager.validate_permit(
                    permit,
                    current_time=current_time,
                    contract_id=self.contract.contract_id,
                    contract_hash=self._contract_hash,
                    session_id=self.session_id,
                )
                if not validation.valid:
                    _LOGGER.warning(
                        "Active permit %s rejected during evaluation: %s",
                        permit.permit_id,
                        validation.reason,
                    )
                    continue
                if tool_name in self.contract.never_allow_tools:
                    continue
                if tool_name not in permit.granted_tools:
                    continue
                if egress_target is not None:
                    if not permit.granted_destinations or egress_target not in permit.granted_destinations:
                        continue
                return self._forward_allowed_tool_call(
                    raw_request,
                    forward_call,
                    tool_name=tool_name,
                    risk_class=risk_hint_wire,
                    reason="exception_permit_active",
                    input_hash=input_hash,
                    egress_target=egress_target,
                    override_metadata={
                        "override_type": "permit",
                        "permit_id": permit.permit_id,
                        "request_id": permit.request_id,
                        "approved_by": permit.approved_by,
                        "approved_at": permit.approved_at,
                        "expires_at": permit.expires_at,
                    },
                )

        intercepted = self.circuit_breaker.call(
            lambda: intercept(self._intercept_request(raw_request), self.contract),
            risk_class=risk_hint_wire,
        )

        if isinstance(intercepted, dict) and intercepted.get("reason") == "proxy_degraded":
            self.health.set_degraded(True)
            decision = str(intercepted["decision"])
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                decision=decision,
                reason="proxy_degraded",
                input_hash=input_hash,
            )
            if decision == "deny":
                return _structured_error("proxy_degraded", tool_name)

            return self._forward_allowed_tool_call(
                raw_request,
                forward_call,
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                reason="proxy_degraded",
                input_hash=input_hash,
                egress_target=egress_target,
            )

        result = intercepted
        if not isinstance(result, InterceptResult):
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                decision="deny",
                reason="proxy_degraded",
                input_hash=input_hash,
            )
            return _structured_error("proxy_degraded", tool_name)

        if result.decision == "deny":
            event_type = "net_call" if result.reason == "not_in_egress_allowlist" else "tool_call"
            self._log_decision(
                event_type=event_type,
                tool_name=result.tool_name,
                risk_class=result.risk_class,
                decision="deny",
                reason=result.reason,
                input_hash=result.input_hash,
            )
            return _structured_error(result.reason, result.tool_name)

        if result.decision == "require_approval":
            if not self.interactive or not self._approval_prompt(result.tool_name):
                self._log_decision(
                    event_type="tool_call",
                    tool_name=result.tool_name,
                    risk_class=result.risk_class,
                    decision="deny",
                    reason="approval_required",
                    input_hash=result.input_hash,
                )
                return _structured_error("approval_required", result.tool_name)

        if egress_target is not None:
            egress_allowed, egress_reason = check_egress(egress_target, self.contract)
            if not egress_allowed:
                self._log_decision(
                    event_type="net_call",
                    tool_name=result.tool_name,
                    risk_class=result.risk_class,
                    decision="deny",
                    reason=egress_reason,
                    input_hash=result.input_hash,
                )
                return _structured_error(egress_reason, result.tool_name)

        return self._forward_allowed_tool_call(
            raw_request,
            forward_call,
            tool_name=result.tool_name,
            risk_class=result.risk_class,
            reason=result.reason,
            input_hash=result.input_hash,
            egress_target=egress_target,
        )


def load_contract(contract_path: str | Path) -> Contract:
    """Load and validate a contract file once at startup."""
    path = Path(contract_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    return Contract.from_dict(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stipul MCP Proxy")
    parser.add_argument("--contract", required=True, help="Path to contract JSON")
    parser.add_argument("--passthrough", action="store_true", help="Disable enforcement")
    parser.add_argument("--interactive", action="store_true", help="Enable approval prompts")
    parser.add_argument(
        "--agent-pid",
        type=int,
        help="PID of agent runtime process for environment isolation checks",
    )
    parser.add_argument(
        "--inspect-current-process-agent-env",
        action="store_true",
        help="Inspect current process env when proxy and agent run in-process",
    )
    return parser


def main(argv: list[str] | None = None) -> ProxyServer:
    parser = build_parser()
    args = parser.parse_args(argv)

    return ProxyServer.from_contract_path(
        args.contract,
        session_id="session-1",
        passthrough=args.passthrough,
        interactive=args.interactive,
        agent_pid=args.agent_pid,
        inspect_current_process_agent_env=args.inspect_current_process_agent_env,
    )


if __name__ == "__main__":
    main()
