"""MCP Proxy server orchestration."""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

from stipul.charter.budget import (
    BudgetTracker,
    DecayAnomaly,
    DecayDetector,
    load_budget_state,
    save_budget_state,
)
from stipul.charter.delegation import (
    DEFAULT_MAX_DELEGATION_CHAIN_DEPTH,
    DelegationManager,
)
from stipul.charter.contract.loader import load_charter
from stipul.writ.breakglass import BreakGlassEvent, BreakGlassManager
from stipul.charter.contract.schema import Contract
from stipul.charter.contract.utils import compute_contract_hash
from stipul.writ.detection.bypass import BypassDetector
from stipul.chronicle.events.logger import EventLogger
from stipul.chronicle.events.store import EventStore
from stipul.chronicle.events.summary import SessionSummary
from stipul.health.endpoint import HealthEndpoint
from stipul.charter.permits import ExceptionPermit, PermitManager, load_permit_secret
from stipul.writ.proxy.approval_state import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalState,
    ApprovalStateError,
    load_approval_state,
    save_approval_state,
)
from stipul.writ.proxy.circuit_breaker import CircuitBreaker
from stipul.writ.proxy.egress import check_egress
from stipul.writ.proxy.interceptor import InterceptResult, intercept
from stipul.writ.proxy.operator_state import OperatorState, OperatorStateError
from stipul.writ.proxy.operator_state import load_operator_state, save_operator_state
from stipul.writ.proxy.session import SessionState
from stipul.writ.proxy.session_lock import FileLock, acquire_session_lock, release_session_lock
from stipul.writ.proxy.startup import check_secret_isolation
from stipul.chronicle.signing.keys import load_or_create_keypair
from stipul.charter.token.mint import mint_token
from stipul.utils.canonical import canonical_json_bytes, compute_prev_hash

_LOGGER = logging.getLogger(__name__)
_NO_OVERRIDE = object()
_APPROVAL_REQUEST_TTL_SECONDS = 300

if TYPE_CHECKING:
    from stipul.writ.proxy.control_sidecar import ControlSidecar
    from stipul.writ.proxy.mcp_gateway import MCPGateway


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


def _request_metadata(raw_request: Mapping[str, Any]) -> dict[str, Any] | None:
    metadata = raw_request.get("metadata")
    if not isinstance(metadata, dict):
        return None
    return dict(metadata)


def _merge_metadata(
    base: dict[str, Any] | None,
    extra: dict[str, Any] | None,
) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if base is not None:
        merged.update(base)
    if extra is not None:
        merged.update(extra)
    return merged or None


def _agent_identity_hash(agent_id: str, code_sha256: str | None) -> str:
    payload = {"agent_id": agent_id, "code_sha256": code_sha256}
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _requester_hex64(agent_id: str) -> str:
    return hashlib.sha256(agent_id.encode("utf-8")).hexdigest()


def _approval_request_id(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(payload))).hexdigest()


def _approval_context(request: ApprovalRequest) -> dict[str, Any]:
    context: dict[str, Any] = {
        "request_id": request.request_id,
        "status": request.status,
        "required_approver_count": request.required_approver_count,
        "approval_count": len(request.approvals),
        "approver_ids": [approval.approved_by for approval in request.approvals],
        "tool_name": request.tool_name,
        "input_hash": request.input_hash,
        "expires_at": request.expires_at,
    }
    if request.egress_target is not None:
        context["egress_target"] = request.egress_target
    if request.derived_permit is not None:
        permit_id = request.derived_permit.get("permit_id")
        if isinstance(permit_id, str) and permit_id:
            context["derived_permit_id"] = permit_id
    return {"approval_context": context}


def _permit_to_dict(permit: ExceptionPermit) -> dict[str, Any]:
    return {
        "permit_id": permit.permit_id,
        "request_id": permit.request_id,
        "approved_by": permit.approved_by,
        "approved_at": permit.approved_at,
        "contract_id": permit.contract_id,
        "contract_hash": permit.contract_hash,
        "session_id": permit.session_id,
        "granted_tools": list(permit.granted_tools),
        "granted_destinations": list(permit.granted_destinations),
        "granted_ttl": permit.granted_ttl,
        "expires_at": permit.expires_at,
        "signature": permit.signature,
    }


def _permit_from_dict(payload: Mapping[str, Any] | None) -> ExceptionPermit | None:
    if not isinstance(payload, Mapping):
        return None
    try:
        return ExceptionPermit(
            permit_id=str(payload["permit_id"]),
            request_id=str(payload["request_id"]),
            approved_by=str(payload["approved_by"]),
            approved_at=str(payload["approved_at"]),
            contract_id=str(payload["contract_id"]),
            contract_hash=str(payload["contract_hash"]),
            session_id=str(payload["session_id"]),
            granted_tools=tuple(str(item) for item in payload["granted_tools"]),
            granted_destinations=tuple(str(item) for item in payload["granted_destinations"]),
            granted_ttl=int(payload["granted_ttl"]),
            expires_at=str(payload["expires_at"]),
            signature=str(payload["signature"]),
        )
    except Exception:
        return None


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
    max_delegation_chain_depth: int = DEFAULT_MAX_DELEGATION_CHAIN_DEPTH
    _control_sidecar: ControlSidecar | None = field(default=None, init=False, repr=False)

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

        self._refresh_operator_state()
        if self.max_delegation_chain_depth <= 0:
            raise ValueError("max_delegation_chain_depth must be > 0")

        if self.passthrough:
            print("⚠ PASSTHROUGH MODE — enforcement disabled")

    def close(self) -> None:
        self.stop_control_sidecar()
        if self.session_lock is None:
            return
        release_session_lock(self.session_lock)
        self.session_lock = None

    def start_control_sidecar(self, *, port: int = 0) -> str:
        if self._control_sidecar is None:
            from stipul.writ.proxy.control_sidecar import ControlSidecar

            self._control_sidecar = ControlSidecar(self)
        return self._control_sidecar.start(port=port)

    def stop_control_sidecar(self) -> None:
        if self._control_sidecar is None:
            return
        self._control_sidecar.stop()
        self._control_sidecar = None

    def create_mcp_gateway(
        self,
        *,
        tool_catalog: Callable[[], list[Any]] | list[Any],
        execute_tool: Callable[[Mapping[str, Any]], Any],
    ) -> MCPGateway:
        from stipul.writ.proxy.mcp_gateway import MCPGateway

        return MCPGateway(
            proxy=self,
            tool_catalog=tool_catalog,
            execute_tool=execute_tool,
        )

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
                self._log_decision(
                    event_type=str(gap_payload["event_type"]),
                    tool_name=str(gap_payload["tool_name"]),
                    risk_class=str(gap_payload["risk_class"]),
                    decision=str(gap_payload["decision"]),
                    reason=str(gap_payload["reason"]),
                    input_hash=hashlib.sha256(
                        canonical_json_bytes(gap_hash_payload)
                    ).hexdigest(),
                    metadata=gap_payload.get("metadata"),
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
            self._log_decision(
                event_type="elev_op",
                tool_name="__proxy__",
                risk_class="write",
                decision=decision,
                reason=reason,
                input_hash=hashlib.sha256(
                    canonical_json_bytes({"reason": reason})
                ).hexdigest(),
            )
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
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = self.event_logger.log_decision_event(
            event_type=event_type,
            tool_name=tool_name,
            risk_class=_risk_to_wire(risk_class),
            decision=decision,
            reason=reason,
            agent_identity=self._agent_identity_hash,
            input_hash=input_hash,
            metadata=metadata,
        )
        self.health.update_last_event_timestamp(event.timestamp)

    def _approval_prompt(self, tool_name: str) -> bool:
        reply = input(f"Approve tool '{tool_name}'? [y/N]: ").strip().lower()
        return reply in {"y", "yes"}

    def _approval_state_dir(self) -> Path:
        return Path(self.state_dir or self.event_logger.store.path.parent)

    def _permit_manager(self) -> PermitManager:
        if self._permit_secret is None:
            self._permit_secret = load_permit_secret()
        return PermitManager(
            contract=self.contract,
            secret=self._permit_secret,
            session_id=self.session_id,
        )

    def _approval_request_ttl(self, current_time: datetime) -> int:
        remaining = int((self.contract.expires_at - current_time).total_seconds())
        if remaining <= 0:
            return 0
        return min(_APPROVAL_REQUEST_TTL_SECONDS, remaining)

    def _approval_binding(
        self,
        *,
        tool_name: str,
        input_hash: str,
        egress_target: str | None,
        requesting_agent_id: str,
    ) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "input_hash": input_hash,
            "egress_target": egress_target,
            "requesting_agent_id": requesting_agent_id,
            "session_id": self.session_id,
            "contract_id": self.contract.contract_id,
            "contract_hash": self._contract_hash,
        }

    def _approval_request_summary(self, request: ApprovalRequest) -> dict[str, Any]:
        return {
            "request_id": request.request_id,
            "status": request.status,
            "tool_name": request.tool_name,
            "input_hash": request.input_hash,
            "egress_target": request.egress_target,
            "requesting_agent_id": request.requesting_agent_id,
            "required_approver_count": request.required_approver_count,
            "approval_count": len(request.approvals),
            "approver_ids": [approval.approved_by for approval in request.approvals],
            "expires_at": request.expires_at,
            "derived_permit_id": (
                request.derived_permit.get("permit_id")
                if request.derived_permit is not None
                else None
            ),
        }

    def _log_approval_lifecycle_event(self, reason: str, request: ApprovalRequest) -> None:
        payload = {
            "reason": reason,
            "request_id": request.request_id,
            "approval_count": len(request.approvals),
            "status": request.status,
        }
        self._log_decision(
            event_type="elev_op",
            tool_name=request.tool_name,
            risk_class="write",
            decision="allow",
            reason=reason,
            input_hash=hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
            metadata=_approval_context(request),
        )

    def _expire_approval_requests(
        self,
        state: ApprovalState,
        *,
        current_time: datetime,
    ) -> tuple[ApprovalState, list[ApprovalRequest]]:
        expired: list[ApprovalRequest] = []
        updated_requests = dict(state.requests)
        for request_id, request in state.requests.items():
            if request.status == "expired":
                continue
            expires_at = datetime.fromisoformat(request.expires_at[:-1] + "+00:00")
            if current_time < expires_at:
                continue
            expired_request = replace(
                request,
                status="expired",
                derived_permit=None,
            )
            updated_requests[request_id] = expired_request
            expired.append(expired_request)
        if not expired:
            return state, []
        return ApprovalState(requests=updated_requests), expired

    def _load_approval_state(self, *, current_time: datetime) -> ApprovalState:
        state = load_approval_state(self._approval_state_dir())
        state, expired_requests = self._expire_approval_requests(state, current_time=current_time)
        if expired_requests:
            save_approval_state(self._approval_state_dir(), state)
            for request in expired_requests:
                self._log_approval_lifecycle_event("approval_request_expired", request)
        return state

    def _save_approval_state(self, state: ApprovalState) -> ApprovalState:
        return save_approval_state(self._approval_state_dir(), state)

    def _create_pending_approval_request(
        self,
        *,
        tool_name: str,
        input_hash: str,
        egress_target: str | None,
        requesting_agent_id: str,
        current_time: datetime,
    ) -> ApprovalRequest:
        ttl = self._approval_request_ttl(current_time)
        if ttl <= 0:
            raise ValueError("contract is already expired at approval request time")
        binding = self._approval_binding(
            tool_name=tool_name,
            input_hash=input_hash,
            egress_target=egress_target,
            requesting_agent_id=requesting_agent_id,
        )
        return ApprovalRequest(
            request_id=_approval_request_id(binding),
            status="pending",
            tool_name=tool_name,
            input_hash=input_hash,
            egress_target=egress_target,
            requesting_agent_id=requesting_agent_id,
            session_id=self.session_id,
            contract_id=self.contract.contract_id,
            contract_hash=self._contract_hash,
            required_approver_count=self.contract.approval_quorum,
            approvals=(),
            expires_at=(current_time.replace(microsecond=0) + timedelta(seconds=ttl))
            .isoformat()
            .replace("+00:00", "Z"),
            derived_permit=None,
        )

    def _ensure_approval_request(
        self,
        *,
        tool_name: str,
        input_hash: str,
        egress_target: str | None,
        requesting_agent_id: str,
        current_time: datetime,
    ) -> ApprovalRequest:
        state = self._load_approval_state(current_time=current_time)
        request = self._create_pending_approval_request(
            tool_name=tool_name,
            input_hash=input_hash,
            egress_target=egress_target,
            requesting_agent_id=requesting_agent_id,
            current_time=current_time,
        )
        existing = state.requests.get(request.request_id)
        if existing is not None and existing.status != "expired":
            return existing
        updated_state = ApprovalState(
            requests={**state.requests, request.request_id: request},
        )
        self._save_approval_state(updated_state)
        self._log_approval_lifecycle_event("approval_request_created", request)
        return request

    def approval_status(self, request_id: str | None = None) -> dict[str, Any]:
        state = self._load_approval_state(current_time=datetime.now(timezone.utc))
        if request_id is not None:
            request = state.requests.get(request_id)
            if request is None:
                raise ValueError(f"approval request not found: {request_id}")
            requests = [request]
        else:
            requests = [state.requests[key] for key in sorted(state.requests)]
        return {
            "request_count": len(requests),
            "requests": [self._approval_request_summary(request) for request in requests],
        }

    def approve_approval_request(self, request_id: str, approved_by: str) -> dict[str, Any]:
        if (
            not isinstance(approved_by, str)
            or len(approved_by) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in approved_by)
        ):
            raise ValueError("approved_by must be a 64-character hexadecimal string")
        current_time = datetime.now(timezone.utc)
        state = self._load_approval_state(current_time=current_time)
        request = state.requests.get(request_id)
        if request is None:
            raise ValueError(f"approval request not found: {request_id}")
        if request.status == "expired":
            raise ValueError("approval request expired")

        updated_request = request
        if all(approval.approved_by != approved_by for approval in request.approvals):
            updated_request = replace(
                request,
                approvals=request.approvals
                + (
                    ApprovalRecord(
                        approved_by=approved_by,
                        approved_at=current_time.isoformat().replace("+00:00", "Z"),
                    ),
                ),
            )

        if (
            len(updated_request.approvals) >= updated_request.required_approver_count
            and updated_request.derived_permit is None
        ):
            permit_manager = self._permit_manager()
            remaining_ttl = int(
                (
                    datetime.fromisoformat(updated_request.expires_at[:-1] + "+00:00")
                    - current_time
                ).total_seconds()
            )
            if remaining_ttl <= 0:
                updated_request = replace(updated_request, status="expired", derived_permit=None)
            else:
                requester_hex64 = _requester_hex64(updated_request.requesting_agent_id)
                permit_request = permit_manager.create_request(
                    requested_by_hex64=requester_hex64,
                    permitted_tools=[updated_request.tool_name],
                    permitted_destinations=(
                        [updated_request.egress_target]
                        if updated_request.egress_target is not None
                        else []
                    ),
                    reason="Approval quorum satisfied",
                    requested_ttl=remaining_ttl,
                    session_id=self.session_id,
                    requested_at=current_time,
                )
                permit = permit_manager.approve_request(
                    permit_request,
                    approved_by_hex64=approved_by,
                    granted_ttl=remaining_ttl,
                    approved_at=current_time,
                )
                updated_request = replace(
                    updated_request,
                    status="approved",
                    derived_permit=_permit_to_dict(permit),
                )

        updated_state = ApprovalState(
            requests={**state.requests, request_id: updated_request},
        )
        self._save_approval_state(updated_state)
        if updated_request.status == "expired" and request.status != "expired":
            self._log_approval_lifecycle_event("approval_request_expired", updated_request)
        elif len(updated_request.approvals) > len(request.approvals):
            self._log_approval_lifecycle_event("approval_added", updated_request)
        return self._approval_request_summary(updated_request)

    def _operator_state_dir(self) -> Path:
        return Path(self.state_dir or self.event_logger.store.path.parent)

    def _refresh_operator_state(self) -> OperatorState | None:
        state = load_operator_state(self._operator_state_dir())
        if state is None:
            self.health.update_operator_status(
                kill_switch_active=False,
                updated_at=None,
                updated_by=None,
                reason=None,
            )
            return None

        self.health.update_operator_status(
            kill_switch_active=state.kill_switch_active,
            updated_at=state.updated_at,
            updated_by=state.updated_by,
            reason=state.reason,
        )
        return state

    def set_kill_switch(self, active: bool, updated_by: str, reason: str) -> None:
        state = save_operator_state(
            self._operator_state_dir(),
            kill_switch_active=active,
            updated_by=updated_by,
            reason=reason,
        )
        self.health.update_operator_status(
            kill_switch_active=state.kill_switch_active,
            updated_at=state.updated_at,
            updated_by=state.updated_by,
            reason=state.reason,
        )
        payload = state.to_dict()
        self._log_decision(
            event_type="elev_op",
            tool_name="__operator__",
            risk_class="write",
            decision="allow",
            reason=reason,
            input_hash=hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
            metadata=payload,
        )

    def _save_budget_state(self) -> None:
        if self.budget_tracker is None:
            return
        save_budget_state(
            Path(self.state_dir or self.event_logger.store.path.parent),
            self.budget_tracker,
            self.session_id,
        )

    def _emit_budget_exhausted_event(
        self,
        *,
        input_hash: str,
        request_metadata: dict[str, Any] | None = None,
    ) -> None:
        if self.budget_tracker is None:
            return
        self._log_decision(
            event_type="budget_exhausted",
            tool_name="__budget__",
            risk_class="write",
            decision="deny",
            reason="budget_exhausted",
            input_hash=input_hash,
            metadata=_merge_metadata(request_metadata, {
                "max_tool_calls": self.budget_tracker.max_tool_calls,
                "max_net_calls": self.budget_tracker.max_net_calls,
                "tool_calls_used": self.budget_tracker.tool_calls_used,
                "net_calls_used": self.budget_tracker.net_calls_used,
                "exhausted_dimension": self.budget_tracker.exhausted_dimension,
                "exhausted_at": self.budget_tracker.exhausted_at,
            }),
        )

    def _emit_budget_anomaly_event(
        self,
        *,
        anomaly: DecayAnomaly,
        input_hash: str,
        request_metadata: dict[str, Any] | None = None,
    ) -> None:
        metadata = {
            "dimension": anomaly.dimension,
            "spend_fraction": anomaly.spend_fraction,
            "time_fraction": anomaly.time_fraction,
            "burn_rate": anomaly.burn_rate,
            "projected_exhaustion_seconds": anomaly.projected_exhaustion_seconds,
        }
        if self.decay_detector is not None:
            metadata.update(self.decay_detector.to_event_payload(anomaly))

        self._log_decision(
            event_type="budget_anomaly",
            tool_name="__budget__",
            risk_class="write",
            decision="allow",
            reason="budget_anomaly",
            input_hash=input_hash,
            metadata=_merge_metadata(request_metadata, metadata),
        )

    def _intercept_request(
        self,
        raw_request: Mapping[str, Any],
        *,
        requesting_agent_id: str | None = None,
    ) -> dict[str, Any]:
        egress_target = _extract_egress_target(raw_request)
        current_time = _now_iso_utc()
        state = {
            "tool_calls_made": self._tool_calls_made,
            "net_calls_made": self._net_calls_made,
            "current_time": current_time,
            "requesting_agent_id": requesting_agent_id or self._agent_id,
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
        self._log_decision(
            event_type="elev_op",
            tool_name=tool_name,
            risk_class=risk_class,
            decision="allow",
            reason=reason,
            input_hash=input_hash,
            metadata=metadata,
        )

    def _try_forward_with_permit(
        self,
        permit: ExceptionPermit,
        raw_request: Mapping[str, Any],
        forward_call: Callable[[Mapping[str, Any]], Any],
        *,
        tool_name: str,
        risk_class: str,
        reason: str,
        input_hash: str,
        egress_target: str | None,
        request_metadata: dict[str, Any] | None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> Any:
        permit_manager = self._permit_manager()
        validation = permit_manager.validate_permit(
            permit,
            current_time=datetime.now(timezone.utc),
            contract_id=self.contract.contract_id,
            contract_hash=self._contract_hash,
            session_id=self.session_id,
        )
        if not validation.valid:
            _LOGGER.warning(
                "Permit %s rejected during evaluation: %s",
                permit.permit_id,
                validation.reason,
            )
            return _NO_OVERRIDE
        if tool_name in self.contract.never_allow_tools:
            return _NO_OVERRIDE
        if tool_name not in permit.granted_tools:
            return _NO_OVERRIDE
        if egress_target is not None:
            if not permit.granted_destinations or egress_target not in permit.granted_destinations:
                return _NO_OVERRIDE

        override_metadata = {
            "override_type": "permit",
            "permit_id": permit.permit_id,
            "request_id": permit.request_id,
            "approved_by": permit.approved_by,
            "approved_at": permit.approved_at,
            "expires_at": permit.expires_at,
        }
        if extra_metadata is not None:
            override_metadata.update(extra_metadata)
        return self._forward_allowed_tool_call(
            raw_request,
            forward_call,
            tool_name=tool_name,
            risk_class=risk_class,
            reason=reason,
            input_hash=input_hash,
            egress_target=egress_target,
            override_metadata=override_metadata,
            request_metadata=request_metadata,
        )

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
        request_metadata: dict[str, Any] | None = None,
    ) -> Any:
        if override_metadata is not None:
            self._emit_override_event(
                tool_name=tool_name,
                risk_class=risk_class,
                reason=reason,
                input_hash=input_hash,
                metadata=_merge_metadata(request_metadata, override_metadata),
            )
        token = mint_token(
            tool_name=tool_name,
            scope="tool.execute",
            ttl=60,
            session_id=self.session_id,
            contract_id=self.contract.contract_id,
        )
        forwarded_request = _merge_headers(raw_request, token)
        self._log_decision(
            event_type="tool_call",
            tool_name=tool_name,
            risk_class=risk_class,
            decision="allow",
            reason=reason,
            input_hash=input_hash,
            metadata=request_metadata,
        )
        self._tool_calls_made += 1
        if egress_target is not None:
            self._net_calls_made += 1
        return forward_call(forwarded_request)

    def handle_tool_call(
        self,
        raw_request: Mapping[str, Any],
        forward_call: Callable[[Mapping[str, Any]], Any],
    ) -> Any:
        """Evaluate, enforce, log, and forward a tool call."""
        tool_name = _safe_tool_name(raw_request)
        input_hash = _input_hash(raw_request)
        egress_target = _extract_egress_target(raw_request)
        risk_hint = self.contract.tool_risk_classes.get(tool_name)
        risk_hint_wire = _risk_to_wire(risk_hint.value if risk_hint else "write")
        request_metadata = _request_metadata(raw_request)
        effective_requesting_agent_id = self._agent_id

        try:
            operator_state = self._refresh_operator_state()
        except OperatorStateError as exc:
            _LOGGER.error("Operator state is unreadable; denying call", exc_info=exc)
            self.health.set_degraded(True)
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                decision="deny",
                reason="proxy_degraded",
                input_hash=input_hash,
                metadata=request_metadata,
            )
            return _structured_error("proxy_degraded", tool_name)

        if operator_state is not None and operator_state.kill_switch_active:
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                decision="deny",
                reason="kill_switch_active",
                input_hash=input_hash,
                metadata=_merge_metadata(request_metadata, {
                    "kill_switch_active": True,
                    "operator_reason": operator_state.reason,
                    "operator_updated_at": operator_state.updated_at,
                    "operator_updated_by": operator_state.updated_by,
                }),
            )
            return _structured_error("kill_switch_active", tool_name)

        try:
            self._load_approval_state(current_time=datetime.now(timezone.utc))
        except ApprovalStateError as exc:
            _LOGGER.error("Approval state is unreadable; denying call", exc_info=exc)
            self.health.set_degraded(True)
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class=risk_hint_wire,
                decision="deny",
                reason="proxy_degraded",
                input_hash=input_hash,
                metadata=request_metadata,
            )
            return _structured_error("proxy_degraded", tool_name)

        delegation_chain = raw_request.get("delegation_chain")
        if delegation_chain is not None:
            try:
                delegation_manager = DelegationManager.from_env(
                    self.contract,
                    self.session_id,
                    max_chain_depth=self.max_delegation_chain_depth,
                )
                delegation_validation = delegation_manager.validate_chain(
                    delegation_chain,
                    current_time=datetime.now(timezone.utc),
                    contract_id=self.contract.contract_id,
                    contract_hash=self._contract_hash,
                    session_id=self.session_id,
                    expected_delegated_actor=self._agent_id,
                    tool_name=tool_name,
                    egress_target=egress_target,
                )
            except ValueError as exc:
                _LOGGER.error("Delegation validation unavailable; denying call", exc_info=exc)
                delegation_validation = None
                delegation_metadata = {
                    "delegation_context": {
                        "chain_depth": (
                            len(delegation_chain)
                            if isinstance(delegation_chain, (list, tuple))
                            else 0
                        ),
                        "delegated_actor": self._agent_id,
                        "validation_reason": "delegation_unavailable",
                    }
                }
                self._log_decision(
                    event_type="tool_call",
                    tool_name=tool_name,
                    risk_class=risk_hint_wire,
                    decision="deny",
                    reason="delegation_unavailable",
                    input_hash=input_hash,
                    metadata=_merge_metadata(request_metadata, delegation_metadata),
                )
                return _structured_error("delegation_unavailable", tool_name)

            delegation_metadata = delegation_validation.as_metadata()
            request_metadata = _merge_metadata(request_metadata, delegation_metadata)
            if not delegation_validation.valid:
                self._log_decision(
                    event_type="tool_call",
                    tool_name=tool_name,
                    risk_class=risk_hint_wire,
                    decision="deny",
                    reason=delegation_validation.reason,
                    input_hash=input_hash,
                    metadata=request_metadata,
                )
                return _structured_error(delegation_validation.reason, tool_name)

            if delegation_validation.parent_actor is not None:
                effective_requesting_agent_id = delegation_validation.parent_actor

        if self.passthrough:
            self._log_decision(
                event_type="tool_call",
                tool_name=tool_name,
                risk_class="write",
                decision="allow",
                reason="passthrough",
                input_hash=input_hash,
                metadata=request_metadata,
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
                metadata=request_metadata,
            )
            return _structured_error("proxy_degraded", tool_name)

        budget_checks = [self.budget_tracker.check_and_decrement("tool")]
        if egress_target is not None:
            budget_checks.append(self.budget_tracker.check_and_decrement("net"))

        for budget_result in budget_checks:
            if budget_result.allowed:
                continue
            if budget_result.first_exhaustion:
                self._emit_budget_exhausted_event(
                    input_hash=input_hash,
                    request_metadata=request_metadata,
                )
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
                metadata=request_metadata,
            )
            return _structured_error("budget_exhausted", tool_name)

        anomaly = self.decay_detector.check(self.budget_tracker)
        if anomaly is not None:
            self._emit_budget_anomaly_event(
                anomaly=anomaly,
                input_hash=input_hash,
                request_metadata=request_metadata,
            )

        self._save_budget_state()

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
                    request_metadata=request_metadata,
                )

        if self.active_permits:
            for permit in self.active_permits:
                response = self._try_forward_with_permit(
                    permit,
                    raw_request,
                    forward_call,
                    tool_name=tool_name,
                    risk_class=risk_hint_wire,
                    reason="exception_permit_active",
                    input_hash=input_hash,
                    egress_target=egress_target,
                    request_metadata=request_metadata,
                )
                if response is not _NO_OVERRIDE:
                    return response

        intercepted = self.circuit_breaker.call(
            lambda: intercept(
                self._intercept_request(
                    raw_request,
                    requesting_agent_id=effective_requesting_agent_id,
                ),
                self.contract,
            ),
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
                metadata=request_metadata,
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
                request_metadata=request_metadata,
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
                metadata=request_metadata,
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
                metadata=request_metadata,
            )
            return _structured_error(result.reason, result.tool_name)

        if result.decision == "require_approval":
            approval_request = self._ensure_approval_request(
                tool_name=result.tool_name,
                input_hash=result.input_hash,
                egress_target=egress_target,
                requesting_agent_id=effective_requesting_agent_id,
                current_time=current_time,
            )
            approval_metadata = _merge_metadata(
                request_metadata,
                _approval_context(approval_request),
            )

            if approval_request.status == "approved" and approval_request.derived_permit is not None:
                permit = _permit_from_dict(approval_request.derived_permit)
                if permit is not None:
                    response = self._try_forward_with_permit(
                        permit,
                        raw_request,
                        forward_call,
                        tool_name=result.tool_name,
                        risk_class=result.risk_class,
                        reason="approval_quorum_active",
                        input_hash=result.input_hash,
                        egress_target=egress_target,
                        request_metadata=approval_metadata,
                        extra_metadata=_approval_context(approval_request),
                    )
                    if response is not _NO_OVERRIDE:
                        return response

            self._log_decision(
                event_type="tool_call",
                tool_name=result.tool_name,
                risk_class=result.risk_class,
                decision="deny",
                reason="approval_required",
                input_hash=result.input_hash,
                metadata=approval_metadata,
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
                    metadata=request_metadata,
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
            request_metadata=request_metadata,
        )


def load_contract(contract_path: str | Path) -> Contract:
    """Load and validate a contract file once at startup."""
    return load_charter(contract_path).contract


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stipul MCP Proxy")
    parser.add_argument("--contract", required=True, help="Path to Charter policy file")
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
