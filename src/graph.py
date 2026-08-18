"""LangGraph assembly: supervisor pattern with checkpointing and HITL interrupts.

Topology::

            START
              |
              v
        +------------+
        | supervisor | <---------------------+
        +------------+                       |
              |  (conditional, deterministic)|
    +---------+---------+---------+          |
    v         v         v         v          |
  triage  enrichment  human_    reporter -----+
                     approval
              |
              v
             END

Every specialist returns to the supervisor rather than calling the next one
directly.  That is what makes the run controllable: there is exactly one place
where "what happens next" is decided, and it is a deterministic function of
validated state.

The human-approval node uses LangGraph's ``interrupt()``.  The graph genuinely
stops -- the process can exit, the container can restart, and the run resumes
from the SQLite checkpoint when a human answers.  The approval is not a prompt
the model can talk its way past; it is a suspended execution that cannot
continue without an external decision.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from src.agents.base import AgentContext
from src.agents.enrichment import run_enrichment
from src.agents.reporter import run_reporter
from src.agents.supervisor import Route, run_supervisor
from src.agents.triage import run_triage
from src.enums import AgentRole, ApprovalStatus, AuditAction
from src.security.audit import AuditLogger, get_audit_logger
from src.security.policy import ApprovalPolicy, default_policy
from src.state import (
    ApprovalDecision,
    ApprovalRequest,
    InvalidStateTransition,
    Phase,
    SOCState,
    validate_transition,
)
from src.tools import ToolBroker, build_broker

#: Route -> phase the supervisor moves the run into when dispatching there.
_ROUTE_PHASE: dict[Route, Phase] = {
    Route.TRIAGE: Phase.TRIAGING,
    Route.ENRICHMENT: Phase.ENRICHING,
    Route.HUMAN_APPROVAL: Phase.AWAITING_APPROVAL,
    Route.REPORTER: Phase.REPORTING,
    Route.HALT: Phase.HALTED,
}


def build_graph(
    *,
    checkpointer: Any | None = None,
    broker: ToolBroker | None = None,
    audit: AuditLogger | None = None,
    policy: ApprovalPolicy | None = None,
    consult_llm: bool = True,
) -> Any:
    """Compile the SOC investigation graph.

    All collaborators are injectable so tests can supply an in-memory audit
    sink, a stub broker, or a policy with different thresholds.
    """
    audit_logger = audit or get_audit_logger()
    tool_broker = broker or build_broker(audit=audit_logger)
    approval_policy = policy or default_policy()

    def _context(state: SOCState, role: AgentRole) -> AgentContext:
        # A run can suspend at the approval interrupt and resume in a different
        # process, where the broker's in-memory tally starts empty.  Seed it
        # from checkpointed state so the budget spans the whole run rather than
        # resetting -- and so the supervisor does not write that empty tally
        # back over the persisted count.
        tool_broker.seed_budget(state.run.thread_id, state.tool_calls_used)
        return AgentContext(
            role=role,
            broker=tool_broker,
            audit=audit_logger,
            thread_id=state.run.thread_id,
        )

    # -- Supervisor --------------------------------------------------------
    def supervisor_node(state: SOCState) -> dict[str, Any]:
        context = _context(state, AgentRole.SUPERVISOR)
        decision, policy_decision, events = run_supervisor(
            state, context, approval_policy, consult_llm=consult_llm
        )

        updates: dict[str, Any] = {
            "audit_log": events,
            "next_agent": decision.route.value,
            "supervisor_turns": state.supervisor_turns + 1,
            "tool_calls_used": tool_broker.calls_used(state.run.thread_id),
            "messages": [
                AIMessage(
                    content=f"[supervisor] route={decision.route.value} ({decision.rule_id}): {decision.reason}",
                    name="supervisor",
                )
            ],
        }

        # Move the workflow phase, validating the transition.
        target_phase = _ROUTE_PHASE.get(decision.route)
        if target_phase is not None and target_phase is not state.phase:
            try:
                validate_transition(state.phase, target_phase)
                updates["phase"] = target_phase
            except InvalidStateTransition as exc:
                updates["errors"] = [str(exc)]
                updates["phase"] = Phase.HALTED
                updates["next_agent"] = Route.HALT.value
                updates["audit_log"] = events + [
                    audit_logger.record(
                        thread_id=state.run.thread_id,
                        actor=AgentRole.SUPERVISOR,
                        action=AuditAction.ERROR,
                        summary="illegal phase transition blocked; halting run",
                        details={"error": str(exc)},
                        success=False,
                    )
                ]
                return updates

        # Record the approval requirement on state when the gate is opened.
        if decision.route is Route.HUMAN_APPROVAL:
            enrichment = state.enrichment_results
            request = ApprovalRequest(
                rule_id=policy_decision.rule_id,
                reason=policy_decision.reason,
                severity=state.triage_result.severity
                if state.triage_result
                else state.alert.reported_severity,
                alert_title=state.alert.title,
                summary=(
                    enrichment.hunt_summary
                    if enrichment and enrichment.hunt_summary
                    else (state.triage_result.rationale if state.triage_result else state.alert.description)
                )[:2000],
                proposed_actions=enrichment.proposed_actions if enrichment else (),
            )
            updates.update(
                {
                    "requires_approval": True,
                    "approval_status": ApprovalStatus.PENDING,
                    "approval_reason": policy_decision.reason,
                    "approval_rule_id": policy_decision.rule_id,
                    "approval_request": request,
                }
            )
            updates["audit_log"] = events + [
                audit_logger.record(
                    thread_id=state.run.thread_id,
                    actor=AgentRole.SUPERVISOR,
                    action=AuditAction.APPROVAL_REQUESTED,
                    summary=f"human approval required: {policy_decision.rule_id}",
                    details={
                        "request_id": request.request_id,
                        "rule_id": policy_decision.rule_id,
                        "reason": policy_decision.reason,
                        "severity": request.severity.value,
                        "proposed_actions": [a.title for a in request.proposed_actions],
                    },
                )
            ]

        return updates

    # -- Triage ------------------------------------------------------------
    def triage_node(state: SOCState) -> dict[str, Any]:
        context = _context(state, AgentRole.TRIAGE)
        result, events = run_triage(state.alert, context)
        return {
            "triage_result": result,
            "audit_log": events,
            "completed_agents": ["triage"],
            "phase": Phase.TRIAGED,
            "tool_calls_used": tool_broker.calls_used(state.run.thread_id),
            "messages": [
                AIMessage(
                    content=(
                        f"[triage] severity={result.severity.value} category={result.category.value} "
                        f"confidence={result.confidence:.2f}: {result.rationale}"
                    ),
                    name="triage",
                )
            ],
        }

    # -- Enrichment --------------------------------------------------------
    def enrichment_node(state: SOCState) -> dict[str, Any]:
        if state.triage_result is None:  # defensive: routing should prevent this
            return {
                "errors": ["enrichment reached without a triage result"],
                "phase": Phase.HALTED,
            }

        context = _context(state, AgentRole.ENRICHMENT)
        results, events = run_enrichment(state.alert, state.triage_result, context)
        return {
            "enrichment_results": results,
            "audit_log": events,
            "completed_agents": ["enrichment"],
            "phase": Phase.ENRICHED,
            "tool_calls_used": tool_broker.calls_used(state.run.thread_id),
            "messages": [
                AIMessage(
                    content=(
                        f"[enrichment] {results.malicious_indicator_count} malicious indicator(s), "
                        f"{len(results.mitre_techniques)} technique(s), {len(results.log_hits)} log hit(s), "
                        f"{len(results.proposed_actions)} proposal(s). {results.hunt_summary}"
                    ),
                    name="enrichment",
                )
            ],
        }

    # -- Human approval (interrupt) ---------------------------------------
    def human_approval_node(state: SOCState) -> dict[str, Any]:
        """Suspend the graph until a human decides.

        ``interrupt()`` raises on the first pass, so this node re-executes from
        the top on resume.  Everything before the interrupt must therefore be
        side-effect free -- the audit event for *requesting* approval is
        emitted by the supervisor, which runs exactly once.
        """
        request = state.approval_request or ApprovalRequest(
            rule_id=state.approval_rule_id or "UNKNOWN",
            reason=state.approval_reason or "Human approval required.",
            severity=state.triage_result.severity
            if state.triage_result
            else state.alert.reported_severity,
            alert_title=state.alert.title,
            summary=state.alert.description[:2000],
        )

        # Execution stops here until the run is resumed with a decision.
        response = interrupt(
            {
                "type": "approval_request",
                "request_id": request.request_id,
                "rule_id": request.rule_id,
                "reason": request.reason,
                "severity": request.severity.value,
                "alert_id": state.alert.alert_id,
                "alert_title": request.alert_title,
                "summary": request.summary,
                "proposed_actions": [
                    {
                        "action_id": action.action_id,
                        "title": action.title,
                        "description": action.description,
                        "risk": action.risk.value,
                        "target": action.target,
                        "execution_mode": action.execution_mode,
                    }
                    for action in request.proposed_actions
                ],
            }
        )

        # --- Resumed: interpret the human's answer ------------------------
        # Anything unparseable is treated as a rejection. Failing closed is the
        # only safe default for an approval gate.
        decision = _parse_approval_response(response, request.request_id)

        approved = decision.approved
        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        target_phase = Phase.APPROVED if approved else Phase.REJECTED

        event = audit_logger.record(
            thread_id=state.run.thread_id,
            actor=AgentRole.HUMAN_ANALYST,
            action=AuditAction.APPROVAL_GRANTED if approved else AuditAction.APPROVAL_REJECTED,
            summary=(
                f"human {'approved' if approved else 'rejected'} incident handling "
                f"({request.rule_id})"
            ),
            details={
                "request_id": request.request_id,
                "decided_by": decision.decided_by,
                "notes": decision.notes,
                "approved_action_ids": list(decision.approved_action_ids),
            },
        )

        return {
            "approval_decision": decision,
            "approval_status": status,
            "audit_log": [event],
            "completed_agents": ["human_approval"],
            "phase": target_phase,
            "messages": [
                AIMessage(
                    content=(
                        f"[human_analyst] {'APPROVED' if approved else 'REJECTED'} by "
                        f"{decision.decided_by}. {decision.notes}"
                    ),
                    name="human_analyst",
                )
            ],
        }

    # -- Reporter ----------------------------------------------------------
    def reporter_node(state: SOCState) -> dict[str, Any]:
        if state.triage_result is None:  # defensive: routing should prevent this
            return {
                "errors": ["reporter reached without a triage result"],
                "phase": Phase.HALTED,
            }

        context = _context(state, AgentRole.REPORTER)
        report, events = run_reporter(
            state.alert,
            state.triage_result,
            state.enrichment_results,
            state.approval_decision,
            state.approval_status,
            context,
        )
        return {
            "final_report": report,
            "audit_log": events,
            "completed_agents": ["reporter"],
            "phase": Phase.COMPLETE,
            "messages": [
                AIMessage(
                    content=f"[reporter] verdict={report.verdict.value}: {report.executive_summary}",
                    name="reporter",
                )
            ],
        }

    # -- Routing -----------------------------------------------------------
    def route_from_supervisor(state: SOCState) -> str:
        route = state.next_agent or Route.FINISH.value
        if route in {Route.FINISH.value, Route.HALT.value}:
            return END
        return route

    graph = StateGraph(SOCState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("human_approval", human_approval_node)
    graph.add_node("reporter", reporter_node)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "triage": "triage",
            "enrichment": "enrichment",
            "human_approval": "human_approval",
            "reporter": "reporter",
            END: END,
        },
    )
    # Every specialist reports back to the supervisor. No agent-to-agent edges.
    for node in ("triage", "enrichment", "human_approval", "reporter"):
        graph.add_edge(node, "supervisor")

    return graph.compile(checkpointer=checkpointer)


def pending_interrupt(graph: Any, config: dict[str, Any], result: Any = None) -> dict[str, Any] | None:
    """Return the payload of a pending interrupt, or None if the run is not paused.

    LangGraph has moved this around between releases: newer versions attach an
    ``__interrupt__`` key to the invoke result, while 0.2.x exposes it only via
    ``get_state(...).tasks[*].interrupts``.  Both are checked so the caller does
    not have to care which is installed.
    """
    if isinstance(result, dict):
        interrupts = result.get("__interrupt__")
        if interrupts:
            return dict(interrupts[0].value)

    snapshot = graph.get_state(config)
    for task in getattr(snapshot, "tasks", ()):
        for item in getattr(task, "interrupts", ()):
            if item.value is not None:
                return dict(item.value)
    return None


def _parse_approval_response(response: Any, request_id: str) -> ApprovalDecision:
    """Coerce a resume payload into an :class:`ApprovalDecision`, failing closed."""
    if isinstance(response, ApprovalDecision):
        return response

    if isinstance(response, bool):
        return ApprovalDecision(request_id=request_id, approved=response)

    if isinstance(response, dict):
        try:
            payload = dict(response)
            payload.setdefault("request_id", request_id)
            payload["approved"] = bool(payload.get("approved", False))
            return ApprovalDecision.model_validate(payload)
        except Exception:  # noqa: BLE001 - malformed input must not crash the gate
            return ApprovalDecision(
                request_id=request_id,
                approved=False,
                decided_by="system",
                notes="Malformed approval payload; failing closed (treated as rejection).",
            )

    return ApprovalDecision(
        request_id=request_id,
        approved=False,
        decided_by="system",
        notes=f"Unrecognised approval response of type {type(response).__name__}; failing closed.",
    )


def build_checkpointer(db_path: Path | None = None) -> Any:
    """Create a SQLite checkpointer.

    Checkpointing is what makes the HITL gate real: the graph can be suspended
    at an interrupt, the process can exit, and an analyst can resume the run
    minutes or hours later from persisted state.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver

    from src.config import get_settings

    settings = get_settings()
    settings.ensure_dirs()
    path = db_path or settings.checkpoint_db
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path), check_same_thread=False)
    return SqliteSaver(connection)


def build_memory_checkpointer() -> Any:
    """In-memory checkpointer for tests and ephemeral runs."""
    from langgraph.checkpoint.memory import MemorySaver

    return MemorySaver()
