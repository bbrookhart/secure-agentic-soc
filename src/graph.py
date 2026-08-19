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
from src.agents.frontier import next_frontier
from src.agents.reporter import run_reporter
from src.agents.supervisor import Route, run_supervisor
from src.agents.triage import run_triage
from src.enums import AgentRole, ApprovalStatus, AuditAction
from src.observability import metrics
from src.security.audit import AuditLogger, get_audit_logger
from src.security.authz import ApprovalContext, authorize_approval, required_approvals
from src.security.policy import ApprovalPolicy, default_policy
from src.state import (
    ApprovalDecision,
    ApprovalRequest,
    InvalidStateTransition,
    Phase,
    SOCState,
    merge_enrichment,
    validate_transition,
)
from src.tools import ToolBroker, build_broker

#: Refused approvals tolerated before the run halts. Bounds a caller that
#: keeps resubmitting the same unauthorised answer.
MAX_AUTHORIZATION_DENIALS = 3

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
            metrics.approval_requested(
                rule_id=policy_decision.rule_id, severity=request.severity.value
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
        # Rounds after the first follow the frontier: entities earlier evidence
        # surfaced that nothing has investigated yet.
        scope = next_frontier(state) if state.enrichment_results is not None else ()
        results, events = run_enrichment(state.alert, state.triage_result, context, scope)

        # Accumulate rather than replace. merge_enrichment ORs the injection
        # flag, so a hostile line found in round one keeps forcing HITL-005
        # even if later rounds come back clean.
        merged = merge_enrichment(state.enrichment_results, results)
        covered = tuple(
            dict.fromkeys(state.investigated_entities + tuple(e.lower() for e in scope))
        )
        chain = state.investigation_chain + (
            (f"round {state.investigation_rounds + 1}: {', '.join(scope)}",) if scope else ()
        )
        return {
            "enrichment_results": merged,
            "investigation_rounds": state.investigation_rounds + 1,
            "investigated_entities": covered,
            "investigation_chain": chain,
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

        # --- Authorisation ------------------------------------------------
        # Authentication established *who* this is at the console. This decides
        # whether they may sign *this*. It runs on approvals only: a rejection
        # is always permitted, because refusing to act is never the dangerous
        # direction, and requiring authority to say "no" would strand runs.
        if decision.approved:
            authorization = authorize_approval(_approval_context(state, decision))
            if not authorization.allowed:
                metrics.authorization_denied(rule_id=authorization.rule_id)
                denial = audit_logger.record(
                    thread_id=state.run.thread_id,
                    actor=AgentRole.HUMAN_ANALYST,
                    action=AuditAction.AUTHORIZATION_DENIED,
                    summary=f"approval refused: {authorization.rule_id}",
                    details={
                        "request_id": request.request_id,
                        "approver": decision.decided_by,
                        "identity_source": decision.identity_source,
                        "rule_id": authorization.rule_id,
                        "reason": authorization.reason,
                        "roles": [role.value for role in authorization.matched_roles],
                        "initiated_by": state.run.initiated_by,
                    },
                    success=False,
                )
                # The gate stays shut and PENDING. An unauthorised approval is
                # not a rejection -- the incident still needs someone who can
                # actually sign it.
                #
                # Bounded, though: a caller that resubmits the same refused
                # answer (an automation with --approve, say) would otherwise
                # loop here until the supervisor turn limit, filling the audit
                # log with identical denials. After MAX_DENIALS the run halts
                # and says why.
                denials = state.authorization_denials + 1
                if denials >= MAX_AUTHORIZATION_DENIALS:
                    return {
                        "approval_status": ApprovalStatus.PENDING,
                        "authorization_denials": denials,
                        "phase": Phase.HALTED,
                        "errors": [
                            f"halted after {denials} refused approval attempts "
                            f"({authorization.rule_id}); an authorised approver is required"
                        ],
                        "audit_log": [denial],
                        "messages": [
                            AIMessage(
                                content=(
                                    f"[authorization] halting after {denials} refused "
                                    f"attempts: {authorization.reason}"
                                ),
                                name="authorization",
                            )
                        ],
                    }
                return {
                    "approval_status": ApprovalStatus.PENDING,
                    "authorization_denials": denials,
                    "audit_log": [denial],
                    "messages": [
                        AIMessage(
                            content=(
                                f"[authorization] REFUSED for {decision.decided_by} "
                                f"({authorization.rule_id}): {authorization.reason}"
                            ),
                            name="authorization",
                        )
                    ],
                }

        approved = decision.approved
        recorded = (*state.recorded_approvals, decision) if approved else state.recorded_approvals

        # --- Two-person integrity ------------------------------------------
        needed = required_approvals(
            action_risks=tuple(a.risk for a in request.proposed_actions),
            asset_is_critical=state.alert.has_critical_asset,
        )
        distinct_approvers = {entry.decided_by for entry in recorded}
        quorum_met = len(distinct_approvers) >= needed

        if approved and not quorum_met:
            waiting = audit_logger.record(
                thread_id=state.run.thread_id,
                actor=AgentRole.HUMAN_ANALYST,
                action=AuditAction.APPROVAL_REQUESTED,
                summary=(
                    f"approval {len(distinct_approvers)}/{needed} recorded; "
                    "awaiting a second approver"
                ),
                details={
                    "request_id": request.request_id,
                    "approver": decision.decided_by,
                    "approvals_recorded": sorted(distinct_approvers),
                    "approvals_required": needed,
                },
            )
            return {
                "recorded_approvals": recorded,
                "approval_status": ApprovalStatus.PENDING,
                "audit_log": [waiting],
                "messages": [
                    AIMessage(
                        content=(
                            f"[human_analyst] {decision.decided_by} approved "
                            f"({len(distinct_approvers)}/{needed}); a second approver is required."
                        ),
                        name="human_analyst",
                    )
                ],
            }

        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        target_phase = Phase.APPROVED if approved else Phase.REJECTED
        metrics.approval_decided(outcome="approved" if approved else "rejected")

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
                "identity_source": decision.identity_source,
                "notes": decision.notes,
                "approved_action_ids": list(decision.approved_action_ids),
                "approvers": sorted(distinct_approvers) if approved else [],
                "approvals_required": needed,
            },
        )

        return {
            "approval_decision": decision,
            "recorded_approvals": recorded,
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
            case_context={
                "related_run_count": state.related_run_count,
                "related_confirmed_malicious": state.related_confirmed_malicious,
                "related_false_positives": state.related_false_positives,
                "case_id": state.case_id,
            },
            investigation_chain=state.investigation_chain,
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


def _approval_context(state: SOCState, decision: ApprovalDecision) -> ApprovalContext:
    """Project state and the decision into the facts authorization may consider.

    Structured values only, like :class:`~src.security.policy.PolicyInput`. The
    roles come from the decision because only the console can verify them; a CLI
    operator asserting a role would be self-granting authority.
    """
    from src.config import get_settings
    from src.security.authz import roles_from_groups

    enrichment = state.enrichment_results
    return ApprovalContext(
        approver=decision.decided_by,
        roles=roles_from_groups(list(decision.roles)),
        severity=state.triage_result.severity if state.triage_result else state.alert.reported_severity,
        action_risks=tuple(a.risk for a in enrichment.proposed_actions) if enrichment else (),
        asset_is_critical=state.alert.has_critical_asset,
        initiated_by=state.run.initiated_by,
        prior_approvers=tuple(entry.decided_by for entry in state.recorded_approvals),
        identity_verified=decision.identity_source == "proxy_header",
        authentication_required=get_settings().require_authenticated_approval,
        separation_of_duties_required=get_settings().require_separation_of_duties,
    )


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


#: Modules whose types are legitimately reconstructed when a checkpoint is loaded.
#: Only this project's own state vocabulary -- nothing else.
_CHECKPOINT_TYPE_MODULES = ("src.state", "src.enums", "src.security.audit")


def checkpoint_allowlist() -> list[tuple[str, str]]:
    """The types a checkpoint is permitted to reconstruct.

    Loading a checkpoint means deserialising it, and deserialisation that can
    reconstruct arbitrary objects is a code-execution primitive: this is
    PYSEC-2026-83 / 1527 / 2573, which were reachable here precisely because a
    resumed approval *is* a checkpoint load in a fresh process.

    Upgrading closed the JSON path. This closes the msgpack one, which otherwise
    defaults to warn-and-allow: with an explicit allowlist, the serialiser will
    reconstruct the built-in safe set plus exactly these types, and a payload
    naming anything else -- ``os.system``, say -- comes back as inert data.

    The list is derived from this project's own modules rather than hand-written,
    so adding a state model cannot silently leave it unloadable, and it still
    cannot widen beyond the three modules above. Passing it explicitly rather
    than relying on ``LANGGRAPH_STRICT_MSGPACK`` means the control does not
    depend on an environment variable someone forgot to set.
    """
    import importlib
    import inspect

    allowed: set[tuple[str, str]] = set()
    for module_name in _CHECKPOINT_TYPE_MODULES:
        module = importlib.import_module(module_name)
        for name, obj in vars(module).items():
            if name.startswith("_") or not inspect.isclass(obj):
                continue
            # Defined here, not merely imported into this namespace.
            if getattr(obj, "__module__", None) == module_name:
                allowed.add((module_name, name))
    return sorted(allowed)


def _serializer() -> Any:
    """Checkpoint serialiser restricted to this project's own types."""
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

    return JsonPlusSerializer(allowed_msgpack_modules=checkpoint_allowlist())


def build_checkpointer(db_path: Path | None = None) -> Any:
    """Create a SQLite checkpointer.

    Checkpointing is what makes the HITL gate real: the graph can be suspended
    at an interrupt, the process can exit, and an analyst can resume the run
    minutes or hours later from persisted state.

    That durability is also why the checkpoint store is integrity-sensitive
    storage, at the same level as the audit log: whoever can write it decides
    what gets deserialised. Hence the restricted serialiser.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver

    from src.config import get_settings

    settings = get_settings()
    settings.ensure_dirs()
    path = db_path or settings.checkpoint_db
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path), check_same_thread=False)
    return SqliteSaver(connection, serde=_serializer())


def build_memory_checkpointer() -> Any:
    """In-memory checkpointer for tests and ephemeral runs.

    Uses the same restricted serialiser as the durable one, so tests exercise
    the configuration that actually ships.
    """
    from langgraph.checkpoint.memory import MemorySaver

    return MemorySaver(serde=_serializer())
