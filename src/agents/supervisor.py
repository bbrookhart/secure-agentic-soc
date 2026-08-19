"""Supervisor agent -- orchestration and policy enforcement.

The supervisor is where this project makes its central security argument:
**reasoning and authority are separated.**

* The **deterministic router** (:func:`deterministic_route`) decides what
  happens next.  It reads validated state and applies ordered rules.  It is the
  authority.
* The **LLM advisor** (optional) is asked for its opinion on the same state.
  Its answer is recorded in the audit log and compared with the router's.  When
  they disagree, the router wins and the disagreement is logged as an override.
  It is reasoning without authority.

That structure means an attacker who fully controls the model's output can, at
worst, generate a logged disagreement.  They cannot route around triage, skip
the approval gate, or drive the graph to FINISH with an unreviewed critical
incident -- because the model was never the thing making that call.

The supervisor also holds **no tools at all** (see ``security/identity.py``),
so compromising the orchestrator yields no capability either.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator

from src.agents.base import AgentContext
from src.agents.coercion import enum_coercer
from src.agents.frontier import next_frontier
from src.enums import (
    AgentRole,
    AlertCategory,
    ApprovalStatus,
    AuditAction,
    PolicyEffect,
    Severity,
)
from src.llm import structured_completion
from src.observability import metrics
from src.prompts import SUPERVISOR as _SUPERVISOR
from src.prompts import with_preamble
from src.security.audit import AuditEvent
from src.security.operating_mode import current_mode
from src.security.policy import ApprovalPolicy, PolicyDecision, PolicyInput
from src.state import Phase, SOCState

#: Hard ceiling on supervisor turns, so a routing bug cannot loop forever.
# Raised from 12 to accommodate multi-round investigations: each extra round
# costs two supervisor turns (out to enrichment, back again), and a run that
# hits this limit halts rather than finishing, so the round cap below must be
# what stops an investigation -- never this.
MAX_SUPERVISOR_TURNS = 20

#: How many evidence-gathering rounds one run may take. Three is enough to
#: follow a lead two hops from the original alert, which covers the realistic
#: "alert names A, A talks to B, B is the actual problem" shape.
MAX_INVESTIGATION_ROUNDS = 3

#: Tool calls that must remain before another round is worth starting.
MIN_ROUND_TOOL_HEADROOM = 8


class Route(str, Enum):
    """Where the supervisor can send control next."""

    TRIAGE = "triage"
    ENRICHMENT = "enrichment"
    HUMAN_APPROVAL = "human_approval"
    REPORTER = "reporter"
    FINISH = "finish"
    HALT = "halt"


class RouteDecision(BaseModel):
    """A routing decision plus the rule that produced it."""

    model_config = {"frozen": True}

    route: Route
    rule_id: str
    reason: str


class SupervisorLLMOutput(BaseModel):
    """Advisory schema for the LLM supervisor. Never authoritative."""

    next_agent: Route = Field(description="Which step should run next.")
    reason: str = Field(max_length=600, description="One or two sentences justifying the choice.")

    _coerce_route = field_validator("next_agent", mode="before")(enum_coercer(Route))


SUPERVISOR_SYSTEM_PROMPT = with_preamble(_SUPERVISOR)


def build_policy_input(state: SOCState, *, max_tool_calls: int) -> PolicyInput:
    """Project state down to the structured facts the policy engine may consider.

    ``max_tool_calls`` comes from the broker that actually enforces the budget,
    so the DENY-002 threshold and the broker ceiling cannot drift apart.

    The injection flag is the union of every untrusted source seen so far:
    the alert's own text (recorded by triage) and tool output (recorded by
    enrichment).  Taking only the latter would miss alert-borne injection
    entirely on runs that skip enrichment.
    """
    triage = state.triage_result
    enrichment = state.enrichment_results

    flagged = bool(triage and triage.untrusted_content_flagged) or bool(
        enrichment and enrichment.untrusted_content_flagged
    )

    return PolicyInput(
        severity=triage.severity if triage else state.alert.reported_severity,
        confidence=triage.confidence if triage else 1.0,
        category_is_unknown=bool(triage and triage.category is AlertCategory.UNKNOWN),
        content_not_analysable=bool(triage and triage.analysis_limits),
        asset_is_critical=state.alert.has_critical_asset,
        proposed_action_risks=tuple(a.risk for a in enrichment.proposed_actions) if enrichment else (),
        tool_calls_used=state.tool_calls_used,
        max_tool_calls=max_tool_calls,
        untrusted_content_flagged=flagged,
        related_confirmed_malicious=state.related_confirmed_malicious,
        autonomy_suspended=current_mode().forces_human_review,
    )


def deterministic_route(
    state: SOCState,
    policy_decision: PolicyDecision,
    *,
    max_tool_calls: int = 40,
) -> RouteDecision:
    """The authoritative router. Ordered rules over validated state.

    ``max_tool_calls`` comes from the broker that actually enforces the budget,
    so the "is another investigation round affordable" check in R-023 is made
    against the real ceiling rather than a guess. It defaults to the broker's
    own default for callers that only exercise routing.
    """
    # --- Terminal states --------------------------------------------------
    if state.phase is Phase.COMPLETE:
        return RouteDecision(route=Route.FINISH, rule_id="R-000", reason="Run already complete.")
    if state.phase is Phase.HALTED:
        return RouteDecision(route=Route.HALT, rule_id="R-001", reason="Run halted.")

    # --- Loop guard -------------------------------------------------------
    if state.supervisor_turns >= MAX_SUPERVISOR_TURNS:
        return RouteDecision(
            route=Route.HALT,
            rule_id="R-002",
            reason=f"Supervisor turn limit ({MAX_SUPERVISOR_TURNS}) reached; halting to bound the run.",
        )

    # --- Operator halt ----------------------------------------------------
    # Checked before policy: 'stop everything' is not a policy question, and
    # an incident responder who set halt expects it to mean halt.
    if current_mode().stops_in_flight:
        return RouteDecision(
            route=Route.HALT,
            rule_id="R-004",
            reason="Operating mode is 'halt'; stopping this run at the supervisor turn.",
        )

    # --- Hard policy denial ----------------------------------------------
    if policy_decision.effect is PolicyEffect.DENY:
        return RouteDecision(
            route=Route.HALT,
            rule_id="R-003",
            reason=f"Policy denied continuation ({policy_decision.rule_id}): {policy_decision.reason}",
        )

    # --- Triage must happen first ----------------------------------------
    if state.triage_result is None:
        return RouteDecision(
            route=Route.TRIAGE,
            rule_id="R-010",
            reason="No triage assessment yet; triage must run before anything else.",
        )

    triage = state.triage_result

    # --- Enrichment -------------------------------------------------------
    if state.enrichment_results is None:
        # First pass. Skip enrichment only for confidently benign, non-severe alerts. The
        # confidence floor matters: a low-confidence "benign" is exactly the
        # case where skipping investigation would be a mistake.
        confidently_benign = (
            triage.category is AlertCategory.BENIGN_OR_FALSE_POSITIVE
            and triage.severity.rank <= Severity.LOW.rank
            and triage.confidence >= 0.70
        )
        # A routing shortcut may never outrank the approval gate.  R-020 returns
        # straight to the reporter, so without this guard a "benign" verdict
        # would carry the run past a policy that demanded a human -- which is
        # precisely what an attacker crafting benign-looking alert text wants.
        # Such runs fall through to enrichment instead, so the analyst reaches
        # the gate with evidence in hand rather than being asked to approve a
        # verdict no one has tested.
        if confidently_benign and policy_decision.effect is PolicyEffect.REQUIRE_APPROVAL:
            return RouteDecision(
                route=Route.ENRICHMENT,
                rule_id="R-022",
                reason=(
                    f"Triage assessed this as benign, but policy requires human review "
                    f"({policy_decision.rule_id}); gathering evidence before the gate rather "
                    "than taking the benign shortcut."
                ),
            )
        if confidently_benign:
            return RouteDecision(
                route=Route.REPORTER,
                rule_id="R-020",
                reason=(
                    f"Triage assessed this as confidently benign ({triage.confidence:.0%}) and "
                    f"{triage.severity.value} severity; enrichment would add no value."
                ),
            )
        return RouteDecision(
            route=Route.ENRICHMENT,
            rule_id="R-021",
            reason="Triage complete; enrichment needed to test the hypothesis against evidence.",
        )

    # --- Human approval gate ----------------------------------------------
    if policy_decision.effect is PolicyEffect.REQUIRE_APPROVAL:
        if state.approval_status in {ApprovalStatus.NOT_REQUIRED, ApprovalStatus.PENDING}:
            return RouteDecision(
                route=Route.HUMAN_APPROVAL,
                rule_id="R-030",
                reason=f"Policy requires human approval ({policy_decision.rule_id}): {policy_decision.reason}",
            )

    # --- Reporting --------------------------------------------------------
    # --- Keep investigating while evidence points somewhere new -----------
    # Deliberately below the approval gate: a run that owes a human must stop
    # and ask, not keep pivoting. Above it, an investigation that kept finding
    # new hosts would postpone the gate indefinitely -- which is exactly what
    # an attacker seeding evidence with fresh hostnames would want.
    if state.enrichment_results is not None and state.final_report is None:
        frontier = next_frontier(state)
        rounds_left = state.investigation_rounds < MAX_INVESTIGATION_ROUNDS
        # Leave headroom rather than running to exhaustion: a round that dies
        # mid-way through its tool budget produces partial evidence, which is
        # worse than not starting it.
        budget_left = (max_tool_calls - state.tool_calls_used) >= MIN_ROUND_TOOL_HEADROOM
        if frontier and rounds_left and budget_left:
            return RouteDecision(
                route=Route.ENRICHMENT,
                rule_id="R-023",
                reason=(
                    f"Evidence surfaced {len(frontier)} entity(ies) nothing has "
                    f"investigated yet ({', '.join(frontier)}); round "
                    f"{state.investigation_rounds + 1} of {MAX_INVESTIGATION_ROUNDS}."
                ),
            )

    if state.final_report is None:
        return RouteDecision(
            route=Route.REPORTER,
            rule_id="R-040",
            reason="Evidence gathering and any required approval are complete; generate the report.",
        )

    return RouteDecision(
        route=Route.FINISH,
        rule_id="R-050",
        reason="Report produced; investigation complete.",
    )


def _render_state_for_supervisor(state: SOCState) -> str:
    """Compact state digest for the LLM advisor.

    Only structured facts are included -- no raw alert text.  The advisor does
    not need attacker-controlled prose to answer "what step comes next", so it
    is not given any.
    """
    triage = state.triage_result
    enrichment = state.enrichment_results

    lines = [
        f"alert_id: {state.alert.alert_id}",
        f"reported_severity: {state.alert.reported_severity.value}",
        f"critical_asset_involved: {state.alert.has_critical_asset}",
        f"phase: {state.phase.value}",
        f"supervisor_turns: {state.supervisor_turns}",
        f"completed_agents: {state.completed_agents or '[]'}",
        f"triage_done: {triage is not None}",
    ]
    if triage:
        lines += [
            f"  triage_severity: {triage.severity.value}",
            f"  triage_category: {triage.category.value}",
            f"  triage_confidence: {triage.confidence}",
        ]
    lines.append(f"enrichment_done: {enrichment is not None}")
    if enrichment:
        lines += [
            f"  malicious_indicators: {enrichment.malicious_indicator_count}",
            f"  techniques_mapped: {len(enrichment.mitre_techniques)}",
            f"  log_hits: {len(enrichment.log_hits)}",
            f"  proposed_actions: {len(enrichment.proposed_actions)}",
            f"  injection_flagged: {enrichment.untrusted_content_flagged}",
        ]
    lines += [
        f"approval_status: {state.approval_status.value}",
        f"report_done: {state.final_report is not None}",
    ]
    return "\n".join(lines)


def run_supervisor(
    state: SOCState,
    context: AgentContext,
    policy: ApprovalPolicy,
    *,
    consult_llm: bool = True,
) -> tuple[RouteDecision, PolicyDecision, list[AuditEvent]]:
    """Evaluate policy, decide the route, and record both."""
    events: list[AuditEvent] = []

    # --- 1. Policy evaluation (deterministic, LLM-free) -------------------
    # The budget ceiling is read from the broker that enforces it, so a
    # reconfigured limit cannot leave policy and enforcement disagreeing.
    policy_input = build_policy_input(state, max_tool_calls=context.broker.max_calls_per_run)
    policy_decision = policy.evaluate(policy_input)
    metrics.policy_decision(
        effect=policy_decision.effect.value, rule_id=policy_decision.rule_id
    )
    events.append(
        context.log(
            AuditAction.POLICY_EVALUATED,
            f"policy: {policy_decision.effect.value} ({policy_decision.rule_id})",
            {
                "effect": policy_decision.effect.value,
                "rule_id": policy_decision.rule_id,
                "reason": policy_decision.reason,
                "matched_rules": list(policy_decision.matched_rules),
                "inputs": policy_input.model_dump(mode="json"),
            },
        )
    )

    # --- 2. Authoritative routing ----------------------------------------
    decision = deterministic_route(
        state, policy_decision, max_tool_calls=context.broker.max_calls_per_run
    )

    # --- 3. Advisory LLM opinion -----------------------------------------
    if consult_llm:
        call = structured_completion(
            SupervisorLLMOutput,
            system_prompt=SUPERVISOR_SYSTEM_PROMPT,
            user_prompt=(
                "Current investigation state:\n"
                f"{_render_state_for_supervisor(state)}\n\n"
                "Which step should run next, and why?"
            ),
            actor=AgentRole.SUPERVISOR,
            thread_id=context.thread_id,
            audit=context.audit,
        )
        events.extend(call.audit_events)

        if call.ok and call.parsed is not None:
            advisory: SupervisorLLMOutput = call.parsed
            agreed = advisory.next_agent is decision.route
            events.append(
                context.log(
                    AuditAction.ROUTING_DECISION,
                    (
                        f"LLM advisor agreed: {advisory.next_agent.value}"
                        if agreed
                        else f"LLM advisor OVERRIDDEN: proposed '{advisory.next_agent.value}', "
                        f"policy routed to '{decision.route.value}'"
                    ),
                    {
                        "advisory_route": advisory.next_agent.value,
                        "advisory_reason": advisory.reason,
                        "authoritative_route": decision.route.value,
                        "authoritative_rule": decision.rule_id,
                        "agreed": agreed,
                    },
                    success=agreed,
                )
            )

    # --- 4. Record the authoritative decision ----------------------------
    events.append(
        context.log(
            AuditAction.ROUTING_DECISION,
            f"route -> {decision.route.value} ({decision.rule_id})",
            {
                "route": decision.route.value,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "phase": state.phase.value,
                "turn": state.supervisor_turns,
            },
        )
    )

    return decision, policy_decision, events
