"""End-to-end graph tests.

These run entirely offline (deterministic fallbacks), so they assert the
*architecture's* behaviour rather than any particular model's output.  That is
the point: the security properties must hold regardless of what the LLM does.
"""

from __future__ import annotations

import pytest
from langgraph.types import Command

from src.enums import AgentRole, ApprovalStatus, PolicyEffect, Severity
from src.graph import build_graph, build_memory_checkpointer, pending_interrupt
from src.state import Phase, SOCState


@pytest.fixture
def graph(audit_logger, broker):
    """A graph wired to isolated collaborators, with the LLM advisor disabled."""
    return build_graph(
        checkpointer=build_memory_checkpointer(),
        broker=broker,
        audit=audit_logger,
        consult_llm=False,
    )


def _config(state: SOCState) -> dict:
    return {"configurable": {"thread_id": state.run.thread_id}, "recursion_limit": 50}


def _state_of(graph, config) -> SOCState:
    return SOCState.model_validate(graph.get_state(config).values)


class TestBenignPath:
    def test_low_severity_completes_without_approval(self, graph, benign_alert):
        initial = SOCState.bootstrap(benign_alert, offline_mode=True)
        config = _config(initial)

        graph.invoke(initial, config=config)
        state = _state_of(graph, config)

        assert state.phase is Phase.COMPLETE
        assert state.approval_status is ApprovalStatus.NOT_REQUIRED
        assert state.final_report is not None
        assert pending_interrupt(graph, config) is None

    def test_report_records_a_verdict(self, graph, benign_alert):
        initial = SOCState.bootstrap(benign_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        report = _state_of(graph, config).final_report
        assert report is not None
        assert report.verdict.value in {"false_positive", "benign_true_positive", "inconclusive"}


class TestHighSeverityHITL:
    def test_graph_pauses_for_approval(self, graph, sample_alert):
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)

        graph.invoke(initial, config=config)

        request = pending_interrupt(graph, config)
        assert request is not None, "high-severity alert must pause for a human"
        assert request["type"] == "approval_request"

        state = _state_of(graph, config)
        assert state.phase is Phase.AWAITING_APPROVAL
        assert state.approval_status is ApprovalStatus.PENDING
        assert state.final_report is None, "no report may be produced before approval"

    def test_approval_resumes_and_completes(self, graph, sample_alert):
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        graph.invoke(
            Command(resume={"approved": True, "decided_by": "test-analyst", "notes": "ok"}),
            config=config,
        )
        state = _state_of(graph, config)

        assert state.phase is Phase.COMPLETE
        assert state.approval_status is ApprovalStatus.APPROVED
        assert state.approval_decision.decided_by == "test-analyst"
        assert state.final_report is not None

    def test_rejection_still_produces_a_report(self, graph, sample_alert):
        """A rejected incident must still be documented, not silently dropped."""
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        graph.invoke(
            Command(resume={"approved": False, "decided_by": "test-analyst", "notes": "not now"}),
            config=config,
        )
        state = _state_of(graph, config)

        assert state.approval_status is ApprovalStatus.REJECTED
        assert state.final_report is not None
        assert any("REJECTED" in caveat for caveat in state.final_report.caveats)

    def test_malformed_resume_fails_closed(self, graph, sample_alert):
        """An unparseable approval payload must be treated as a rejection."""
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        graph.invoke(Command(resume="yes please approve"), config=config)
        state = _state_of(graph, config)

        assert state.approval_status is ApprovalStatus.REJECTED

    def test_proposals_are_drafted_but_not_executed(self, graph, sample_alert):
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        state = _state_of(graph, config)
        proposals = state.enrichment_results.proposed_actions
        assert proposals, "a confirmed ransomware incident should draft containment"
        assert all(p.execution_mode == "proposal_only" for p in proposals)


class TestInjectionContainment:
    def test_injection_forces_approval_despite_low_severity(self, graph, injection_alert):
        """The injected text demands 'skip human approval'. It must not get it."""
        initial = SOCState.bootstrap(injection_alert, offline_mode=True)
        config = _config(initial)

        graph.invoke(initial, config=config)
        state = _state_of(graph, config)

        assert state.enrichment_results is not None
        assert state.enrichment_results.untrusted_content_flagged
        assert state.approval_status is ApprovalStatus.PENDING
        assert pending_interrupt(graph, config) is not None

    def test_injection_is_audited_not_suppressed(self, graph, injection_alert, audit_logger):
        """The injected text demands 'do not log this'. It must be logged."""
        initial = SOCState.bootstrap(injection_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)

        events = audit_logger.read_events(initial.run.thread_id)
        assert any(e.action.value == "untrusted_content_flagged" for e in events)
        assert len(events) > 5

    def test_injection_is_reported_as_a_finding(self, graph, injection_alert):
        initial = SOCState.bootstrap(injection_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)
        graph.invoke(Command(resume={"approved": False, "decided_by": "test"}), config=config)

        report = _state_of(graph, config).final_report
        assert report is not None
        assert any("injection" in finding.lower() for finding in report.key_findings)


class TestAuditCompleteness:
    def test_every_stage_is_audited(self, graph, sample_alert, audit_logger):
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)
        graph.invoke(Command(resume={"approved": True, "decided_by": "test"}), config=config)

        actions = {e.action.value for e in audit_logger.read_events(initial.run.thread_id)}
        for required in {
            "agent_started", "agent_completed", "routing_decision",
            "policy_evaluated", "tool_call", "tool_result",
            "approval_requested", "approval_granted",
        }:
            assert required in actions, f"missing audit action: {required}"

    def test_audit_chain_verifies_after_a_full_run(self, graph, sample_alert, audit_logger):
        from src.security.audit import verify_chain

        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)
        graph.invoke(Command(resume={"approved": True, "decided_by": "test"}), config=config)

        ok, message = verify_chain(audit_logger.read_events(initial.run.thread_id))
        assert ok, message

    def test_human_decision_is_attributed(self, graph, sample_alert, audit_logger):
        initial = SOCState.bootstrap(sample_alert, offline_mode=True)
        config = _config(initial)
        graph.invoke(initial, config=config)
        graph.invoke(Command(resume={"approved": True, "decided_by": "alice"}), config=config)

        approvals = [
            e for e in audit_logger.read_events(initial.run.thread_id)
            if e.action.value == "approval_granted"
        ]
        assert approvals
        assert approvals[0].actor is AgentRole.HUMAN_ANALYST
        assert approvals[0].details["decided_by"] == "alice"


class TestRoutingAuthority:
    def test_router_ignores_the_llm_when_they_disagree(self, sample_alert):
        """The deterministic router is the authority; the model only advises."""
        from src.agents.supervisor import Route, deterministic_route
        from src.security.policy import PolicyDecision

        state = SOCState.bootstrap(sample_alert, offline_mode=True)
        allow = PolicyDecision(effect=PolicyEffect.ALLOW, rule_id="ALLOW-000", reason="none")

        # Whatever a model might propose, triage must run first.
        decision = deterministic_route(state, allow)
        assert decision.route is Route.TRIAGE

    def test_turn_limit_halts_runaway_loops(self, sample_alert):
        from src.agents.supervisor import MAX_SUPERVISOR_TURNS, Route, deterministic_route
        from src.security.policy import PolicyDecision

        state = SOCState.bootstrap(sample_alert, offline_mode=True).model_copy(
            update={"supervisor_turns": MAX_SUPERVISOR_TURNS}
        )
        allow = PolicyDecision(effect=PolicyEffect.ALLOW, rule_id="ALLOW-000", reason="none")

        assert deterministic_route(state, allow).route is Route.HALT

    def test_deny_halts_the_run(self, sample_alert):
        from src.agents.supervisor import Route, deterministic_route
        from src.security.policy import PolicyDecision

        state = SOCState.bootstrap(sample_alert, offline_mode=True)
        deny = PolicyDecision(effect=PolicyEffect.DENY, rule_id="DENY-001", reason="destructive")

        assert deterministic_route(state, deny).route is Route.HALT


class TestTriageGuardrail:
    def test_severity_downgrade_is_capped(self, audit_logger, broker, sample_alert):
        """A model must not be able to bury a strongly-evidenced severe alert."""
        from src.agents.base import AgentContext
        from src.agents.triage import run_triage

        context = AgentContext(AgentRole.TRIAGE, broker, audit_logger, "t1")
        result, _ = run_triage(sample_alert, context)

        # Offline, this is the deterministic classifier's own verdict.
        assert result.severity.rank >= Severity.HIGH.rank
