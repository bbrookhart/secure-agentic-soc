"""Human authorization: who may approve what, and what is refused.

Authentication established *who*; these assert *what they may do*. The
interesting cases are all denials -- an approval gate is only worth something if
it says no to the right people.
"""

from __future__ import annotations

import pytest
from langgraph.types import Command

from src.enums import ActionRisk, ApprovalStatus, Severity
from src.graph import build_graph, build_memory_checkpointer, pending_interrupt
from src.security.approval_identity import resolve_identity
from src.security.authz import (
    AnalystRole,
    ApprovalContext,
    authority_matrix,
    authorize_approval,
    effective_authority,
    required_approvals,
    roles_from_groups,
)
from src.state import Phase, SOCState


def _context(**overrides) -> ApprovalContext:
    """A verified senior-analyst approval, unless a test says otherwise."""
    base = {
        "approver": "s.senior",
        "roles": (AnalystRole.SENIOR_ANALYST,),
        "severity": Severity.HIGH,
        "identity_verified": True,
        "authentication_required": True,
    }
    return ApprovalContext(**{**base, **overrides})


class TestRoleResolution:
    def test_groups_map_to_roles(self):
        assert roles_from_groups("soc-senior") == (AnalystRole.SENIOR_ANALYST,)
        assert roles_from_groups(["soc-analyst", "soc-viewer"]) == (
            AnalystRole.ANALYST,
            AnalystRole.VIEWER,
        )

    def test_unrecognised_groups_grant_nothing(self):
        """A group that means nothing here must not be guessed at."""
        assert roles_from_groups("engineering,everyone") == ()
        assert roles_from_groups(None) == ()

    def test_strongest_role_wins(self):
        authority = effective_authority([AnalystRole.VIEWER, AnalystRole.SENIOR_ANALYST])
        assert authority is not None
        assert authority.role is AnalystRole.SENIOR_ANALYST

    def test_identity_carries_groups_from_the_proxy(self):
        identity = resolve_identity(
            {"X-Forwarded-User": "a.analyst", "X-Forwarded-Groups": "soc-analyst,soc-viewer"}
        )
        assert identity is not None
        assert roles_from_groups(list(identity.groups)) == (
            AnalystRole.ANALYST,
            AnalystRole.VIEWER,
        )


class TestApprovalAuthority:
    def test_a_senior_analyst_may_approve(self):
        assert authorize_approval(_context()).allowed

    def test_a_viewer_may_not_approve(self):
        decision = authorize_approval(_context(roles=(AnalystRole.VIEWER,)))
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-002-role-may-not-approve"

    def test_no_role_means_no_authority(self):
        decision = authorize_approval(_context(roles=()))
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-001-no-role"

    def test_analyst_cannot_approve_above_their_severity_ceiling(self):
        decision = authorize_approval(
            _context(roles=(AnalystRole.ANALYST,), severity=Severity.CRITICAL)
        )
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-004-severity-ceiling"

    def test_analyst_cannot_approve_a_disruptive_action(self):
        """Signing a ticket and isolating a host are not the same act."""
        decision = authorize_approval(
            _context(
                roles=(AnalystRole.ANALYST,),
                severity=Severity.MEDIUM,
                action_risks=(ActionRisk.DISRUPTIVE,),
            )
        )
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-005-action-risk-ceiling"

    def test_analyst_cannot_approve_on_a_critical_asset(self):
        decision = authorize_approval(
            _context(roles=(AnalystRole.ANALYST,), severity=Severity.MEDIUM, asset_is_critical=True)
        )
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-006-critical-asset"

    def test_senior_analyst_may_do_all_of_the_above(self):
        assert authorize_approval(
            _context(
                severity=Severity.CRITICAL,
                action_risks=(ActionRisk.DISRUPTIVE,),
                asset_is_critical=True,
            )
        ).allowed


class TestSeparationOfDuties:
    def test_the_initiator_may_not_approve_their_own_run(self):
        decision = authorize_approval(_context(approver="s.senior", initiated_by="s.senior"))
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-003-separation-of-duties"

    def test_someone_else_may(self):
        assert authorize_approval(_context(approver="s.senior", initiated_by="a.other")).allowed

    def test_it_holds_even_without_a_verified_identity(self):
        """It compares two names rather than trusting a claim of privilege.

        That makes it the one authorization rule still worth something when the
        identity is self-asserted, so it must not be skipped in local mode.
        """
        decision = authorize_approval(
            _context(
                approver="cli-analyst",
                initiated_by="cli-analyst",
                identity_verified=False,
                authentication_required=False,
            )
        )
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-003-separation-of-duties"


class TestUnverifiedIdentities:
    def test_unverified_approval_is_refused_when_authentication_is_required(self):
        decision = authorize_approval(_context(identity_verified=False))
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-008-unverified-identity"

    def test_role_ceilings_are_not_enforced_in_local_mode(self):
        """They would be self-granted, so enforcing them would be theatre.

        The decision is still recorded as unauthenticated in the audit trail,
        which is the honest signal.
        """
        decision = authorize_approval(
            _context(
                roles=(),
                severity=Severity.CRITICAL,
                identity_verified=False,
                authentication_required=False,
            )
        )
        assert decision.allowed
        assert decision.rule_id == "AUTHZ-000-unauthenticated-local"


class TestTwoPersonIntegrity:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.setenv("SOC_REQUIRE_TWO_PERSON_APPROVAL", "false")
        from src.config import get_settings

        get_settings.cache_clear()
        assert required_approvals(action_risks=(ActionRisk.DISRUPTIVE,), asset_is_critical=True) == 1

    def test_two_approvers_for_disruptive_on_a_critical_asset(self, monkeypatch):
        monkeypatch.setenv("SOC_REQUIRE_TWO_PERSON_APPROVAL", "true")
        from src.config import get_settings

        get_settings.cache_clear()
        assert required_approvals(action_risks=(ActionRisk.DISRUPTIVE,), asset_is_critical=True) == 2
        # Not for lesser combinations -- the cost has to be proportional.
        assert required_approvals(action_risks=(ActionRisk.LOW_IMPACT,), asset_is_critical=True) == 1
        assert required_approvals(action_risks=(ActionRisk.DISRUPTIVE,), asset_is_critical=False) == 1

    def test_the_same_person_cannot_be_both_approvers(self):
        decision = authorize_approval(_context(approver="s.senior", prior_approvers=("s.senior",)))
        assert not decision.allowed
        assert decision.rule_id == "AUTHZ-007-duplicate-approver"


class TestAuthorizationInTheGate:
    """End to end: an unauthorised approval must not open the gate."""

    @pytest.fixture
    def graph(self, audit_logger, broker):
        return build_graph(
            checkpointer=build_memory_checkpointer(),
            broker=broker,
            audit=audit_logger,
            consult_llm=False,
        )

    def _suspended(self, graph, alert, **bootstrap):
        initial = SOCState.bootstrap(alert, offline_mode=True, **bootstrap)
        config = {"configurable": {"thread_id": initial.run.thread_id}, "recursion_limit": 50}
        graph.invoke(initial, config=config)
        assert pending_interrupt(graph, config) is not None
        return initial, config

    def test_an_unauthorised_approval_leaves_the_gate_shut(self, graph, sample_alert, audit_logger):
        initial, config = self._suspended(graph, sample_alert)

        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "j.junior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-viewer"],
                }
            ),
            config=config,
        )
        state = SOCState.model_validate(graph.get_state(config).values)

        assert state.approval_status is ApprovalStatus.PENDING
        assert state.phase is not Phase.COMPLETE
        assert state.final_report is None

    def test_the_refusal_is_audited(self, graph, sample_alert, audit_logger):
        """'Someone tried and was refused' is what a reviewer looks for."""
        initial, config = self._suspended(graph, sample_alert)

        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "j.junior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-viewer"],
                }
            ),
            config=config,
        )

        events = audit_logger.read_events(initial.run.thread_id)
        denials = [e for e in events if e.action.value == "authorization_denied"]
        assert denials
        assert denials[0].details["approver"] == "j.junior"
        assert not denials[0].success

    def test_an_authorised_approver_can_still_finish_the_run(self, graph, sample_alert):
        """The gate must reopen for someone who actually holds the authority."""
        initial, config = self._suspended(graph, sample_alert)

        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "j.junior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-viewer"],
                }
            ),
            config=config,
        )
        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "s.senior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-senior"],
                }
            ),
            config=config,
        )
        state = SOCState.model_validate(graph.get_state(config).values)

        assert state.approval_status is ApprovalStatus.APPROVED
        assert state.phase is Phase.COMPLETE

    def test_the_initiator_cannot_approve_their_own_run(self, graph, sample_alert):
        initial, config = self._suspended(graph, sample_alert, initiated_by="s.senior")

        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "s.senior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-senior"],
                }
            ),
            config=config,
        )
        state = SOCState.model_validate(graph.get_state(config).values)
        assert state.approval_status is ApprovalStatus.PENDING

    def test_repeated_refusals_halt_rather_than_spin(self, graph, sample_alert, audit_logger):
        """A caller resubmitting the same refused answer must not loop the gate.

        An automation running with --approve would otherwise re-answer the
        interrupt on every supervisor turn, filling the audit log with identical
        denials until the turn limit.
        """
        from src.graph import MAX_AUTHORIZATION_DENIALS

        initial, config = self._suspended(graph, sample_alert)

        refused = Command(
            resume={
                "approved": True,
                "decided_by": "j.junior",
                "identity_source": "proxy_header",
                "roles": ["soc-viewer"],
            }
        )
        for _ in range(MAX_AUTHORIZATION_DENIALS + 2):
            graph.invoke(refused, config=config)
            state = SOCState.model_validate(graph.get_state(config).values)
            if state.phase is Phase.HALTED:
                break

        state = SOCState.model_validate(graph.get_state(config).values)
        assert state.phase is Phase.HALTED
        assert state.approval_status is ApprovalStatus.PENDING, "a refusal is not a rejection"

        denials = [
            e for e in audit_logger.read_events(initial.run.thread_id)
            if e.action.value == "authorization_denied"
        ]
        assert len(denials) <= MAX_AUTHORIZATION_DENIALS

    def test_separation_of_duties_can_be_disabled_for_single_operator_use(
        self, graph, sample_alert, monkeypatch
    ):
        """A single-operator deployment cannot satisfy AC-5, and says so deliberately."""
        monkeypatch.setenv("SOC_REQUIRE_SEPARATION_OF_DUTIES", "false")
        from src.config import get_settings

        get_settings.cache_clear()

        initial, config = self._suspended(graph, sample_alert, initiated_by="s.senior")
        graph.invoke(
            Command(
                resume={
                    "approved": True,
                    "decided_by": "s.senior",
                    "identity_source": "proxy_header",
                    "roles": ["soc-senior"],
                }
            ),
            config=config,
        )
        state = SOCState.model_validate(graph.get_state(config).values)
        assert state.approval_status is ApprovalStatus.APPROVED

    def test_rejection_never_requires_authority(self, graph, sample_alert):
        """Refusing to act is not the dangerous direction.

        Requiring authority to say 'no' would strand runs whenever the only
        person present lacked approval rights.
        """
        initial, config = self._suspended(graph, sample_alert)

        graph.invoke(
            Command(resume={"approved": False, "decided_by": "j.junior", "roles": ["soc-viewer"]}),
            config=config,
        )
        state = SOCState.model_validate(graph.get_state(config).values)

        assert state.approval_status is ApprovalStatus.REJECTED
        assert state.final_report is not None


class TestAuthorityMatrixIsReadableAsData:
    def test_matrix_renders_every_role(self):
        rows = authority_matrix()
        assert {row["role"] for row in rows} == {role.value for role in AnalystRole}

    def test_only_the_viewer_lacks_approval_rights(self):
        rows = {row["role"]: row for row in authority_matrix()}
        assert rows["viewer"]["may_approve"] is False
        assert rows["analyst"]["may_approve"] is True

    def test_critical_asset_authority_is_reserved_to_senior_roles(self):
        rows = {row["role"]: row for row in authority_matrix()}
        assert rows["analyst"]["may_approve_critical_asset"] is False
        assert rows["senior_analyst"]["may_approve_critical_asset"] is True
