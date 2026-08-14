"""State schema, immutability and transition-validation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.enums import ApprovalStatus, Severity
from src.state import (
    ALLOWED_TRANSITIONS,
    ApprovalDecision,
    InvalidStateTransition,
    Phase,
    ProposedAction,
    SOCState,
    validate_transition,
)


class TestAlertImmutability:
    def test_alert_is_frozen(self, sample_alert):
        with pytest.raises(ValidationError):
            sample_alert.title = "rewritten by an agent"

    def test_fingerprint_is_stable(self, sample_alert):
        assert sample_alert.fingerprint() == sample_alert.fingerprint()

    def test_fingerprint_changes_with_content(self, sample_alert):
        altered = sample_alert.model_copy(update={"title": "different"})
        assert altered.fingerprint() != sample_alert.fingerprint()

    def test_state_rejects_swapped_alert(self, sample_alert):
        """The run's fingerprint pins the evidence for the whole investigation.

        `validate_assignment=True` means an agent cannot quietly substitute a
        softened version of the alert it was asked to analyse.
        """
        state = SOCState.bootstrap(sample_alert)
        substitute = sample_alert.model_copy(update={"title": "Nothing to see here"})

        with pytest.raises(ValidationError, match="fingerprint mismatch"):
            state.alert = substitute

    def test_critical_asset_detected(self, sample_alert, benign_alert):
        assert sample_alert.has_critical_asset is True
        assert benign_alert.has_critical_asset is False


class TestPhaseTransitions:
    def test_legal_transition(self):
        validate_transition(Phase.INGESTED, Phase.TRIAGING)
        validate_transition(Phase.TRIAGING, Phase.TRIAGED)
        validate_transition(Phase.ENRICHED, Phase.AWAITING_APPROVAL)

    def test_illegal_transition_rejected(self):
        with pytest.raises(InvalidStateTransition):
            validate_transition(Phase.INGESTED, Phase.COMPLETE)

    def test_cannot_skip_triage_to_report(self):
        with pytest.raises(InvalidStateTransition):
            validate_transition(Phase.INGESTED, Phase.REPORTING)

    def test_terminal_phases_have_no_exits(self):
        assert ALLOWED_TRANSITIONS[Phase.COMPLETE] == frozenset()
        assert ALLOWED_TRANSITIONS[Phase.HALTED] == frozenset()

    def test_self_transition_allowed(self):
        validate_transition(Phase.TRIAGING, Phase.TRIAGING)

    def test_approval_cannot_be_bypassed(self):
        """From AWAITING_APPROVAL the only exits are a decision or a halt."""
        allowed = ALLOWED_TRANSITIONS[Phase.AWAITING_APPROVAL]
        assert Phase.REPORTING not in allowed
        assert Phase.COMPLETE not in allowed
        assert allowed == frozenset({Phase.APPROVED, Phase.REJECTED, Phase.HALTED})


class TestStateInvariants:
    def test_pending_approval_blocks_completion(self, sample_alert):
        state = SOCState.bootstrap(sample_alert)
        with pytest.raises(ValidationError, match="pending"):
            SOCState.model_validate(
                {
                    **state.model_dump(),
                    "approval_status": ApprovalStatus.PENDING,
                    "phase": Phase.COMPLETE,
                }
            )

    def test_approved_status_requires_a_decision(self, sample_alert):
        state = SOCState.bootstrap(sample_alert)
        with pytest.raises(ValidationError, match="no ApprovalDecision"):
            SOCState.model_validate(
                {**state.model_dump(), "approval_status": ApprovalStatus.APPROVED}
            )

    def test_status_must_match_decision(self, sample_alert):
        state = SOCState.bootstrap(sample_alert)
        with pytest.raises(ValidationError, match="contradicts"):
            SOCState.model_validate(
                {
                    **state.model_dump(),
                    "approval_status": ApprovalStatus.APPROVED,
                    "approval_decision": ApprovalDecision(approved=False).model_dump(),
                }
            )

    def test_report_requires_triage(self, sample_alert):
        from src.enums import Verdict
        from src.state import IncidentReport

        state = SOCState.bootstrap(sample_alert)
        report = IncidentReport(
            title="t", executive_summary="s" * 30, verdict=Verdict.INCONCLUSIVE,
            severity=Severity.LOW, confidence=0.5,
        )
        with pytest.raises(ValidationError, match="without a triage_result"):
            SOCState.model_validate({**state.model_dump(), "final_report": report.model_dump()})


class TestProposedAction:
    def test_execution_mode_is_pinned(self):
        from src.enums import ActionRisk

        with pytest.raises(ValidationError):
            ProposedAction(
                title="Isolate host",
                description="d",
                risk=ActionRisk.DISRUPTIVE,
                target="SRV-01",
                execution_mode="execute_now",
            )

    def test_default_is_proposal_only(self):
        from src.enums import ActionRisk

        action = ProposedAction(
            title="Isolate host", description="d", risk=ActionRisk.DISRUPTIVE, target="SRV-01"
        )
        assert action.execution_mode == "proposal_only"


class TestSeverityOrdering:
    def test_rank_ordering_is_not_lexicographic(self):
        """'critical' < 'low' alphabetically; rank must not be fooled by that."""
        assert Severity.CRITICAL.rank > Severity.LOW.rank

    def test_at_least(self):
        from src.enums import at_least

        assert at_least(Severity.CRITICAL, Severity.HIGH)
        assert at_least(Severity.HIGH, Severity.HIGH)
        assert not at_least(Severity.MEDIUM, Severity.HIGH)
