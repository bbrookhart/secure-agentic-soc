"""Operating mode, single-writer enforcement, and the LLM circuit breaker.

These cover the controls for when the system itself is the problem: stopping
autonomy without a redeploy, refusing a second writer, and not spending a
timeout per node against a model server that is failing every request.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.enums import Severity
from src.security.instance_lock import InstanceLock, InstanceLockError
from src.security.operating_mode import (
    OperatingMode,
    clear_mode,
    current_mode,
    mode_file,
    set_mode,
)
from src.security.policy import PolicyEffect, PolicyInput, default_policy


@pytest.fixture(autouse=True)
def _clean_mode():
    clear_mode()
    yield
    clear_mode()


class TestOperatingMode:
    def test_default_is_normal(self):
        assert current_mode() is OperatingMode.NORMAL

    def test_the_file_overrides_configuration(self):
        """During an incident, a control needing a redeploy is not a control."""
        set_mode(OperatingMode.REVIEW_ALL)
        assert current_mode() is OperatingMode.REVIEW_ALL
        clear_mode()
        assert current_mode() is OperatingMode.NORMAL

    def test_an_unreadable_mode_fails_toward_more_review(self):
        """Guessing wrong should cost analyst time, not unattended completion."""
        mode_file().parent.mkdir(parents=True, exist_ok=True)
        mode_file().write_text("something-nobody-defined\n", encoding="utf-8")
        assert current_mode() is OperatingMode.REVIEW_ALL

    @pytest.mark.parametrize(
        ("mode", "accepts", "forces_review", "stops"),
        [
            (OperatingMode.NORMAL, True, False, False),
            (OperatingMode.REVIEW_ALL, True, True, False),
            (OperatingMode.DRAIN, False, True, False),
            (OperatingMode.HALT, False, True, True),
        ],
    )
    def test_mode_semantics(self, mode, accepts, forces_review, stops):
        assert mode.accepts_new_runs is accepts
        assert mode.forces_human_review is forces_review
        assert mode.stops_in_flight is stops

    def test_changing_the_mode_is_audited(self, audit_logger):
        set_mode(OperatingMode.HALT, reason="suspected campaign", audit=audit_logger)
        events = audit_logger.read_events("operations")
        assert events
        assert events[-1].action.value == "operating_mode_changed"
        assert events[-1].details["mode"] == "halt"
        # Narrowing autonomy is recorded as a non-success so it stands out.
        assert events[-1].success is False

    def test_returning_to_normal_is_also_audited(self, audit_logger):
        """Widening autonomy back is the change a reviewer asks about."""
        set_mode(OperatingMode.NORMAL, reason="cleared", audit=audit_logger)
        events = audit_logger.read_events("operations")
        assert events[-1].details["mode"] == "normal"


class TestModeReachesThePolicyEngine:
    def test_suspended_autonomy_gates_an_otherwise_clean_alert(self):
        decision = default_policy().evaluate(
            PolicyInput(severity=Severity.INFO, confidence=0.99, autonomy_suspended=True)
        )
        assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
        assert decision.rule_id == "HITL-000-autonomy-suspended"

    def test_it_is_reported_before_less_specific_reasons(self):
        """An analyst should be told autonomy was withdrawn, not about a threshold."""
        decision = default_policy().evaluate(
            PolicyInput(severity=Severity.CRITICAL, confidence=0.2, autonomy_suspended=True)
        )
        assert decision.rule_id == "HITL-000-autonomy-suspended"
        assert "HITL-001-high-severity" in decision.matched_rules

    def test_normal_mode_leaves_policy_alone(self):
        decision = default_policy().evaluate(
            PolicyInput(severity=Severity.LOW, confidence=0.99, autonomy_suspended=False)
        )
        assert decision.effect is PolicyEffect.ALLOW

    def test_halt_stops_an_in_flight_run(self, sample_alert):
        from src.agents.supervisor import Route, deterministic_route
        from src.security.policy import PolicyDecision
        from src.state import SOCState

        set_mode(OperatingMode.HALT)
        state = SOCState.bootstrap(sample_alert, offline_mode=True)
        allow = PolicyDecision(effect=PolicyEffect.ALLOW, rule_id="ALLOW-000", reason="")

        decision = deterministic_route(state, allow)
        assert decision.route is Route.HALT
        assert decision.rule_id == "R-004"


class TestInstanceLock:
    def test_a_second_instance_is_refused(self, tmp_path: Path):
        first = InstanceLock(tmp_path / ".lock")
        first.acquire()
        try:
            with pytest.raises(InstanceLockError, match="another instance"):
                InstanceLock(tmp_path / ".lock").acquire()
        finally:
            first.release()

    def test_the_message_explains_the_consequence(self, tmp_path: Path):
        """'Already locked' is not actionable; saying what breaks is."""
        first = InstanceLock(tmp_path / ".lock")
        first.acquire()
        try:
            with pytest.raises(InstanceLockError) as excinfo:
                InstanceLock(tmp_path / ".lock").acquire()
            message = str(excinfo.value)
            assert "rate limit" in message
            assert "audit chain" in message
        finally:
            first.release()

    def test_the_lock_is_reusable_after_release(self, tmp_path: Path):
        """A crashed process must not leave the system unstartable."""
        first = InstanceLock(tmp_path / ".lock")
        first.acquire()
        first.release()

        second = InstanceLock(tmp_path / ".lock")
        second.acquire()
        second.release()

    def test_it_records_who_holds_it(self, tmp_path: Path):
        lock = InstanceLock(tmp_path / ".lock")
        lock.acquire()
        try:
            assert "pid=" in (tmp_path / ".lock").read_text(encoding="utf-8")
        finally:
            lock.release()


class TestCircuitBreaker:
    def setup_method(self):
        from src.llm import reset_breaker

        reset_breaker()

    def teardown_method(self):
        from src.llm import reset_breaker

        reset_breaker()

    def test_it_opens_after_repeated_failures(self):
        from src.llm import _breaker_is_open, _breaker_record

        assert not _breaker_is_open()
        for _ in range(3):
            _breaker_record(ok=False)
        assert _breaker_is_open()

    def test_a_success_closes_it(self):
        from src.llm import _breaker_is_open, _breaker_record

        for _ in range(3):
            _breaker_record(ok=False)
        _breaker_record(ok=True)
        assert not _breaker_is_open()

    def test_an_open_breaker_reports_the_model_unavailable(self, monkeypatch):
        """The point: fall to the deterministic path now, not after a timeout."""
        monkeypatch.setenv("SOC_OFFLINE_MODE", "false")
        from src.config import get_settings

        get_settings.cache_clear()

        from src.llm import _breaker_record, is_available

        for _ in range(3):
            _breaker_record(ok=False)
        assert is_available(force=True) is False

    def test_it_reopens_after_the_cooldown(self, monkeypatch):
        import src.llm as llm

        for _ in range(3):
            llm._breaker_record(ok=False)
        assert llm._breaker_is_open()

        # Half-open once the cooldown has passed.
        monkeypatch.setattr(llm, "_breaker_opened_at", 0.0)
        monkeypatch.setattr(llm.time, "monotonic", lambda: llm._BREAKER_COOLDOWN_SECONDS + 1)
        assert not llm._breaker_is_open()
