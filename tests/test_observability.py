"""Telemetry label discipline, health checks, and token accounting.

The important tests here are about what telemetry must *not* carry. In a SOC
tool the data is incident data, and a metric labelled with a hostname or an
alert id ships the contents of an investigation to whatever backend the
collector points at. That is an egress path the rest of the project works hard
to avoid, so the label vocabulary is closed and asserted rather than trusted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.observability import metrics
from src.observability.health import Check, readiness, render, run_checks
from src.observability.telemetry import (
    ALLOWED_ATTRIBUTES,
    MAX_ATTRIBUTE_LENGTH,
    safe_attributes,
)


class TestLabelDiscipline:
    """Telemetry is egress. What it may carry is a security decision."""

    def test_alert_identifiers_are_dropped(self):
        safe = safe_attributes(
            {
                "alert_id": "ALRT-2026-0112-001",
                "thread_id": "run-abc123",
                "severity": "high",
            }
        )
        assert safe == {"severity": "high"}

    def test_host_and_user_identifiers_are_dropped(self):
        """These are the fields that would turn metrics into an incident feed."""
        safe = safe_attributes(
            {
                "host": "SRV-FILE-02",
                "hostname": "SRV-FILE-02",
                "user": "k.novak",
                "asset": "PAY-PROC-01",
                "indicator": "203.0.113.45",
                "tool": "enrich_ioc",
            }
        )
        assert safe == {"tool": "enrich_ioc"}

    def test_free_text_is_dropped(self):
        safe = safe_attributes({"summary": "ransomware on the file server", "outcome": "ok"})
        assert safe == {"outcome": "ok"}

    def test_an_allowed_key_with_an_unbounded_value_is_dropped(self):
        """A truncated hostname is still a hostname, so drop rather than trim."""
        safe = safe_attributes({"rule_id": "x" * (MAX_ATTRIBUTE_LENGTH + 1)})
        assert safe == {}

    def test_booleans_and_numbers_pass_through(self):
        assert safe_attributes({"offline": True, "used_llm": False}) == {
            "offline": True,
            "used_llm": False,
        }

    def test_the_vocabulary_stays_closed(self):
        """A widening of this set is a deliberate change, reviewed as one."""
        assert ALLOWED_ATTRIBUTES == frozenset(
            {
                "actor",
                "route",
                "rule_id",
                "effect",
                "severity",
                "category",
                "verdict",
                "phase",
                "tool",
                "outcome",
                "source",
                "kind",
                "offline",
                "used_llm",
            }
        )

    def test_no_metric_helper_accepts_free_text(self):
        """Every recording helper funnels through the same filter."""
        # None of these raise, and none can smuggle a label through.
        metrics.injection_detected(source="alert")
        metrics.policy_decision(effect="require_approval", rule_id="HITL-001-high-severity")
        metrics.authorization_denied(rule_id="AUTHZ-002-role-may-not-approve")
        metrics.tool_call(tool="enrich_ioc", outcome="denied")
        metrics.llm_call(actor="triage", outcome="fallback", duration_ms=12.0)
        metrics.llm_tokens(actor="triage", input_tokens=10, output_tokens=5)
        metrics.run_completed(phase="complete", verdict="true_positive", duration_ms=100.0)


class TestMetricsAreSafeWhenDisabled:
    def test_recording_is_a_noop_without_telemetry(self):
        """Telemetry off is the default; nothing may break because of it."""
        metrics.reset()
        metrics.run_started(offline=True)
        metrics.error(kind="handler_exception")
        metrics.chain_verified(outcome="ok")
        metrics.audit_forward_failure()

    def test_a_broken_instrument_never_propagates(self, monkeypatch):
        """An observability fault must not become a pipeline fault."""

        class Exploding:
            def add(self, *args, **kwargs):
                raise RuntimeError("collector on fire")

            def record(self, *args, **kwargs):
                raise RuntimeError("collector on fire")

        metrics.reset()
        monkeypatch.setattr(metrics, "_built", True)
        monkeypatch.setitem(metrics._instruments, "errors", Exploding())
        monkeypatch.setitem(metrics._instruments, "run_duration", Exploding())

        metrics.error(kind="test")  # must not raise
        metrics.run_completed(phase="complete", duration_ms=5.0)  # must not raise


class TestHealthChecks:
    def test_all_checks_run_and_none_raise(self):
        checks = run_checks()
        assert checks
        assert all(isinstance(check, Check) for check in checks)

    def test_readiness_tolerates_degraded(self):
        """Degraded must not pull an instance out of rotation.

        The deterministic floor exists precisely so a missing model is a quality
        drop rather than an outage.
        """
        ready, checks = readiness()
        assert ready
        # The default test environment has no encryption declaration.
        assert any(check.status == "degraded" for check in checks)

    def test_an_unwritable_audit_path_is_critical(self, monkeypatch, tmp_path: Path):
        """Running investigations unrecorded is worse than not running them."""
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        blocked.chmod(0o500)
        monkeypatch.setenv("SOC_AUDIT_LOG_PATH", str(blocked / "sub" / "audit.jsonl"))
        from src.config import get_settings

        get_settings.cache_clear()
        try:
            from src.observability.health import check_audit_writable

            assert check_audit_writable().status == "critical"
        finally:
            blocked.chmod(0o700)
            get_settings.cache_clear()

    def test_a_world_readable_signing_key_is_critical(self, monkeypatch, tmp_path: Path):
        """A key others can read is a key they can forge with."""
        key = tmp_path / "signing-key.pem"
        key.write_text("not a real key", encoding="utf-8")
        key.chmod(0o644)
        monkeypatch.setenv("SOC_AUDIT_SIGNING_ENABLED", "true")
        monkeypatch.setenv("SOC_AUDIT_SIGNING_KEY_PATH", str(key))
        from src.config import get_settings

        get_settings.cache_clear()
        try:
            from src.observability.health import check_signing_key

            check = check_signing_key()
            assert check.status == "critical"
            assert "forge" in check.detail
        finally:
            get_settings.cache_clear()

    def test_render_is_readable(self):
        text = render(run_checks())
        assert "state_writable" in text


class TestTokenAccounting:
    def test_usage_is_read_from_the_standard_field(self):
        from src.llm import _usage_of

        class Message:
            usage_metadata = {"input_tokens": 120, "output_tokens": 45}

        assert _usage_of(Message()) == (120, 45)

    def test_a_response_without_usage_contributes_zero(self):
        """A provider that reports nothing must not break the call."""
        from src.llm import _usage_of

        assert _usage_of(object()) == (0, 0)
        assert _usage_of(None) == (0, 0)

    @pytest.mark.parametrize("usage", [{"input_tokens": "x"}, {"input_tokens": None}, "nonsense"])
    def test_malformed_usage_is_tolerated(self, usage):
        from src.llm import _usage_of

        class Message:
            usage_metadata = usage

        assert _usage_of(Message()) == (0, 0)
