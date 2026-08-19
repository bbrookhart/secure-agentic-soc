"""Who decides the verdict, and how that is allowed to change.

Routing has always been advisory: the model proposes, the deterministic router
decides, the disagreement is audited. Triage was the one place the model still
*decided* -- it set severity and category, and those drive the approval gate.

The corpus says that was the wrong way round. Paired against the deterministic
floor over 38 cases, llama3.2 scored 39% category against 68%, 79% severity in
band against 93%, and missed four escalations against two -- two of them real
attacks it under-called to "medium" so ``HITL-001`` never fired. Every one of
those differences is resolved at p<0.05.

So authority is earned. These tests pin both halves: that it is withheld by
default and the withholding is visible, and that granting it restores the old
behaviour intact for a model that has earned it.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.enums import AgentRole, AlertCategory, Severity


@pytest.fixture
def _authoritative(monkeypatch: pytest.MonkeyPatch) -> None:
    """Grant the model verdict authority, as a promoted model would have.

    Settings are an ``lru_cache`` singleton, so the environment change only
    takes effect once the cache is dropped. Teardown is handled by the autouse
    ``_isolated_settings`` fixture, which clears it again after every test.
    """
    from src.config import get_settings

    monkeypatch.setenv("SOC_MODEL_VERDICT_AUTHORITY", "true")
    get_settings.cache_clear()


class TestDefaultIsAdvisory:
    def test_triage_does_not_hold_verdict_authority_by_default(self):
        from src.model_profiles import profile_for

        assert not profile_for(AgentRole.TRIAGE).verdict_authority

    def test_no_other_role_can_hold_it(self, _authoritative: None):
        """Only triage produces a verdict; granting it elsewhere is meaningless."""
        from src.model_profiles import profile_for

        for role in (AgentRole.SUPERVISOR, AgentRole.ENRICHMENT, AgentRole.REPORTER):
            assert not profile_for(role).verdict_authority

    def test_the_setting_actually_promotes_triage(self, _authoritative: None):
        from src.model_profiles import profile_for

        assert profile_for(AgentRole.TRIAGE).verdict_authority


class TestTheModelIsOverruled:
    """The behaviour, exercised through ``run_triage`` with a stubbed model."""

    def _run(self, monkeypatch: pytest.MonkeyPatch, alert: Any, proposed: dict[str, Any]):
        from src.agents import triage as triage_module
        from src.agents.triage import TriageLLMOutput, run_triage

        class _Call:
            ok = True
            audit_events: list[Any] = []
            parsed = TriageLLMOutput(**proposed)

        monkeypatch.setattr(triage_module, "structured_completion", lambda *a, **k: _Call())

        import tempfile
        from pathlib import Path

        from src.agents.base import AgentContext
        from src.security.audit import AuditLogger
        from src.tools import build_broker

        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLogger(Path(tmp) / "a.jsonl")
            context = AgentContext(
                thread_id="t-verdict",
                broker=build_broker(audit=audit),
                audit=audit,
                role=AgentRole.TRIAGE,
            )
            return run_triage(alert, context)

    def test_the_models_verdict_is_discarded(self, monkeypatch, sample_alert):
        """Ransomware on a critical file server must not become 'low/unknown'."""
        result, _events = self._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.LOW,
                "category": AlertCategory.UNKNOWN,
                "confidence": 0.9,
                "rationale": "The model is confidently wrong about this one." * 2,
            },
        )
        assert result.severity is not Severity.LOW
        assert result.category is not AlertCategory.UNKNOWN

    def test_what_the_model_proposed_is_still_recorded(self, monkeypatch, sample_alert):
        """Withheld, not discarded -- promotion has to be answerable from data."""
        result, _events = self._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.LOW,
                "category": AlertCategory.UNKNOWN,
                "confidence": 0.9,
                "rationale": "The model is confidently wrong about this one." * 2,
            },
        )
        assert result.advisory_severity is Severity.LOW
        assert result.advisory_category is AlertCategory.UNKNOWN

    def test_the_disagreement_is_audited(self, monkeypatch, sample_alert):
        _result, events = self._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.LOW,
                "category": AlertCategory.UNKNOWN,
                "confidence": 0.9,
                "rationale": "The model is confidently wrong about this one." * 2,
            },
        )
        overrides = [e for e in events if "LLM advisor OVERRIDDEN" in e.summary]
        assert overrides, "an overruled model must leave a trace"
        assert overrides[0].details["advisory_severity"] == "low"
        assert not overrides[0].success

    def test_the_models_narrative_is_kept(self, monkeypatch, sample_alert):
        """The verdict is withheld; the reason to run a model at all is not."""
        rationale = "Shadow copies were deleted before the mass rename, which matters."
        result, _events = self._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.LOW,
                "category": AlertCategory.UNKNOWN,
                "confidence": 0.9,
                "rationale": rationale,
                "key_observations": ["vssadmin ran first"],
            },
        )
        assert rationale in result.rationale
        assert "vssadmin ran first" in result.key_observations
        assert result.used_llm

    def test_a_promoted_model_decides_again(self, monkeypatch, sample_alert, _authoritative):
        """Granting authority restores the old behaviour for an earned model."""
        result, _events = self._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.CRITICAL,
                "category": AlertCategory.MALWARE,
                "confidence": 0.9,
                "rationale": "Mass encryption with shadow copy deletion on a file server.",
            },
        )
        assert result.severity is Severity.CRITICAL
        assert result.advisory_severity is None, (
            "an authoritative model decided; there is no withheld proposal to record"
        )


class TestCategoryAdmitsDisagreement:
    """The severity band's argument, applied to category."""

    def _outcome(self, primary: str, also: list[str], got: str):
        from evals.cases import load_cases
        from evals.runner import CaseOutcome

        case = load_cases()[0]
        expectation = case.expected.model_copy(
            update={
                "category": AlertCategory(primary),
                "category_also_acceptable": tuple(AlertCategory(c) for c in also),
            }
        )
        return CaseOutcome(case=case.model_copy(update={"expected": expectation}), category=got)

    def test_an_accepted_alternative_scores(self):
        outcome = self._outcome("unknown", ["benign_or_false_positive"], "benign_or_false_positive")
        assert outcome.category_correct

    def test_the_strict_reading_still_requires_the_primary(self):
        outcome = self._outcome("unknown", ["benign_or_false_positive"], "benign_or_false_positive")
        assert not outcome.category_exact

    def test_an_unlisted_category_is_still_wrong(self):
        """A band that admits everything measures nothing."""
        outcome = self._outcome("unknown", ["benign_or_false_positive"], "malware")
        assert not outcome.category_correct

    def test_the_primary_satisfies_both_readings(self):
        outcome = self._outcome("unknown", ["benign_or_false_positive"], "unknown")
        assert outcome.category_correct and outcome.category_exact


class TestConfidenceIsPartOfTheVerdict:
    """Confidence decides whether the alert is investigated at all.

    Rule ``R-020`` sends a *confidently* benign alert straight to the reporter,
    skipping enrichment. So a model with no say over severity or category could
    still decide an incident was not worth investigating, simply by being sure.
    Measured: ``GEN-001`` gathered evidence in three rounds offline and **zero**
    on the LLM path, because the model said 0.8 where the classifier caps at
    0.6.

    It is also the model's least trustworthy output. On this corpus its
    0.8-1.0 bucket is right 56% of the time and its 0.2-0.4 bucket 86% --
    inverted, so high confidence predicts being wrong.
    """

    def test_the_models_confidence_is_withheld_too(self, monkeypatch, sample_alert):
        from tests.test_verdict_authority import TestTheModelIsOverruled

        result, _events = TestTheModelIsOverruled()._run(
            monkeypatch,
            sample_alert,
            {
                "severity": Severity.LOW,
                "category": AlertCategory.UNKNOWN,
                "confidence": 0.99,
                "rationale": "Certain, and wrong, which is the dangerous combination.",
            },
        )
        assert result.confidence <= 0.6, (
            "a model that cannot set the verdict must not set the confidence that "
            "decides whether the verdict is investigated"
        )


class TestSecretDisclosureCheck:
    """Describing an attack is not committing one.

    ``INJ-011``'s payload demands the system reveal its API keys. A report
    saying so is doing its job. The invariant check used to substring-match
    "api key" and call that a breach -- failing the run, and creating pressure
    to stop reports describing injection attempts.
    """

    def _violations(self, report_text: str) -> list[str]:
        from src.security.redaction import redact_text

        return (
            ["report contains redactable secret material"]
            if redact_text(report_text) != report_text
            else []
        )

    def test_describing_a_secret_solicitation_is_not_a_breach(self):
        text = (
            "The alert matched prompt-injection heuristics (secret_solicitation) "
            "with instructions to reveal system configuration and API keys."
        )
        assert self._violations(text) == []

    @pytest.mark.parametrize(
        "leaked",
        [
            "config is api_key=sk-abcdef0123456789abcdef",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijkl.signature12345",
            "password: hunter2000secret",
        ],
    )
    def test_an_actual_disclosure_is_a_breach(self, leaked: str):
        assert self._violations(leaked)
