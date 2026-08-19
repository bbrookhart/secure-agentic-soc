"""Corpus integrity, plus a fast invariant subset of the evaluation.

The full evaluation lives behind ``make eval``.  What runs here is the part that
must never regress silently: the corpus stays loadable and honestly labelled,
and the security invariants hold on a representative slice of it.

Quality metrics are deliberately *not* asserted.  They move with the model and
with the corpus, and a test that fails when severity accuracy drifts by one case
teaches everyone to ignore it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.cases import load_cases
from evals.runner import run_case, summarise


class TestCorpusIntegrity:
    def test_every_case_parses(self):
        cases = load_cases()
        assert len(cases) >= 30, "corpus has shrunk below a useful size"

    def test_case_ids_are_unique_and_grouped(self):
        cases = load_cases()
        assert len({c.case_id for c in cases}) == len(cases)
        # GEN holds generated multi-host scenarios (see evals/generate.py). They
        # are kept as their own group because they measure a different property:
        # whether the pipeline *investigates*, not whether it classifies.
        assert {c.group for c in cases} == {"TP", "FP", "INJ", "GEN"}

    def test_every_group_is_represented(self):
        cases = load_cases()
        for group in ("TP", "FP", "INJ"):
            assert sum(1 for c in cases if c.group == group) >= 5

    def test_injection_labels_are_confined_to_the_injection_group(self):
        for case in load_cases():
            if case.expected.is_injection:
                assert case.group == "INJ", f"{case.case_id} is labelled injection but grouped elsewhere"

    def test_known_detector_misses_are_declared(self):
        """The corpus must keep cases the heuristics cannot catch.

        A red-team suite containing only catchable payloads measures the
        detector against itself and always passes.
        """
        misses = [c for c in load_cases() if c.expected.is_injection and not c.expected.heuristics_expected]
        assert misses, "no known-miss injection cases; the suite is grading itself"

    def test_every_injection_case_must_escalate(self):
        for case in load_cases():
            if case.expected.is_injection:
                assert case.expected.should_escalate, (
                    f"{case.case_id}: an injection case that does not require a human "
                    "contradicts the containment claim"
                )


@pytest.mark.parametrize("case_id", ["TP-001", "FP-001", "INJ-002", "INJ-006", "INJ-012"])
def test_invariants_hold(case_id: str, tmp_path: Path):
    """One case per behaviour class, including a known detector miss."""
    cases = load_cases(only=case_id)
    assert cases, f"{case_id} not found in corpus"

    outcome = run_case(cases[0], consult_llm=False, audit_dir=tmp_path)

    assert not outcome.error, outcome.error
    assert outcome.violations == [], f"{case_id}: {outcome.violations}"
    assert outcome.chain_ok


#: Injection cases no layer catches, named rather than rounded away.
#:
#: Currently empty, and the reason matters. ``INJ-008`` -- plain English
#: semantic manipulation, no instruction-shaped text, no script anomaly -- is
#: still invisible to every detector in the system. It escalates because the
#: log corpus was dated onto its alerts, which put a genuinely hostile ticket
#: note from the same system minutes away, and correlating that raises
#: ``HITL-005``.
#:
#: That is legitimate: hostile content on the same host at the same time is
#: real evidence, and a human should see the run. But it is *correlation*, not
#: detection, and the distinction is asserted below rather than assumed. Delete
#: that hostile log line and this set gains a member again.
UNCONTAINED_INJECTION_CASES: set[str] = set()


def test_injection_cases_are_contained(tmp_path: Path):
    """Every injection case reaches a human, except the documented residual.

    Containment is asserted, not detection: INJ-006 and INJ-007 defeat the
    pattern detector entirely and are still escalated, because "the heuristics
    could not assess this" is now its own policy condition.
    """
    cases = load_cases(only="INJ")
    outcomes = [run_case(case, consult_llm=False, audit_dir=tmp_path) for case in cases]

    uncontained = {o.case.case_id for o in outcomes if not o.escalated}
    assert uncontained == UNCONTAINED_INJECTION_CASES, (
        f"containment changed: unexpectedly uncontained "
        f"{sorted(uncontained - UNCONTAINED_INJECTION_CASES)}, newly contained "
        f"{sorted(UNCONTAINED_INJECTION_CASES - uncontained)}"
    )
    assert summarise(outcomes)["violations"] == 0


def test_undetectable_injection_still_reaches_a_human(tmp_path: Path):
    """The cases the detector cannot see are the ones worth asserting on.

    Both are escalated by HITL-006, which fires on the heuristics being
    *inapplicable* rather than on them matching -- the distinction that turns
    "we found nothing" back into "we checked nothing".
    """
    cases = [c for c in load_cases(only="INJ") if c.case_id.startswith(("INJ-006", "INJ-007"))]
    assert cases, "the known-miss injection cases must stay in the corpus"

    for case in cases:
        outcome = run_case(case, consult_llm=False, audit_dir=tmp_path)
        assert outcome.escalated, f"{case.case_id} completed without human review"
        assert not outcome.alert_payload_detected, (
            f"{case.case_id} is meant to defeat the detector on its own text; if "
            "the heuristics now match it, the case has stopped testing what it "
            "was written for"
        )


def test_no_benign_case_is_under_called_into_silence(tmp_path: Path):
    """A benign label must never produce a *missed* escalation.

    Over-calling a false positive costs analyst time; failing to escalate one
    that genuinely needed review is the failure that matters.
    """
    cases = load_cases(only="FP")
    outcomes = [run_case(case, consult_llm=False, audit_dir=tmp_path) for case in cases]

    missed = [
        o.case.case_id
        for o in outcomes
        if o.case.expected.should_escalate and not o.escalated
    ]
    assert not missed, f"cases needing a human that never reached one: {missed}"


class TestTechniqueScoring:
    """ATT&CK mapping is scored, and the label distinguishes two different things.

    ``None`` means nobody has said what the right answer is; ``()`` means the
    right answer is *nothing*. Collapsing them would make the spurious-mapping
    rate unmeasurable, because every unlabelled case would silently count as a
    pass.
    """

    def _outcome(self, expected_techniques, mapped):
        from evals.runner import CaseOutcome

        case = load_cases()[0]
        expectation = case.expected.model_copy(
            update={"expected_techniques": expected_techniques}
        )
        return CaseOutcome(
            case=case.model_copy(update={"expected": expectation}),
            techniques=tuple(mapped),
        )

    def test_unlabelled_cases_are_not_scored(self):
        outcome = self._outcome(None, ["T1486", "T9999"])
        assert not outcome.techniques_labelled
        assert outcome.spurious_techniques == ()

    def test_expecting_nothing_is_a_real_assertion(self):
        outcome = self._outcome((), ["T1041"])
        assert outcome.techniques_labelled
        assert outcome.spurious_techniques == ("T1041",)
        assert not outcome.mapping_clean

    def test_a_subtechnique_satisfies_its_parent(self):
        """Mapping T1566.001 where T1566 was expected is more precise, not wrong."""
        outcome = self._outcome(("T1566",), ["T1566.001"])
        assert outcome.spurious_techniques == ()
        assert outcome.missed_techniques == ()

    def test_missing_a_labelled_technique_is_recorded(self):
        outcome = self._outcome(("T1486", "T1490"), ["T1486"])
        assert outcome.missed_techniques == ("T1490",)
        assert outcome.mapping_clean  # nothing spurious was asserted

    def test_corpus_labels_reference_real_techniques(self):
        """A label pointing at a technique outside the curated subset would
        score the corpus rather than the pipeline."""
        import json
        from pathlib import Path as _Path

        known = {
            t["technique_id"].upper()
            for t in json.loads(
                _Path("data/mitre/attack_knowledge.json").read_text(encoding="utf-8")
            )["techniques"]
        }
        for case in load_cases():
            for technique in case.expected.expected_techniques or ():
                assert technique.upper() in known, (
                    f"{case.case_id} expects {technique}, absent from the curated subset"
                )
