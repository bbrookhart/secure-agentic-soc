"""The labelled evaluation corpus.

Each case pairs a :class:`~src.state.SecurityAlert` with the outcome a competent
analyst would expect.  Two things are worth stating about the labels:

* **Severity is a band, not a point.**  Reasonable analysts disagree between
  "high" and "critical" on the same alert; scoring that disagreement as an error
  would measure conformity rather than correctness.  Exact-match is reported
  separately so the stricter number is still visible.
* **``should_escalate`` is a property of the alert, not of the current policy.**
  It records whether a human genuinely ought to see this incident.  Scoring the
  pipeline against the policy it already implements would be circular -- it
  would pass by construction, and it would never surface a badly-tuned rule.

The injection cases carry an extra ``heuristics_expected`` label marking whether
the pattern detector is expected to fire.  Cases where it is *not* (other
languages, mixed-script look-alikes, purely semantic manipulation) are kept in
the corpus deliberately: the claim being tested is not "the detector catches
everything", it is "a miss degrades to least privilege and the policy gate".
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from src.enums import AlertCategory, Severity
from src.state import SecurityAlert

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


class Expectation(BaseModel):
    """Ground truth for one case."""

    model_config = ConfigDict(frozen=True)

    severity_band: tuple[Severity, ...] = Field(min_length=1)
    category: AlertCategory
    should_escalate: bool
    is_injection: bool = False
    #: Only meaningful for injection cases: should the pattern detector fire?
    heuristics_expected: bool = True
    notes: str = ""


class EvalCase(BaseModel):
    """One labelled alert."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    alert: SecurityAlert
    expected: Expectation

    @property
    def group(self) -> str:
        return self.case_id.split("-", 1)[0]


def load_cases(*, only: str | None = None) -> list[EvalCase]:
    """Load every case in the corpus, optionally filtered by id substring."""
    cases: list[EvalCase] = []
    for path in sorted(CORPUS_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError(f"{path.name} must contain a JSON array of cases")
        for entry in payload:
            cases.append(EvalCase.model_validate(entry))

    seen = [case.case_id for case in cases]
    duplicates = {case_id for case_id in seen if seen.count(case_id) > 1}
    if duplicates:
        raise ValueError(f"duplicate case ids in corpus: {sorted(duplicates)}")

    if only:
        cases = [case for case in cases if only in case.case_id]
    return cases


def iter_groups(cases: list[EvalCase]) -> Iterator[tuple[str, list[EvalCase]]]:
    """Yield ``(group, cases)`` for TP / FP / INJ, in corpus order."""
    for group in sorted({case.group for case in cases}):
        yield group, [case for case in cases if case.group == group]
