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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from src.enums import AlertCategory, Severity
from src.state import SecurityAlert

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


#: Where an injection payload enters the system. The distinction is the whole
#: point of the trust-boundary design, and scoring it in aggregate hides the
#: only interesting question: which boundary was actually tested?
#:
#: ``alert`` is text a reporter submitted -- attacker-influenced, but it arrives
#: through the front door and triage sees it directly. The rest arrive in *tool
#: output*, after the pipeline decided to go looking: a poisoned intel note, a
#: tampered ATT&CK description, a hostile log line, a prior case summary. Those
#: are the channels an attacker can reach without filing a ticket, and they are
#: read by an agent that has already accepted the surrounding evidence as real.
InjectionChannel = Literal["alert", "intel", "mitre", "logs", "case_history"]


class Expectation(BaseModel):
    """Ground truth for one case."""

    model_config = ConfigDict(frozen=True)

    severity_band: tuple[Severity, ...] = Field(min_length=1)
    category: AlertCategory
    #: Categories a competent analyst could also defend for this alert.
    #:
    #: The same argument the severity band rests on, applied to the axis that
    #: needed it just as much. A service-desk ticket whose only content is a
    #: manipulation attempt is genuinely both "unknown" (nothing was
    #: determined) and "benign_or_false_positive" (as an *alert* there is
    #: nothing here) -- and the classifier itself splits between the two across
    #: near-identical cases.
    #:
    #: Scoring one of those as an error measures conformity, not correctness.
    #: The alternative -- relabelling to whatever the system currently says --
    #: was checked and rejected: it would have fixed seven cases and broken
    #: three, by moving ground truth toward the majority output.
    #:
    #: Strict accuracy (primary only) is reported alongside, so the harder
    #: number stays visible exactly as it does for severity.
    category_also_acceptable: tuple[AlertCategory, ...] = ()
    should_escalate: bool
    is_injection: bool = False
    #: Only meaningful for injection cases: should the pattern detector fire?
    heuristics_expected: bool = True
    #: Which trust boundary the payload crosses. Defaults to ``alert`` because
    #: every case written before this label existed injects through alert text.
    injection_channel: InjectionChannel = "alert"
    #: ATT&CK technique IDs a competent analyst would cite for this alert.
    #:
    #: ``None`` means *unlabelled* and the case is skipped by technique scoring;
    #: an empty tuple is a real label meaning **nothing should be mapped**, which
    #: is the assertion that matters for benign alerts. The distinction is the
    #: point: without it, "no expectation" and "expect nothing" collapse into
    #: each other and the spurious-mapping rate becomes unmeasurable.
    expected_techniques: tuple[str, ...] | None = None
    #: Entities beyond the alert's own that the investigation should reach.
    #:
    #: Same convention as ``expected_techniques``: ``None`` is unlabelled and
    #: skipped, while an empty tuple is a real assertion that evidence is
    #: confined to the alert's own host and the run must *not* pivot. Both
    #: halves are needed -- a loop that always pivots would score perfectly on
    #: recall alone, so the control cases are what make the metric honest.
    expected_entities: tuple[str, ...] | None = None
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
