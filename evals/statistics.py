"""Statistics for reading evaluation results honestly.

The corpus is 35 cases. That is a perfectly reasonable size for a labelled
security corpus, and a completely unreasonable size to read point estimates off
without saying how precise they are: a proportion near 50% on 35 samples carries
a 95% interval of roughly plus or minus 16 points. Reporting "category accuracy
49%" and then "category accuracy 54%" as though the second is an improvement
describes noise.

Three tools, each answering a question the runner could not answer before:

* :func:`wilson_interval` -- *how precise is this number?* Wilson rather than the
  textbook normal approximation because the normal one is badly wrong exactly
  where this corpus lives: small samples and proportions near 0 or 1, where it
  happily produces bounds below 0% or above 100%.

* :func:`mcnemar` -- *is model A actually better than model B?* Comparing two
  aggregate percentages throws away the pairing, and the pairing is most of the
  signal: both models saw the *same* alerts, so case difficulty cancels if you
  compare case by case. Only the cases where they disagree carry information.
  This is what makes a 35-case corpus able to resolve a difference at all.

* :func:`calibration` -- *does a confidence of 0.8 mean 80% right?* Triage emits
  a confidence and policy rule ``HITL-004`` routes to a human below 0.55, so an
  uncalibrated number is steering a safety gate. Brier score and expected
  calibration error say whether it deserves the authority it has.

No SciPy. The exact binomial test needs ``math.comb`` and nothing else, and this
module is imported by the eval harness, which must stay runnable offline.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: z for a 95% two-sided interval. Fixed rather than a parameter on every call
#: site, so every number in a report is quoted at the same confidence level.
Z_95 = 1.959963984540054


# --- Precision of a single proportion ---------------------------------------
@dataclass(frozen=True)
class Interval:
    """A proportion with its confidence interval."""

    point: float
    low: float
    high: float
    trials: int

    @property
    def half_width(self) -> float:
        """Half the interval span -- the '± this much' of the estimate.

        The number to compare a claimed improvement against. A delta smaller
        than this is not something the corpus can see.
        """
        return (self.high - self.low) / 2

    def resolves(self, difference: float) -> bool:
        """Whether a difference of this size is larger than the noise floor."""
        return abs(difference) > self.half_width

    def as_dict(self) -> dict[str, Any]:
        return {
            "point": round(self.point, 4),
            "low": round(self.low, 4),
            "high": round(self.high, 4),
            "half_width": round(self.half_width, 4),
            "trials": self.trials,
        }

    def format(self) -> str:
        return f"{self.point:.0%} ±{self.half_width:.0%}"


def wilson_interval(successes: int, trials: int, *, z: float = Z_95) -> Interval:
    """Wilson score interval for ``successes`` out of ``trials``.

    Stays inside [0, 1] and remains sensible at the boundaries, where this
    corpus spends much of its time -- injection containment and chain
    verification both sit at 100%, and the useful question there is "100% of how
    many?", which a degenerate zero-width interval would hide.
    """
    if trials <= 0:
        return Interval(point=0.0, low=0.0, high=0.0, trials=0)

    successes = max(0, min(successes, trials))
    proportion = successes / trials

    denominator = 1 + z**2 / trials
    centre = (proportion + z**2 / (2 * trials)) / denominator
    spread = (
        z
        / denominator
        * math.sqrt(proportion * (1 - proportion) / trials + z**2 / (4 * trials**2))
    )

    return Interval(
        point=proportion,
        low=max(0.0, centre - spread),
        high=min(1.0, centre + spread),
        trials=trials,
    )


# --- Comparing two systems on the same cases --------------------------------
@dataclass(frozen=True)
class PairedComparison:
    """Case-by-case comparison of two runs over an identical corpus."""

    metric: str
    #: Cases the first system got right and the second got wrong.
    a_only: int
    #: Cases the second got right and the first got wrong.
    b_only: int
    #: Cases both got right, and cases both got wrong.
    both_right: int
    both_wrong: int
    p_value: float

    @property
    def discordant(self) -> int:
        """Cases where the two disagreed. The only ones carrying information."""
        return self.a_only + self.b_only

    @property
    def pairs(self) -> int:
        return self.discordant + self.both_right + self.both_wrong

    @property
    def significant(self) -> bool:
        return self.p_value < 0.05

    def verdict(self, a_label: str = "A", b_label: str = "B") -> str:
        """One line an operator can act on."""
        if self.discordant == 0:
            return f"identical on all {self.pairs} cases"
        winner, loser = (
            (b_label, a_label) if self.b_only > self.a_only else (a_label, b_label)
        )
        if self.a_only == self.b_only:
            return (
                f"even ({self.a_only}/{self.b_only} split over {self.discordant} "
                f"disagreements, p={self.p_value:.3f})"
            )
        if not self.significant:
            return (
                f"{winner} leads but the corpus cannot resolve it "
                f"({self.a_only}/{self.b_only} over {self.discordant}, p={self.p_value:.3f})"
            )
        return (
            f"{winner} beats {loser} ({self.a_only}/{self.b_only} over "
            f"{self.discordant} disagreements, p={self.p_value:.3f})"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "a_only": self.a_only,
            "b_only": self.b_only,
            "both_right": self.both_right,
            "both_wrong": self.both_wrong,
            "discordant": self.discordant,
            "pairs": self.pairs,
            "p_value": round(self.p_value, 5),
            "significant": self.significant,
        }


def exact_binomial_two_sided(a_only: int, b_only: int) -> float:
    """Two-sided exact binomial p-value for the discordant split.

    Under the null hypothesis that the two systems are equally good, each
    disagreement is a fair coin, so the split is Binomial(n, 0.5). The exact
    test is used rather than the chi-square approximation because the
    approximation needs roughly 25 discordant pairs and this corpus will
    routinely produce five.
    """
    n = a_only + b_only
    if n == 0:
        return 1.0

    tail = sum(math.comb(n, k) for k in range(min(a_only, b_only) + 1))
    return min(1.0, 2 * tail / (2**n))


def mcnemar(
    a_correct: Sequence[bool],
    b_correct: Sequence[bool],
    *,
    metric: str = "",
) -> PairedComparison:
    """McNemar's test over paired per-case outcomes.

    ``a_correct[i]`` and ``b_correct[i]`` must describe the *same* case. Cases
    where both systems agree are counted but contribute nothing to the p-value;
    that is the point of the test, and it is why it can detect a difference the
    aggregate percentages cannot.
    """
    if len(a_correct) != len(b_correct):
        raise ValueError(
            f"paired comparison needs equal-length outcomes, got {len(a_correct)} and {len(b_correct)}"
        )

    a_only = sum(1 for a, b in zip(a_correct, b_correct, strict=True) if a and not b)
    b_only = sum(1 for a, b in zip(a_correct, b_correct, strict=True) if b and not a)
    both_right = sum(1 for a, b in zip(a_correct, b_correct, strict=True) if a and b)
    both_wrong = sum(1 for a, b in zip(a_correct, b_correct, strict=True) if not a and not b)

    return PairedComparison(
        metric=metric,
        a_only=a_only,
        b_only=b_only,
        both_right=both_right,
        both_wrong=both_wrong,
        p_value=exact_binomial_two_sided(a_only, b_only),
    )


# --- Does the confidence number mean anything? ------------------------------
@dataclass(frozen=True)
class CalibrationBin:
    """One confidence bucket: what was claimed against what happened."""

    low: float
    high: float
    count: int
    mean_confidence: float
    accuracy: float

    @property
    def gap(self) -> float:
        """Signed over-confidence. Positive means the claim outran the result."""
        return self.mean_confidence - self.accuracy

    def as_dict(self) -> dict[str, Any]:
        return {
            "low": round(self.low, 2),
            "high": round(self.high, 2),
            "count": self.count,
            "mean_confidence": round(self.mean_confidence, 4),
            "accuracy": round(self.accuracy, 4),
            "gap": round(self.gap, 4),
        }


@dataclass(frozen=True)
class Calibration:
    """How well stated confidence tracks observed correctness."""

    #: Mean squared error of the confidence as a probability forecast. Lower is
    #: better; 0.25 is what you get by always saying 0.5.
    brier: float
    #: Expected calibration error: the count-weighted mean gap across bins.
    ece: float
    #: Mean confidence minus overall accuracy. Positive is systematic
    #: over-confidence, the direction that quietly disarms a low-confidence gate.
    bias: float
    bins: tuple[CalibrationBin, ...]
    samples: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "brier": round(self.brier, 4),
            "ece": round(self.ece, 4),
            "bias": round(self.bias, 4),
            "samples": self.samples,
            "bins": [b.as_dict() for b in self.bins],
        }


def calibration(
    confidences: Sequence[float],
    outcomes: Sequence[bool],
    *,
    bin_count: int = 5,
) -> Calibration:
    """Score stated confidence against observed correctness.

    ``outcomes[i]`` is whether the assessment that carried ``confidences[i]``
    turned out to be right. Empty bins are dropped rather than reported as 0%
    accuracy, which would be an artefact of the bucketing rather than a finding.
    """
    if len(confidences) != len(outcomes):
        raise ValueError(
            f"calibration needs equal-length inputs, got {len(confidences)} and {len(outcomes)}"
        )
    samples = len(confidences)
    if samples == 0:
        return Calibration(brier=0.0, ece=0.0, bias=0.0, bins=(), samples=0)

    clamped = [max(0.0, min(1.0, float(c))) for c in confidences]
    truths = [1.0 if o else 0.0 for o in outcomes]

    brier = sum((c - t) ** 2 for c, t in zip(clamped, truths, strict=True)) / samples
    accuracy = sum(truths) / samples
    bias = sum(clamped) / samples - accuracy

    bins: list[CalibrationBin] = []
    weighted_gap = 0.0
    width = 1.0 / bin_count
    for index in range(bin_count):
        low = index * width
        high = low + width
        # The top bin is closed so a confidence of exactly 1.0 lands somewhere.
        members = [
            (c, t)
            for c, t in zip(clamped, truths, strict=True)
            if (low <= c < high) or (index == bin_count - 1 and c == 1.0)
        ]
        if not members:
            continue
        count = len(members)
        mean_confidence = sum(c for c, _ in members) / count
        bin_accuracy = sum(t for _, t in members) / count
        bins.append(
            CalibrationBin(
                low=low,
                high=high,
                count=count,
                mean_confidence=mean_confidence,
                accuracy=bin_accuracy,
            )
        )
        weighted_gap += (count / samples) * abs(mean_confidence - bin_accuracy)

    return Calibration(
        brier=brier,
        ece=weighted_gap,
        bias=bias,
        bins=tuple(bins),
        samples=samples,
    )
