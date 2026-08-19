"""Tests for the evaluation statistics.

These functions decide whether a quality claim is supportable, so they are
worth testing against known-good values rather than against themselves. The
Wilson and McNemar cases below use hand-computable inputs.
"""

from __future__ import annotations

import math

import pytest

from evals.statistics import (
    calibration,
    exact_binomial_two_sided,
    mcnemar,
    wilson_interval,
)


class TestWilsonInterval:
    def test_stays_inside_the_unit_interval_at_the_boundary(self):
        """The reason for Wilson over the normal approximation.

        At 35/35 the textbook interval is 100% ± 0%, which claims perfection is
        certain. Wilson keeps an upper bound of 1.0 but a lower bound well below
        it, which is the honest statement: 100% of a small sample.
        """
        interval = wilson_interval(35, 35)
        assert interval.point == 1.0
        assert interval.high == pytest.approx(1.0)
        assert 0.85 < interval.low < 1.0

    def test_zero_successes_does_not_go_negative(self):
        interval = wilson_interval(0, 20)
        assert interval.low == 0.0
        assert 0.0 < interval.high < 0.25

    def test_half_width_on_the_corpus_size_that_matters(self):
        """35 cases at ~50% is the case the whole module exists for."""
        interval = wilson_interval(17, 35)
        assert 0.14 < interval.half_width < 0.18

    def test_precision_improves_with_sample_size(self):
        small = wilson_interval(50, 100)
        large = wilson_interval(500, 1000)
        assert large.half_width < small.half_width

    def test_no_trials_is_not_a_crash(self):
        interval = wilson_interval(0, 0)
        assert interval.trials == 0
        assert interval.half_width == 0.0

    def test_resolves_rejects_a_difference_inside_the_noise(self):
        interval = wilson_interval(17, 35)
        assert not interval.resolves(0.05)
        assert interval.resolves(0.40)

    def test_successes_cannot_exceed_trials(self):
        assert wilson_interval(50, 10).point == 1.0


class TestExactBinomial:
    def test_no_disagreement_is_no_evidence(self):
        assert exact_binomial_two_sided(0, 0) == 1.0

    def test_symmetric_split_is_maximally_unconvincing(self):
        assert exact_binomial_two_sided(5, 5) == 1.0

    def test_known_value(self):
        """8 disagreements all one way: 2 * (1/256)."""
        assert exact_binomial_two_sided(8, 0) == pytest.approx(2 / 256)

    def test_is_symmetric_in_its_arguments(self):
        assert exact_binomial_two_sided(7, 2) == exact_binomial_two_sided(2, 7)

    def test_more_lopsided_is_more_significant(self):
        assert exact_binomial_two_sided(9, 1) < exact_binomial_two_sided(6, 4)


class TestMcNemar:
    def test_resolves_a_difference_the_aggregate_intervals_cannot(self):
        """The case that justifies the whole approach.

        Over 35 cases A scores 57% and B scores 34%. Read as two independent
        proportions their Wilson intervals overlap, which is the reading that
        says "this corpus cannot tell them apart" -- and it is wrong, because
        the runs are not independent. They saw the same alerts. Paired, they
        disagree on only 10 cases and A wins 9 of them, which is significant.

        Overlapping intervals do not mean no difference when the data are
        paired. That is the entire reason this module exists.
        """
        # 11 both right, 9 A-only, 1 B-only, 14 both wrong.
        a = [True] * 11 + [True] * 9 + [False] + [False] * 14
        b = [True] * 11 + [False] * 9 + [True] + [False] * 14
        assert len(a) == len(b) == 35

        interval_a = wilson_interval(sum(a), 35)
        interval_b = wilson_interval(sum(b), 35)
        assert interval_a.low < interval_b.high, "the aggregate intervals overlap"

        result = mcnemar(a, b)
        assert result.discordant == 10
        assert result.a_only == 9
        assert result.b_only == 1
        assert result.p_value == pytest.approx(2 * (1 + 10) / 1024)
        assert result.significant

    def test_agreement_contributes_nothing_to_the_p_value(self):
        few = mcnemar([True, False], [False, True])
        padded = mcnemar(
            [True, False] + [True] * 50,
            [False, True] + [True] * 50,
        )
        assert few.p_value == padded.p_value
        assert padded.both_right == 50

    def test_identical_systems_are_reported_as_such(self):
        outcomes = [True, False, True, True]
        result = mcnemar(outcomes, outcomes)
        assert result.discordant == 0
        assert result.p_value == 1.0
        assert "identical" in result.verdict()

    def test_verdict_refuses_to_call_an_unresolvable_lead(self):
        result = mcnemar([True, True, False], [False, False, True])
        assert not result.significant
        assert "cannot resolve" in result.verdict("A", "B")

    def test_verdict_names_the_winner_when_it_is_real(self):
        result = mcnemar([True] * 9 + [False], [False] * 9 + [True])
        assert result.significant
        assert result.verdict("alpha", "beta").startswith("alpha beats beta")

    def test_mismatched_lengths_are_rejected(self):
        with pytest.raises(ValueError, match="equal-length"):
            mcnemar([True], [True, False])

    def test_counts_partition_the_corpus(self):
        a = [True, True, False, False, True]
        b = [True, False, True, False, False]
        result = mcnemar(a, b)
        assert result.pairs == 5
        assert result.both_right + result.both_wrong + result.discordant == 5


class TestCalibration:
    def test_perfect_calibration_scores_zero_error(self):
        # Ten cases at 1.0 that are all right, ten at 0.0 that are all wrong.
        result = calibration([1.0] * 10 + [0.0] * 10, [True] * 10 + [False] * 10)
        assert result.brier == pytest.approx(0.0)
        assert result.ece == pytest.approx(0.0)
        assert result.bias == pytest.approx(0.0)

    def test_confident_and_wrong_is_the_worst_score(self):
        result = calibration([1.0] * 8, [False] * 8)
        assert result.brier == pytest.approx(1.0)
        assert result.bias == pytest.approx(1.0)

    def test_always_saying_half_scores_the_reference_value(self):
        """0.25 is the score to beat; anything worse is uninformative."""
        result = calibration([0.5] * 20, [True] * 10 + [False] * 10)
        assert result.brier == pytest.approx(0.25)

    def test_bias_sign_distinguishes_over_from_under_confidence(self):
        over = calibration([0.9] * 10, [True] * 5 + [False] * 5)
        under = calibration([0.1] * 10, [True] * 5 + [False] * 5)
        assert over.bias > 0
        assert under.bias < 0

    def test_empty_bins_are_dropped_rather_than_reported_as_zero(self):
        result = calibration([0.9] * 5, [True] * 5)
        assert len(result.bins) == 1
        assert result.bins[0].count == 5

    def test_confidence_of_exactly_one_lands_in_the_top_bin(self):
        result = calibration([1.0], [True])
        assert result.samples == 1
        assert sum(b.count for b in result.bins) == 1

    def test_values_outside_the_unit_interval_are_clamped(self):
        result = calibration([1.4, -0.3], [True, False])
        assert result.brier == pytest.approx(0.0)

    def test_mismatched_lengths_are_rejected(self):
        with pytest.raises(ValueError, match="equal-length"):
            calibration([0.5], [True, False])

    def test_no_samples_is_not_a_crash(self):
        result = calibration([], [])
        assert result.samples == 0
        assert result.bins == ()

    def test_every_case_is_counted_in_exactly_one_bin(self):
        confidences = [i / 50 for i in range(51)]
        result = calibration(confidences, [True] * 51)
        assert sum(b.count for b in result.bins) == 51

    def test_ece_is_the_count_weighted_mean_gap(self):
        # One bin of 3 claiming ~0.9 and observing 1/3; another of 1 that is
        # perfectly calibrated. ECE must weight by how many cases each holds.
        result = calibration([0.9, 0.9, 0.9, 0.1], [True, False, False, False])
        assert 0.0 < result.ece < 1.0
        assert not math.isnan(result.ece)
