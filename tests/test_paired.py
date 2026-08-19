"""Tests for the paired report comparison.

The comparison is what decides "should we adopt this model", so the cases that
matter most are the ones where it must *refuse* to call a winner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evals.paired import _case_correctness, align, compare, main, render


def make_case(
    case_id: str,
    *,
    severity: str | None = "high",
    category: str = "malware",
    escalated: bool = True,
    band: tuple[str, ...] = ("high", "critical"),
    expected_category: str = "malware",
    should_escalate: bool = True,
    error: str = "",
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "expected": {
            "severity_band": list(band),
            "category": expected_category,
            "should_escalate": should_escalate,
        },
        "severity": severity,
        "category": category,
        "escalated": escalated,
        "error": error,
        "violations": [],
    }


def make_report(cases: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    report = {
        "mode": "llm",
        "prompt_manifest": "abc123",
        "model_digest": "sha256:aaa",
        "summary": {
            "severity_in_band": 0.5,
            "category_accuracy": 0.5,
            "escalation_accuracy": 0.5,
        },
        "cases": cases,
    }
    report.update(overrides)
    return report


class TestCaseCorrectness:
    def test_reads_each_verdict_from_the_recorded_outcome(self):
        result = _case_correctness(make_case("TP-001"))
        assert result == {
            "severity_in_band": True,
            "category_correct": True,
            "escalation_correct": True,
            "assessment_correct": True,
        }

    def test_severity_outside_the_band_is_wrong(self):
        result = _case_correctness(make_case("TP-001", severity="low"))
        assert not result["severity_in_band"]
        assert not result["assessment_correct"]

    def test_assessment_needs_both_halves(self):
        result = _case_correctness(make_case("TP-001", category="phishing"))
        assert result["severity_in_band"]
        assert not result["category_correct"]
        assert not result["assessment_correct"]

    def test_a_case_with_no_severity_is_not_credited(self):
        result = _case_correctness(make_case("TP-001", severity=None))
        assert not result["severity_in_band"]


class TestAlign:
    def test_pairs_only_the_shared_cases(self):
        a = make_report([make_case("TP-001"), make_case("TP-002")])
        b = make_report([make_case("TP-002"), make_case("TP-003")])
        shared, notes = align(a, b)
        assert shared == ["TP-002"]
        assert len(notes) == 2

    def test_a_case_that_errored_in_either_run_is_dropped(self):
        """A crash is a defect, not a wrong answer.

        Scoring it as incorrect would credit the other system for judgement it
        never exercised.
        """
        a = make_report([make_case("TP-001"), make_case("TP-002", error="Timeout")])
        b = make_report([make_case("TP-001"), make_case("TP-002")])
        shared, notes = align(a, b)
        assert shared == ["TP-001"]
        assert any("errored" in note for note in notes)

    def test_identical_corpora_produce_no_complaints(self):
        a = make_report([make_case("TP-001")])
        b = make_report([make_case("TP-001")])
        shared, notes = align(a, b)
        assert shared == ["TP-001"]
        assert notes == []


class TestCompare:
    def test_identical_reports_show_no_disagreement(self):
        cases = [make_case(f"TP-{i:03d}") for i in range(10)]
        result = compare(make_report(cases), make_report(list(cases)))
        assert result["paired_cases"] == 10
        for comparison in result["comparisons"].values():
            assert comparison["discordant"] == 0
            assert comparison["p_value"] == 1.0

    def test_refuses_to_call_a_small_lead(self):
        """Three disagreements, all one way, is not enough. p = 0.25."""
        a = [make_case(f"TP-{i:03d}", category="malware") for i in range(10)]
        b = [
            make_case(f"TP-{i:03d}", category="phishing" if i < 3 else "malware")
            for i in range(10)
        ]
        result = compare(make_report(a), make_report(b))
        comparison = result["comparisons"]["category_correct"]
        assert comparison["a_only"] == 3
        assert comparison["b_only"] == 0
        assert not comparison["significant"]

    def test_calls_a_lead_that_is_actually_supported(self):
        a = [make_case(f"TP-{i:03d}", category="malware") for i in range(12)]
        b = [
            make_case(f"TP-{i:03d}", category="phishing" if i < 8 else "malware")
            for i in range(12)
        ]
        result = compare(make_report(a), make_report(b))
        comparison = result["comparisons"]["category_correct"]
        assert comparison["a_only"] == 8
        assert comparison["significant"]

    def test_every_metric_is_tested(self):
        result = compare(make_report([make_case("TP-001")]), make_report([make_case("TP-001")]))
        assert set(result["comparisons"]) == {
            "severity_in_band",
            "category_correct",
            "escalation_correct",
            "assessment_correct",
        }


class TestRender:
    def _rendered(self, a: dict[str, Any], b: dict[str, Any]) -> str:
        return render(compare(a, b), a, b, label_a="alpha", label_b="beta")

    def test_warns_when_the_prompts_differ(self):
        a = make_report([make_case("TP-001")], prompt_manifest="one")
        b = make_report([make_case("TP-001")], prompt_manifest="two")
        assert "prompts differ" in self._rendered(a, b)

    def test_warns_when_the_modes_differ(self):
        a = make_report([make_case("TP-001")], mode="offline")
        b = make_report([make_case("TP-001")], mode="llm")
        assert "different systems" in self._rendered(a, b)

    def test_states_plainly_when_nothing_was_resolved(self):
        cases = [make_case(f"TP-{i:03d}") for i in range(10)]
        output = self._rendered(make_report(cases), make_report(list(cases)))
        assert "No metric separated the two systems" in output
        assert "not that they are identical" in output

    def test_names_the_noise_floor(self):
        cases = [make_case(f"TP-{i:03d}") for i in range(10)]
        assert "noise floor" in self._rendered(make_report(cases), make_report(list(cases)))


class TestCli:
    def test_reports_a_missing_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        existing = tmp_path / "a.json"
        existing.write_text(json.dumps(make_report([make_case("TP-001")])))
        assert main([str(existing), str(tmp_path / "missing.json")]) == 2

    def test_refuses_reports_with_nothing_in_common(self, tmp_path: Path):
        a, b = tmp_path / "a.json", tmp_path / "b.json"
        a.write_text(json.dumps(make_report([make_case("TP-001")])))
        b.write_text(json.dumps(make_report([make_case("TP-999")])))
        assert main([str(a), str(b)]) == 2

    def test_writes_a_machine_readable_comparison(self, tmp_path: Path):
        a, b = tmp_path / "a.json", tmp_path / "b.json"
        out = tmp_path / "out.json"
        cases = [make_case(f"TP-{i:03d}") for i in range(5)]
        a.write_text(json.dumps(make_report(cases)))
        b.write_text(json.dumps(make_report(list(cases))))

        assert main([str(a), str(b), "--labels", "alpha", "beta", "--json", str(out)]) == 0
        payload = json.loads(out.read_text())
        assert payload["a"]["label"] == "alpha"
        assert payload["paired_cases"] == 5
        # The private helper keys are for the renderer, not the artefact.
        assert "_objects" not in payload
