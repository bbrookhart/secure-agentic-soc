"""Compare two evaluation reports case by case.

The question this exists to answer is "is the new model actually better?", and
the obvious way to answer it does not work. Two runs of the corpus give two
percentages; subtracting them gives a delta; on 35 cases that delta is swamped
by a confidence interval of roughly ±16 points. Every conclusion drawn that way
is a coin flip dressed as a measurement.

The pairing is what rescues it. Both runs saw the *same* 35 alerts, so the
difficulty of each alert is common to both and cancels. Cases where the two
systems agree -- however hard or easy -- tell you nothing about which is better;
only the disagreements do. McNemar's test reads exactly those, which is why it
can resolve a difference the aggregate percentages cannot.

Concretely: if A and B each score 60% but disagree on 8 cases with A right on 7
of them, that is p=0.070 on the pairing and invisible in the aggregate.

Usage::

    python -m evals.paired baseline-a.json baseline-b.json
    python -m evals.paired a.json b.json --labels llama3.2 qwen3:8b --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from evals.statistics import PairedComparison, mcnemar, wilson_interval

#: The per-case properties worth testing, and how to read each from a report.
#: Cost metrics are excluded on purpose -- they are continuous, and McNemar is
#: a test about a binary outcome per case.
_METRICS: dict[str, str] = {
    "severity_in_band": "Severity in band",
    "category_correct": "Category correct",
    "escalation_correct": "Escalation correct",
    "assessment_correct": "Severity and category both right",
}


def _case_correctness(case: dict[str, Any]) -> dict[str, bool]:
    """Recompute each per-case verdict from a stored report.

    Derived from the recorded outcome rather than read from a stored flag, so
    reports written before this module existed can still be compared -- which
    matters, because the whole point is comparing against baselines recorded
    earlier.
    """
    expected = case.get("expected", {})
    band = set(expected.get("severity_band", []))
    severity = case.get("severity")

    severity_in_band = severity is not None and severity in band

    # Categories a competent analyst could also defend, mirroring the severity
    # band. This must match how ``runner.summarise`` scores, or the per-case
    # verdict and the headline proportion answer different questions -- which
    # they briefly did, printing "66% -> 83%" beside "identical on all 41
    # cases". Older reports have no such field and simply get an empty set.
    acceptable = {expected.get("category")}
    acceptable |= set(expected.get("category_also_acceptable") or ())
    category_correct = case.get("category", "") in acceptable
    escalation_correct = bool(case.get("escalated")) == bool(expected.get("should_escalate"))

    return {
        "severity_in_band": severity_in_band,
        "category_correct": category_correct,
        "escalation_correct": escalation_correct,
        "assessment_correct": severity_in_band and category_correct,
    }


def align(report_a: dict[str, Any], report_b: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Case ids present in both reports, and a list of complaints about the rest.

    A case that errored in either run is dropped from the comparison: it has no
    outcome to pair, and scoring a crash as "wrong" would credit the other
    system for a defect rather than for judgement.
    """
    cases_a = {c["case_id"]: c for c in report_a.get("cases", [])}
    cases_b = {c["case_id"]: c for c in report_b.get("cases", [])}

    shared = sorted(set(cases_a) & set(cases_b))
    notes: list[str] = []

    only_a = sorted(set(cases_a) - set(cases_b))
    only_b = sorted(set(cases_b) - set(cases_a))
    if only_a:
        notes.append(f"{len(only_a)} case(s) only in the first report: {', '.join(only_a[:4])}")
    if only_b:
        notes.append(f"{len(only_b)} case(s) only in the second report: {', '.join(only_b[:4])}")

    errored = [cid for cid in shared if cases_a[cid].get("error") or cases_b[cid].get("error")]
    if errored:
        notes.append(f"{len(errored)} case(s) errored in one run and were dropped")
        shared = [cid for cid in shared if cid not in errored]

    return shared, notes


def compare(report_a: dict[str, Any], report_b: dict[str, Any]) -> dict[str, Any]:
    """Run the paired test for every metric over the cases both reports share."""
    shared, notes = align(report_a, report_b)
    cases_a = {c["case_id"]: c for c in report_a.get("cases", [])}
    cases_b = {c["case_id"]: c for c in report_b.get("cases", [])}

    correctness_a = [_case_correctness(cases_a[cid]) for cid in shared]
    correctness_b = [_case_correctness(cases_b[cid]) for cid in shared]

    comparisons: dict[str, PairedComparison] = {}
    for metric in _METRICS:
        comparisons[metric] = mcnemar(
            [c[metric] for c in correctness_a],
            [c[metric] for c in correctness_b],
            metric=metric,
        )

    return {
        "paired_cases": len(shared),
        "notes": notes,
        "comparisons": {name: c.as_dict() for name, c in comparisons.items()},
        "_objects": comparisons,
        "_case_ids": shared,
        "_correctness": (correctness_a, correctness_b),
    }


def _provenance_warning(report_a: dict[str, Any], report_b: dict[str, Any]) -> list[str]:
    """Flag comparisons where the two runs describe different systems."""
    warnings: list[str] = []
    if (
        report_a.get("prompt_manifest")
        and report_b.get("prompt_manifest")
        and report_a["prompt_manifest"] != report_b["prompt_manifest"]
    ):
        warnings.append(
            "The prompts differ between these reports. Any difference below is a "
            "prompt change as much as a model change."
        )
    if report_a.get("mode") != report_b.get("mode"):
        warnings.append(
            f"Comparing '{report_a.get('mode')}' against '{report_b.get('mode')}' mode -- "
            "these are different systems, not two settings of one."
        )
    return warnings


def render(
    result: dict[str, Any],
    report_a: dict[str, Any],
    report_b: dict[str, Any],
    *,
    label_a: str,
    label_b: str,
) -> str:
    """Terminal report."""
    lines: list[str] = [
        "",
        f"  Paired comparison -- {label_a}  vs  {label_b}",
        f"  {result['paired_cases']} cases run through both.",
        "",
    ]

    for warning in _provenance_warning(report_a, report_b):
        lines += [f"  ! {warning}", ""]
    for note in result["notes"]:
        lines.append(f"  note: {note}")
    if result["notes"]:
        lines.append("")

    summary_a = report_a.get("summary", {})
    summary_b = report_b.get("summary", {})

    lines += [
        f"  {'metric':<34} {label_a[:12]:>12} {label_b[:12]:>12}   {'verdict'}",
        f"  {'-' * 34} {'-' * 12} {'-' * 12}   {'-' * 44}",
    ]

    # The aggregate figures are shown next to the paired verdict on purpose:
    # seeing "49% vs 54%" beside "the corpus cannot resolve it" is the whole
    # lesson this tool exists to teach.
    aggregate_keys = {
        "severity_in_band": "severity_in_band",
        "category_correct": "category_accuracy",
        "escalation_correct": "escalation_accuracy",
        "assessment_correct": None,
    }

    for metric, label in _METRICS.items():
        comparison: PairedComparison = result["_objects"][metric]
        key = aggregate_keys[metric]
        left = f"{summary_a[key]:.0%}" if key and key in summary_a else "-"
        right = f"{summary_b[key]:.0%}" if key and key in summary_b else "-"
        lines.append(
            f"  {label:<34} {left:>12} {right:>12}   {comparison.verdict(label_a, label_b)}"
        )

    lines += ["", "  Reading this"]

    resolved = [m for m in _METRICS if result["_objects"][m].significant]
    if resolved:
        lines.append(
            "    Differences the corpus can actually support: "
            + ", ".join(_METRICS[m] for m in resolved)
            + "."
        )
    else:
        lines.append(
            "    No metric separated the two systems at p<0.05. That is a real result --"
        )
        lines.append(
            "    it means this corpus cannot tell them apart, not that they are identical."
        )

    # The most common misreading is treating a wide aggregate gap as a finding,
    # so name the noise floor explicitly rather than leaving it to be inferred.
    interval = wilson_interval(
        int(summary_a.get("category_accuracy", 0) * result["paired_cases"]),
        result["paired_cases"],
    )
    lines += [
        f"    Aggregate noise floor at this corpus size: about ±{interval.half_width:.0%} on a",
        "    mid-range proportion. Aggregate gaps smaller than that are not evidence.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two eval reports case by case (McNemar's test)."
    )
    parser.add_argument("report_a", help="First report from evals.runner --json.")
    parser.add_argument("report_b", help="Second report from evals.runner --json.")
    parser.add_argument(
        "--labels",
        nargs=2,
        metavar=("A", "B"),
        help="Names for the two systems (default: the file stems).",
    )
    parser.add_argument("--json", dest="json_path", help="Write the comparison to this path.")
    args = parser.parse_args(argv)

    paths = [Path(args.report_a), Path(args.report_b)]
    for path in paths:
        if not path.exists():
            print(f"report not found: {path}", file=sys.stderr)
            return 2

    report_a, report_b = (json.loads(p.read_text(encoding="utf-8")) for p in paths)
    label_a, label_b = args.labels or [p.stem for p in paths]

    result = compare(report_a, report_b)
    if result["paired_cases"] == 0:
        print("the two reports share no comparable cases", file=sys.stderr)
        return 2

    print(render(result, report_a, report_b, label_a=label_a, label_b=label_b))

    if args.json_path:
        payload = {
            "a": {"label": label_a, "source": str(paths[0]), "mode": report_a.get("mode")},
            "b": {"label": label_b, "source": str(paths[1]), "mode": report_b.get("mode")},
            "paired_cases": result["paired_cases"],
            "notes": result["notes"],
            "comparisons": result["comparisons"],
        }
        Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"  comparison written to {args.json_path}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
