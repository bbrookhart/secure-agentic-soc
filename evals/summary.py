"""Render an evaluation report as Markdown for a CI job summary.

Separate from the runner's terminal output on purpose. The runner prints for a
human at a terminal; this prints for the pull request, where the useful question
is not "what are the numbers" but "what did this change do to them".

The layout follows the same split the runner enforces: invariants first and
unmissable, because they are the build gate, then quality metrics, which are
reported and never enforced.

Usage::

    python -m evals.summary eval-report.json >> "$GITHUB_STEP_SUMMARY"
    python -m evals.summary eval-report.json --baseline baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: Metrics where a higher number is better, for arrow direction on deltas.
_HIGHER_IS_BETTER = {
    "severity_in_band",
    "category_accuracy",
    "escalation_accuracy",
    "escalation_precision",
    "escalation_recall",
    "escalation_f1",
    "injection_containment",
    "injection_detection",
    "chain_verified",
}

_PERCENT_METRICS = {
    "severity_in_band",
    "severity_under_called",
    "severity_over_called",
    "category_accuracy",
    "escalation_accuracy",
    "escalation_precision",
    "escalation_recall",
    "injection_containment",
    "injection_detection",
    "benign_overcall",
    "chain_verified",
}


def _format(name: str, value: Any) -> str:
    if isinstance(value, float) and name in _PERCENT_METRICS:
        return f"{value:.0%}"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def _delta(name: str, current: Any, baseline: Any) -> str:
    """Render the change against a baseline, if there is one worth showing."""
    if baseline is None or not isinstance(current, int | float) or not isinstance(baseline, int | float):
        return ""
    difference = current - baseline
    if abs(difference) < 1e-9:
        return "—"

    if name in _PERCENT_METRICS:
        magnitude = f"{abs(difference):.0%}"
    else:
        magnitude = f"{abs(difference):.1f}"

    improved = difference > 0 if name in _HIGHER_IS_BETTER else difference < 0
    return f"{'🟢' if improved else '🔴'} {'+' if difference > 0 else '−'}{magnitude}"


def render(report: dict[str, Any], baseline: dict[str, Any] | None = None) -> str:
    summary = report.get("summary", {})
    cases = report.get("cases", [])
    base_summary = (baseline or {}).get("summary", {})

    violations = [
        (case["case_id"], violation)
        for case in cases
        for violation in case.get("violations", [])
    ]
    errored = [case["case_id"] for case in cases if case.get("error")]

    lines: list[str] = [
        f"## Evaluation — {summary.get('cases', 0)} cases, {report.get('mode', 'offline')} mode",
        "",
    ]

    # A prompt or model change invalidates the comparison before any metric
    # is read: the baseline describes a system that no longer exists.
    if baseline:
        drifted = [
            name
            for name, key in (("prompts", "prompt_manifest"), ("model", "model_digest"))
            if report.get(key) and baseline.get(key) and report[key] != baseline[key]
        ]
        if drifted:
            lines += [
                "> [!IMPORTANT]",
                f"> **The {' and '.join(drifted)} changed since the baseline.** The deltas below "
                "compare different systems. Re-baseline before citing these numbers as current.",
                "",
            ]

    # --- Invariants: the gate ------------------------------------------
    if violations or errored:
        lines += [
            "### 🔴 Security invariants BREACHED",
            "",
            "These are unconditional properties, not quality metrics. A breach is a defect "
            "regardless of what the numbers below say.",
            "",
        ]
        lines += [f"- `{case_id}` — {violation}" for case_id, violation in violations]
        lines += [f"- `{case_id}` — run errored" for case_id in errored]
        lines.append("")
    else:
        lines += [
            "### 🟢 Security invariants held",
            "",
            "No run completed past an approval it owed. Every proposal was proposal-only. "
            "Every audit chain verified. No configuration reached a report.",
            "",
        ]

    # --- Quality: reported, never enforced ------------------------------
    lines += [
        "### Quality metrics",
        "",
        "_Reported, not enforced — these move with the model and the corpus._",
        "",
        "| Metric | Value | vs. baseline |",
        "|:--|--:|--:|",
    ]

    for key, label in (
        ("severity_in_band", "Severity in band"),
        ("severity_under_called", "Severity under-called"),
        ("severity_over_called", "Severity over-called"),
        ("category_accuracy", "Category accuracy"),
        ("escalation_accuracy", "Escalation accuracy"),
        ("escalation_precision", "Escalation precision"),
        ("escalation_recall", "Escalation recall"),
        ("missed_escalations", "Missed escalations"),
        ("unnecessary_escalations", "Unnecessary escalations"),
        ("injection_containment", "Injection containment"),
        ("injection_detection", "Injection detection"),
        ("mean_tool_calls", "Mean tool calls"),
    ):
        if key not in summary:
            continue
        lines.append(
            f"| {label} | {_format(key, summary[key])} | {_delta(key, summary[key], base_summary.get(key))} |"
        )

    lines.append("")

    # Under-calling and missed escalations are the failures that matter in a
    # SOC, so they get called out rather than left in a table row.
    concerns: list[str] = []
    if summary.get("missed_escalations"):
        concerns.append(
            f"**{summary['missed_escalations']} missed escalation(s)** — incidents that "
            "needed a human and did not reach one."
        )
    if summary.get("severity_under_called"):
        concerns.append(
            f"**{summary['severity_under_called']:.0%} under-called** — rated below the "
            "acceptable band, the direction that costs more than analyst time."
        )
    if summary.get("injection_containment", 1.0) < 1.0:
        concerns.append(
            f"**Injection containment {summary['injection_containment']:.0%}** — an injection "
            "case completed without human review."
        )
    if concerns:
        lines += ["> [!WARNING]", *[f"> - {concern}" for concern in concerns], ""]

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render an eval report as Markdown.")
    parser.add_argument("report", help="Path to the JSON report from evals.runner --json.")
    parser.add_argument("--baseline", help="Optional earlier report to compare against.")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"report not found: {report_path}", file=sys.stderr)
        return 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    baseline = None
    if args.baseline and Path(args.baseline).exists():
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))

    print(render(report, baseline))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
