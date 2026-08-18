"""Supervisor architecture versus the single ReAct agent, on the same corpus.

The README asserts this comparison qualitatively.  This runs it.

Two honest caveats, both structural rather than incidental:

* **The baseline needs a model.**  It has no deterministic fallback -- that
  absence *is* one of the findings, since the supervisor pipeline still
  produces a full assessment with the model switched off.  So this script
  requires Ollama and refuses to pretend otherwise.
* **The baseline returns free text.**  There is no schema to read a severity or
  a category out of, so it cannot be scored on the quality metrics at all.
  That is the second finding: an unstructured answer is not merely harder to
  grade, it is impossible to gate on.  What *can* be compared is capability
  exposure, tool spend, and whether an approval gate exists at all.

Usage::

    python -m evals.compare
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from evals.cases import load_cases
from evals.runner import run_case
from src.enums import AgentRole
from src.security.audit import AuditLogger, set_audit_logger, verify_chain
from src.security.identity import get_identity


def _baseline_case(case: Any, audit_dir: Path) -> dict[str, Any]:
    """Run one alert through the single ReAct agent."""
    from src.agents.baseline import run_baseline_agent

    audit = AuditLogger(audit_dir / f"baseline-{case.case_id}.jsonl")
    set_audit_logger(audit)
    thread_id = f"baseline-{case.case_id}"

    started = time.perf_counter()
    try:
        summary, _ = run_baseline_agent(case.alert, thread_id=thread_id)
        error = ""
    except Exception as exc:  # noqa: BLE001 - a crashed case is a result
        summary, error = "", f"{type(exc).__name__}: {exc}"
    finally:
        set_audit_logger(None)

    events = audit.read_events(thread_id)
    chain_ok, _ = verify_chain(events)
    tool_calls = sum(1 for e in events if e.action.value == "tool_call")

    return {
        "case_id": case.case_id,
        "duration_ms": (time.perf_counter() - started) * 1000,
        "tool_calls": tool_calls,
        "chain_ok": chain_ok,
        "output_chars": len(summary),
        "structured": False,
        "escalated": False,  # the baseline has no gate to reach
        "error": error,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare the supervisor pipeline with the ReAct baseline.")
    parser.add_argument("--only", help="Run only cases whose id contains this substring.")
    args = parser.parse_args(argv)

    os.environ["SOC_OFFLINE_MODE"] = "false"
    from src.config import get_settings
    from src.llm import is_available

    get_settings.cache_clear()

    if not is_available(force=True):
        print(
            "\n  The baseline agent has no deterministic fallback, so this comparison needs a\n"
            "  running model server. Start Ollama and retry.\n\n"
            "  That asymmetry is itself the first result: with the model unavailable the\n"
            "  supervisor pipeline still triages, enriches, gates and reports, while the\n"
            "  single-agent design cannot start.\n",
            file=sys.stderr,
        )
        return 2

    cases = load_cases(only=args.only)
    supervisor_identities = [AgentRole.TRIAGE, AgentRole.ENRICHMENT, AgentRole.REPORTER]

    with tempfile.TemporaryDirectory(prefix="soc-compare-") as tmp:
        audit_dir = Path(tmp)
        supervisor = [run_case(case, consult_llm=True, audit_dir=audit_dir) for case in cases]
        baseline = [_baseline_case(case, audit_dir) for case in cases]

    total = len(cases) or 1
    sup_gated = sum(1 for o in supervisor if o.escalated)
    sup_violations = sum(len(o.violations) for o in supervisor)

    print(f"\n  Supervisor vs. baseline -- {len(cases)} cases\n")
    print(f"  {'property':<34} {'supervisor':<24} {'baseline'}")
    print(f"  {'-' * 34} {'-' * 24} {'-' * 24}")

    rows = [
        (
            "output",
            "validated Pydantic models",
            "free text",
        ),
        (
            "runs without a model",
            "yes (deterministic floor)",
            "no",
        ),
        (
            "approval gate",
            f"{sup_gated}/{total} runs suspended",
            "none in the design",
        ),
        (
            "peak tools held at once",
            str(max(len(get_identity(r).allowed_tools) for r in supervisor_identities)),
            str(len(get_identity(AgentRole.BASELINE).allowed_tools)),
        ),
        (
            "tools held while writing up",
            str(len(get_identity(AgentRole.REPORTER).allowed_tools)),
            str(len(get_identity(AgentRole.BASELINE).allowed_tools)),
        ),
        (
            "mean tool calls",
            f"{sum(o.tool_calls for o in supervisor) / total:.1f}",
            f"{sum(b['tool_calls'] for b in baseline) / total:.1f}",
        ),
        (
            "mean duration",
            f"{sum(o.duration_ms for o in supervisor) / total:.0f}ms",
            f"{sum(b['duration_ms'] for b in baseline) / total:.0f}ms",
        ),
        (
            "audit chains verified",
            f"{sum(o.chain_ok for o in supervisor)}/{total}",
            f"{sum(b['chain_ok'] for b in baseline)}/{total}",
        ),
        (
            "invariant breaches",
            str(sup_violations),
            "not assessable (no schema)",
        ),
    ]
    for label, left, right in rows:
        print(f"  {label:<34} {left:<24} {right}")

    print(
        "\n  The two tool rows are the blast radius of a successful injection, and the\n"
        "  second is the one that matters. Peak capability is comparable -- enrichment\n"
        "  holds a little more than the baseline does. The difference is *when*: the\n"
        "  baseline holds its full set for the entire run, including while it writes the\n"
        "  summary from everything it has read, whereas the reporter holds nothing at\n"
        "  all. The component most exposed to untrusted text ends up with the least\n"
        "  authority, which is not something a single-agent design can express.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
