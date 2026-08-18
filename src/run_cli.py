"""Command-line runner for the Agentic SOC pipeline.

Usage::

    python -m src.run_cli --alert alert-001-ransomware
    python -m src.run_cli --alert alert-003-false-positive --offline
    python -m src.run_cli --list
    python -m src.run_cli --verify-audit <thread_id>

High-severity alerts pause for approval.  Provide ``--approve`` / ``--reject``
for a non-interactive decision, or answer the prompt.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from src.config import get_settings
from src.enums import AgentRole, AuditAction
from src.graph import build_checkpointer, build_graph, pending_interrupt
from src.ingest import AlertIngestError, list_sample_alerts, resolve_alert
from src.memory import DEDUP_WINDOW, attach_case_context, record_run
from src.security.audit import get_audit_logger, verify_chain
from src.security.identity import capability_matrix
from src.security.policy import default_policy
from src.security.redaction import register_secrets
from src.state import SOCState

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def _supports_colour() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}" if _supports_colour() else text


def _header(text: str) -> None:
    print(f"\n{_c('=' * 78, DIM)}")
    print(_c(text, BOLD))
    print(f"{_c('=' * 78, DIM)}")


def cmd_list() -> int:
    _header("Available sample alerts")
    alerts = list_sample_alerts()
    if not alerts:
        print("No sample alerts found in data/sample_alerts/.")
        return 1
    for path in alerts:
        try:
            alert = resolve_alert(str(path))
            print(f"  {_c(path.stem, CYAN):<50} {alert.reported_severity.value:<9} {alert.title[:60]}")
        except AlertIngestError as exc:
            print(f"  {path.stem:<50} {_c('INVALID', RED)}: {exc}")
    return 0


def cmd_policy() -> int:
    _header("Approval policy rules")
    for rule in default_policy().describe():
        effect = rule["effect"]
        colour = RED if effect == "deny" else (YELLOW if effect == "require_approval" else GREEN)
        print(f"  {_c(rule['rule_id'], colour):<40} {effect:<18} {rule['reason']}")

    _header("Agent capability matrix (least privilege)")
    print(f"  {'AGENT':<26} {'TOOLS':<62} {'MAX RISK':<12}")
    for row in capability_matrix():
        tools = ", ".join(row["tools"])  # type: ignore[arg-type]
        print(f"  {row['agent']:<26} {tools[:60]:<62} {row['max_action_risk']:<12}")
    return 0


def cmd_verify_audit(thread_id: str) -> int:
    _header(f"Audit chain verification: {thread_id}")
    logger = get_audit_logger()
    events = logger.read_events(thread_id)
    if not events:
        print(f"No audit events found for thread '{thread_id}'.")
        return 1

    ok, message = verify_chain(events)
    status = _c("VERIFIED", GREEN) if ok else _c("TAMPERING DETECTED", RED)
    print(f"  Events : {len(events)}")
    print(f"  Status : {status}")
    print(f"  Detail : {message}")
    return 0 if ok else 2


def _print_approval_request(payload: dict[str, Any]) -> None:
    _header("HUMAN APPROVAL REQUIRED")
    print(f"  {_c('Rule', BOLD)}      : {payload.get('rule_id')}")
    print(f"  {_c('Reason', BOLD)}    : {payload.get('reason')}")
    print(f"  {_c('Severity', BOLD)}  : {_c(str(payload.get('severity', '')).upper(), YELLOW)}")
    print(f"  {_c('Alert', BOLD)}     : {payload.get('alert_id')} -- {payload.get('alert_title')}")
    print(f"\n  {_c('Summary', BOLD)}:\n    {payload.get('summary', '')[:1200]}")

    actions = payload.get("proposed_actions") or []
    if actions:
        print(f"\n  {_c('Proposed containment actions (PROPOSAL ONLY -- nothing is executed)', BOLD)}:")
        for action in actions:
            print(
                f"    - [{action['risk']:<10}] {action['title']}\n"
                f"        {action['description']}"
            )
    else:
        print("\n  No containment actions were drafted.")


def _resolve_decision(args: argparse.Namespace) -> dict[str, Any]:
    if args.approve:
        return {
            "approved": True,
            "decided_by": args.analyst,
            "identity_source": "cli_flag",
            "notes": "Approved via --approve flag.",
        }
    if args.reject:
        return {
            "approved": False,
            "decided_by": args.analyst,
            "identity_source": "cli_flag",
            "notes": "Rejected via --reject flag.",
        }

    if not sys.stdin.isatty():
        # Fail closed when nobody can answer.
        print(_c("\n  No TTY available and no --approve/--reject flag; failing closed.", YELLOW))
        return {
            "approved": False,
            "decided_by": "system",
            "identity_source": "system_default",
            "notes": "No interactive analyst available; rejected by default.",
        }

    while True:
        answer = input(f"\n  {_c('Approve this incident handling? [y/N]: ', BOLD)}").strip().lower()
        if answer in {"y", "yes"}:
            notes = input("  Notes (optional): ").strip()
            return {
                "approved": True,
                "decided_by": args.analyst,
                "identity_source": "cli_operator",
                "notes": notes,
            }
        if answer in {"", "n", "no"}:
            notes = input("  Reason for rejection (optional): ").strip()
            return {
                "approved": False,
                "decided_by": args.analyst,
                "identity_source": "cli_operator",
                "notes": notes,
            }
        print("  Please answer 'y' or 'n'.")


def _print_audit_trail(state: SOCState) -> None:
    _header("Audit trail")
    for event in state.audit_log:
        colour = GREEN if event.success else RED
        marker = " " if event.success else "!"
        took = f" ({event.duration_ms:.0f}ms)" if event.duration_ms else ""
        print(
            f"  {marker}{event.sequence:03d}  {_c(event.actor.value, CYAN):<22} "
            f"{_c(event.action.value, colour):<34} {event.summary}{_c(took, DIM)}"
        )

    # Verify the *persisted* log, not the state slice: run-level events
    # (run_started / run_completed) are written straight to the logger and
    # never enter graph state, so the on-disk record is the complete chain.
    persisted = get_audit_logger().read_events(state.run.thread_id)
    ok, message = verify_chain(persisted)
    status = _c("VERIFIED", GREEN) if ok else _c("TAMPERING DETECTED", RED)
    print(f"\n  Hash chain: {status} -- {message}")


def _print_summary(state: SOCState) -> None:
    _header("Run summary")
    triage = state.triage_result
    enrichment = state.enrichment_results

    print(f"  Thread ID        : {state.run.thread_id}")
    print(f"  Alert            : {state.alert.alert_id} -- {state.alert.title}")
    print(f"  Final phase      : {state.phase.value}")
    print(f"  Agents run       : {', '.join(state.completed_agents) or '(none)'}")
    print(f"  Supervisor turns : {state.supervisor_turns}")
    print(f"  Tool calls       : {state.tool_calls_used}")
    print(f"  Approval         : {state.approval_status.value}"
          + (f" ({state.approval_rule_id})" if state.approval_rule_id else ""))
    if triage:
        print(f"  Triage           : {triage.severity.value} / {triage.category.value} "
              f"@ {triage.confidence:.0%} (llm={triage.used_llm})")
    if enrichment:
        print(f"  Enrichment       : {enrichment.malicious_indicator_count} malicious IOC(s), "
              f"{len(enrichment.mitre_techniques)} technique(s), {len(enrichment.log_hits)} log hit(s), "
              f"{len(enrichment.proposed_actions)} proposal(s)")
        if enrichment.untrusted_content_flagged:
            print(f"  {_c('Injection        : DETECTED -- ' + ', '.join(enrichment.injection_flags), RED)}")
    if state.errors:
        print(f"  {_c('Errors           : ' + '; '.join(state.errors), RED)}")


def cmd_run(args: argparse.Namespace) -> int:
    settings = get_settings()
    register_secrets(settings.secret_values())

    if args.offline:
        os.environ["SOC_OFFLINE_MODE"] = "true"
        get_settings.cache_clear()
        settings = get_settings()

    try:
        alert = resolve_alert(args.alert)
    except AlertIngestError as exc:
        print(_c(f"error: {exc}", RED), file=sys.stderr)
        return 1

    _header("Agentic SOC -- investigation start")
    print(f"  Alert    : {alert.alert_id} -- {alert.title}")
    print(f"  Source   : {alert.source} (reported {alert.reported_severity.value})")
    print(f"  Assets   : {', '.join(a.name for a in alert.assets) or '(none)'}")
    print(f"  Model    : {settings.ollama_model} "
          f"{_c('[OFFLINE MODE -- deterministic fallbacks]', YELLOW) if settings.offline_mode else ''}")

    checkpointer = build_memory() if args.ephemeral else build_checkpointer()
    graph = build_graph(checkpointer=checkpointer, consult_llm=not settings.offline_mode)

    initial = SOCState.bootstrap(
        alert,
        thread_id=args.thread_id,
        model_name=settings.ollama_model,
        offline_mode=settings.offline_mode,
        initiated_by=args.analyst,
    )
    # What has this environment seen before? Attached once, before the graph
    # starts, so the policy engine can consider it from the first turn.
    initial = attach_case_context(initial)
    if initial.duplicate_of and not args.force:
        print(
            _c(
                f"\n  Identical alert already investigated in run {initial.duplicate_of} "
                f"within the last {int(DEDUP_WINDOW.total_seconds() // 3600)}h.",
                YELLOW,
            )
        )
        print("  Re-running would produce a second opinion on the same bytes. Use --force to override.")
        return 0

    if initial.related_run_count:
        print(
            f"  History  : {initial.related_run_count} related run(s), "
            f"{initial.related_confirmed_malicious} previously confirmed"
            + (f" [case {initial.case_id}]" if initial.case_id else "")
        )

    config = {"configurable": {"thread_id": initial.run.thread_id}, "recursion_limit": 50}

    audit = get_audit_logger()
    audit.record(
        thread_id=initial.run.thread_id,
        actor=AgentRole.SUPERVISOR,
        action=AuditAction.RUN_STARTED,
        summary=f"investigation started for {alert.alert_id}",
        details={
            "alert_id": alert.alert_id,
            "alert_fingerprint": initial.run.alert_fingerprint,
            "model": settings.ollama_model,
            "offline_mode": settings.offline_mode,
        },
    )

    payload: Any = initial
    while True:
        result = graph.invoke(payload, config=config)

        request = pending_interrupt(graph, config, result)
        if request is None:
            break

        _print_approval_request(request)
        decision = _resolve_decision(args)

        from langgraph.types import Command

        payload = Command(resume=decision)

    final_state = SOCState.model_validate(graph.get_state(config).values)

    # Persist the outcome so the next investigation is not starting cold. The
    # analyst's decision is the most expensive signal this system produces;
    # until now it was written to the audit log and never read again.
    case_id = record_run(final_state)

    audit.record(
        thread_id=final_state.run.thread_id,
        actor=AgentRole.SUPERVISOR,
        action=AuditAction.RUN_COMPLETED,
        summary=f"investigation finished in phase '{final_state.phase.value}'",
        details={
            "phase": final_state.phase.value,
            "verdict": final_state.final_report.verdict.value if final_state.final_report else None,
            "tool_calls": final_state.tool_calls_used,
            "case_id": case_id,
        },
    )

    _print_summary(final_state)

    if not args.quiet_audit:
        _print_audit_trail(final_state)

    if final_state.final_report is not None:
        _header("Incident report")
        print(final_state.final_report.to_markdown())
    else:
        print(_c("\nNo report was produced (run halted before reporting).", YELLOW))

    print(f"\n{_c('Resume or inspect this run with thread id:', DIM)} {final_state.run.thread_id}")
    return 0


def build_memory() -> Any:
    from src.graph import build_memory_checkpointer

    return build_memory_checkpointer()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentic-soc",
        description="Run a security alert through the multi-agent SOC pipeline.",
    )
    parser.add_argument("--alert", "-a", help="Alert file path or sample name (e.g. alert-001-ransomware).")
    parser.add_argument("--list", "-l", action="store_true", help="List bundled sample alerts.")
    parser.add_argument("--policy", action="store_true", help="Show approval policy and capability matrix.")
    parser.add_argument("--verify-audit", metavar="THREAD_ID", help="Verify the audit hash chain for a run.")
    parser.add_argument("--thread-id", help="Explicit thread id (resumes an existing run if it exists).")
    parser.add_argument("--offline", action="store_true", help="Force deterministic mode with no LLM calls.")
    parser.add_argument("--ephemeral", action="store_true", help="Use an in-memory checkpointer.")
    parser.add_argument("--approve", action="store_true", help="Auto-approve any HITL gate (non-interactive).")
    parser.add_argument("--reject", action="store_true", help="Auto-reject any HITL gate (non-interactive).")
    parser.add_argument(
        "--analyst",
        default="cli-analyst",
        help="Name recorded as the deciding analyst. Self-asserted: the audit trail marks "
        "CLI decisions as such, since only the console can verify an identity.",
    )
    parser.add_argument("--quiet-audit", action="store_true", help="Suppress the audit trail printout.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Investigate even if an identical alert was already handled recently.",
    )

    args = parser.parse_args(argv)

    if args.approve and args.reject:
        parser.error("--approve and --reject are mutually exclusive")

    if args.list:
        return cmd_list()
    if args.policy:
        return cmd_policy()
    if args.verify_audit:
        return cmd_verify_audit(args.verify_audit)
    if args.alert:
        return cmd_run(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
