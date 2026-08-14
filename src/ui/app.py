"""Streamlit analyst dashboard and approval console.

Two jobs:

1. **Run investigations** -- pick an alert, watch the pipeline execute, read the
   report.
2. **Be the human in the loop** -- when the graph interrupts, this is where an
   analyst reviews the evidence and the drafted proposals and decides.

The approval UI is deliberately blunt about what it is doing: every proposal is
labelled ``PROPOSAL ONLY``, and approving does not execute anything.  Approval
records a human decision in the audit trail and unblocks the report; carrying
the action out remains a human act in whatever console holds that authority.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Allow `streamlit run src/ui/app.py` from the repository root.
if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st  # noqa: E402

from src.config import get_settings  # noqa: E402
from src.enums import AgentRole, AuditAction  # noqa: E402
from src.graph import build_checkpointer, build_graph, pending_interrupt  # noqa: E402
from src.ingest import (  # noqa: E402
    AlertIngestError,
    list_sample_alerts,
    parse_alert,
    resolve_alert,
)
from src.security.audit import get_audit_logger, verify_chain  # noqa: E402
from src.security.identity import capability_matrix  # noqa: E402
from src.security.policy import default_policy  # noqa: E402
from src.state import SOCState  # noqa: E402

st.set_page_config(page_title="Agentic SOC", page_icon="🛡️", layout="wide")

SEVERITY_COLOUR = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#0369a1",
    "info": "#4b5563",
}


# --- Graph plumbing ---------------------------------------------------------
@st.cache_resource
def get_graph() -> Any:
    """Compile the graph once per session, with durable checkpointing."""
    return build_graph(checkpointer=build_checkpointer())


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": 50}


def _load_state(thread_id: str) -> SOCState | None:
    snapshot = get_graph().get_state(_config(thread_id))
    if not snapshot.values:
        return None
    try:
        return SOCState.model_validate(snapshot.values)
    except Exception as exc:  # noqa: BLE001 - surface rather than crash the UI
        st.error(f"Could not load run state: {exc}")
        return None


# --- Rendering helpers ------------------------------------------------------
def _severity_badge(severity: str) -> str:
    colour = SEVERITY_COLOUR.get(severity.lower(), "#4b5563")
    return (
        f"<span style='background:{colour};color:#fff;padding:2px 10px;"
        f"border-radius:10px;font-size:0.8rem;font-weight:600;'>{severity.upper()}</span>"
    )


def render_audit_table(state: SOCState) -> None:
    st.subheader("Audit trail")
    if not state.audit_log:
        st.info("No audit events recorded yet.")
        return

    # Verify the persisted log (the complete record), falling back to the
    # in-state slice if the run has not been flushed to disk yet.
    persisted = get_audit_logger().read_events(state.run.thread_id)
    if persisted:
        ok, message = verify_chain(persisted)
    else:
        ok, message = verify_chain(list(state.audit_log), expect_genesis=False)

    if ok:
        st.success(f"Hash chain verified — {message}")
    else:
        st.error(f"AUDIT TAMPERING DETECTED — {message}")

    st.dataframe(
        [
            {
                "#": event.sequence,
                "actor": event.actor.value,
                "action": event.action.value,
                "summary": event.summary,
                "ok": "yes" if event.success else "NO",
                "ms": round(event.duration_ms) if event.duration_ms else None,
            }
            for event in state.audit_log
        ],
        use_container_width=True,
        hide_index=True,
        height=420,
    )


def render_approval_panel(thread_id: str, request: dict[str, Any]) -> None:
    """The human-in-the-loop decision surface."""
    st.warning(f"**Human approval required** — rule `{request.get('rule_id')}`")
    st.markdown(
        f"{_severity_badge(str(request.get('severity', 'medium')))} &nbsp; "
        f"**{request.get('alert_id')}** — {request.get('alert_title')}",
        unsafe_allow_html=True,
    )
    st.markdown(f"**Why this stopped:** {request.get('reason')}")

    with st.expander("Investigation summary", expanded=True):
        st.write(request.get("summary", ""))

    actions = request.get("proposed_actions") or []
    if actions:
        st.markdown("#### Drafted containment actions")
        st.caption(
            "These are PROPOSALS. This system cannot execute containment. Approving records "
            "your decision and unblocks reporting; carrying the action out remains a human step."
        )
        for action in actions:
            risk = str(action.get("risk", "read_only"))
            icon = "🔴" if risk == "disruptive" else ("🟡" if risk == "low_impact" else "⚪")
            st.markdown(
                f"{icon} **{action.get('title')}** &nbsp;`{risk}`  \n"
                f"{action.get('description')}"
            )
    else:
        st.caption("No containment actions were drafted for this incident.")

    with st.form(f"approval-{request.get('request_id')}"):
        analyst = st.text_input("Your name", value="analyst")
        notes = st.text_area("Decision notes", placeholder="Rationale, scope limits, follow-ups…")
        approve_col, reject_col = st.columns(2)
        approved = approve_col.form_submit_button("✅ Approve", use_container_width=True)
        rejected = reject_col.form_submit_button("⛔ Reject", use_container_width=True)

    if approved or rejected:
        from langgraph.types import Command

        decision = {
            "request_id": request.get("request_id", ""),
            "approved": bool(approved),
            "decided_by": analyst or "analyst",
            "notes": notes,
            "approved_action_ids": [a["action_id"] for a in actions] if approved else [],
        }
        with st.spinner("Resuming investigation…"):
            get_graph().invoke(Command(resume=decision), config=_config(thread_id))
        st.rerun()


def render_report(state: SOCState) -> None:
    report = state.final_report
    if report is None:
        st.info("No report has been produced yet.")
        return

    left, mid, right = st.columns(3)
    left.metric("Verdict", report.verdict.value.replace("_", " ").title())
    mid.metric("Severity", report.severity.value.upper())
    right.metric("Confidence", f"{report.confidence:.0%}")

    st.markdown(report.to_markdown())
    st.download_button(
        "Download report (Markdown)",
        data=report.to_markdown(),
        file_name=f"incident-{state.alert.alert_id}.md",
        mime="text/markdown",
    )


def render_evidence(state: SOCState) -> None:
    triage = state.triage_result
    enrichment = state.enrichment_results

    if triage:
        st.markdown("#### Triage")
        st.markdown(
            f"{_severity_badge(triage.severity.value)} &nbsp; **{triage.category.value}** "
            f"&nbsp; confidence {triage.confidence:.0%} &nbsp; "
            f"{'LLM' if triage.used_llm else 'rule-based fallback'}",
            unsafe_allow_html=True,
        )
        st.write(triage.rationale)
        if triage.key_observations:
            for observation in triage.key_observations:
                st.markdown(f"- {observation}")

    if not enrichment:
        return

    st.markdown("#### Enrichment")
    if enrichment.untrusted_content_flagged:
        st.error(
            "**Prompt injection detected** in gathered evidence: "
            + ", ".join(enrichment.injection_flags)
            + ". The content was contained and reported, not executed."
        )
    st.write(enrichment.hunt_summary)

    if enrichment.ioc_enrichments:
        st.markdown("**Indicators**")
        st.dataframe(
            [
                {
                    "indicator": item.indicator,
                    "type": item.indicator_type.value,
                    "malicious": "YES" if item.known_malicious else "unknown",
                    "score": item.reputation_score,
                    "threats": ", ".join(item.threat_names) or "—",
                }
                for item in enrichment.ioc_enrichments
            ],
            use_container_width=True,
            hide_index=True,
        )

    if enrichment.mitre_techniques:
        st.markdown("**MITRE ATT&CK**")
        st.dataframe(
            [
                {
                    "technique": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "confidence": f"{t.confidence:.0%}",
                }
                for t in enrichment.mitre_techniques
            ],
            use_container_width=True,
            hide_index=True,
        )

    if enrichment.log_hits:
        st.markdown("**Correlated logs**")
        st.dataframe(
            [
                {
                    "log_id": hit.log_id,
                    "timestamp": hit.timestamp,
                    "host": hit.host,
                    "relevance": f"{hit.relevance:.2f}",
                    "message": hit.message[:180],
                }
                for hit in enrichment.log_hits
            ],
            use_container_width=True,
            hide_index=True,
        )

    if enrichment.pivot_suggestions:
        st.markdown("**Suggested pivots**")
        for pivot in enrichment.pivot_suggestions:
            st.markdown(f"- {pivot}")


# --- Sidebar ----------------------------------------------------------------
def sidebar() -> tuple[str | None, bool]:
    settings = get_settings()
    st.sidebar.title("🛡️ Agentic SOC")
    st.sidebar.caption("Security-first multi-agent alert triage")

    st.sidebar.markdown("### Run an alert")
    samples = list_sample_alerts()
    names = [path.stem for path in samples]
    choice = st.sidebar.selectbox("Sample alert", names) if names else None

    uploaded = st.sidebar.file_uploader("…or upload an alert (JSON)", type=["json"])
    start = st.sidebar.button("▶ Start investigation", use_container_width=True, type="primary")

    if uploaded is not None and start:
        import json

        try:
            alert = parse_alert(json.loads(uploaded.read().decode("utf-8")))
            st.session_state["pending_alert"] = alert
        except (AlertIngestError, ValueError) as exc:
            st.sidebar.error(f"Invalid alert: {exc}")
            return None, False

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Environment")
    st.sidebar.caption(f"Model: `{settings.ollama_model}`")
    st.sidebar.caption(f"Ollama: `{settings.ollama_base_url}`")
    st.sidebar.caption(f"Mode: {'offline (deterministic)' if settings.offline_mode else 'LLM enabled'}")

    with st.sidebar.expander("Approval policy"):
        for rule in default_policy().describe():
            st.markdown(f"**{rule['rule_id']}** — `{rule['effect']}`  \n{rule['reason']}")

    with st.sidebar.expander("Agent capabilities (least privilege)"):
        st.dataframe(
            [
                {
                    "agent": row["agent"],
                    "tools": ", ".join(row["tools"]),  # type: ignore[arg-type]
                    "max risk": row["max_action_risk"],
                }
                for row in capability_matrix()
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.sidebar.markdown("---")
    resume_id = st.sidebar.text_input("Load run by thread id")
    if st.sidebar.button("Load run", use_container_width=True) and resume_id:
        st.session_state["thread_id"] = resume_id.strip()
        st.rerun()

    return choice, start


# --- Main -------------------------------------------------------------------
def main() -> None:
    settings = get_settings()
    settings.ensure_dirs()

    choice, start = sidebar()

    if start:
        alert = st.session_state.pop("pending_alert", None)
        if alert is None and choice:
            try:
                alert = resolve_alert(choice)
            except AlertIngestError as exc:
                st.error(str(exc))
                return

        if alert is not None:
            initial = SOCState.bootstrap(
                alert,
                model_name=settings.ollama_model,
                offline_mode=settings.offline_mode,
            )
            thread_id = initial.run.thread_id
            st.session_state["thread_id"] = thread_id

            audit = get_audit_logger()
            audit.record(
                thread_id=thread_id,
                actor=AgentRole.SUPERVISOR,
                action=AuditAction.RUN_STARTED,
                summary=f"investigation started for {alert.alert_id} (UI)",
                details={"alert_id": alert.alert_id, "surface": "streamlit"},
            )

            with st.spinner("Agents working… (triage → enrichment → report)"):
                get_graph().invoke(initial, config=_config(thread_id))
            st.rerun()

    active_thread: str | None = st.session_state.get("thread_id")
    if not active_thread:
        st.title("Agentic SOC")
        st.markdown(
            """
            Select a sample alert in the sidebar and press **Start investigation**.

            A supervisor agent routes the alert through **triage**, **enrichment/hunting** and
            **reporting**. High-severity incidents, disruptive proposals, low-confidence verdicts
            and detected prompt-injection attempts all pause here for your approval before the
            investigation can complete.

            Every routing decision, tool call and policy evaluation is written to a
            hash-chained audit log you can verify on the **Audit** tab.
            """
        )
        st.info("Tip: `alert-005-prompt-injection` demonstrates the injection containment path.")
        return

    state = _load_state(active_thread)
    if state is None:
        st.error(f"No run found for thread `{active_thread}`.")
        return

    st.title(state.alert.title)
    st.caption(
        f"`{state.alert.alert_id}` · source **{state.alert.source}** · "
        f"thread `{active_thread}` · phase **{state.phase.value}**"
    )

    request = pending_interrupt(get_graph(), _config(active_thread))
    if request is not None:
        render_approval_panel(active_thread, request)
        st.markdown("---")

    report_tab, evidence_tab, audit_tab, state_tab = st.tabs(
        ["📄 Report", "🔍 Evidence", "🧾 Audit", "⚙️ Raw state"]
    )
    with report_tab:
        render_report(state)
    with evidence_tab:
        render_evidence(state)
    with audit_tab:
        render_audit_table(state)
    with state_tab:
        st.json(state.model_dump(mode="json", exclude={"audit_log", "messages"}))


if __name__ == "__main__":
    main()
