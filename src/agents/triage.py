"""Triage agent.

Responsibility: turn a raw alert into a structured, defensible first
assessment -- severity, category, confidence, and candidate ATT&CK techniques
for the hunter to verify.

Method (deliberately in this order):

1. Run the **deterministic classifier tool** first.  Its output is transparent
   and reproducible, and it anchors the LLM.
2. Contain the alert text, recording any injection heuristics it matched.  The
   flags become part of the :class:`~src.state.TriageResult` so they reach the
   policy engine even when the run never enriches.
3. Ask the LLM to review that assessment with the alert in front of it.  The
   model may revise severity or category, but it must justify the change.
4. Reconcile: the LLM's judgement is accepted, except that a downgrade below
   the deterministic classifier's severity is capped when the classifier saw
   strong aggravating evidence.  A model talked into "this is benign" by
   injected text cannot quietly bury a serious alert.

Step 4 is the security-relevant part.  The LLM has influence over the verdict,
but not unilateral power to suppress one.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.agents.base import (
    AgentContext,
    alert_summary_text,
    contain_alert,
)
from src.agents.coercion import enum_coercer
from src.enums import AgentRole, AlertCategory, AuditAction, Severity
from src.llm import structured_completion
from src.observability import metrics
from src.prompts import TRIAGE as _TRIAGE
from src.prompts import with_preamble
from src.security.audit import AuditEvent
from src.state import SecurityAlert, TriageResult

TRIAGE_SYSTEM_PROMPT = with_preamble(_TRIAGE)


class TriageLLMOutput(BaseModel):
    """Schema the triage model must fill."""

    severity: Severity = Field(description="Assessed severity: info, low, medium, high or critical.")
    category: AlertCategory = Field(description="Incident category.")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in this assessment, 0.0-1.0.")
    rationale: str = Field(
        min_length=20,
        max_length=2000,
        description="Two to four sentences justifying the severity and category, citing specific evidence.",
    )
    key_observations: list[str] = Field(
        default_factory=list,
        max_length=8,
        description="Short factual bullets of what stands out in this alert.",
    )
    suggested_techniques: list[str] = Field(
        default_factory=list,
        max_length=6,
        description="Candidate MITRE ATT&CK technique IDs, e.g. ['T1486', 'T1490'].",
    )
    recommended_next_step: str = Field(
        default="",
        max_length=400,
        description="The single most valuable next investigative action.",
    )

    # Models write 'Critical' where the enum says 'critical'. Normalise
    # presentation only; an unrecognised value still fails validation and
    # falls to the deterministic classifier, which is the correct outcome.
    _coerce_severity = field_validator("severity", mode="before")(enum_coercer(Severity))
    # Category may fall back to UNKNOWN; severity may not. See enum_coercer.
    _coerce_category = field_validator("category", mode="before")(
        enum_coercer(AlertCategory, unknown=AlertCategory.UNKNOWN)
    )


def _coerce_technique_ids(candidates: list[str]) -> tuple[str, ...]:
    """Keep only well-formed technique IDs, normalised to upper case."""
    import re

    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    seen: list[str] = []
    for candidate in candidates:
        value = str(candidate).strip().upper()
        if pattern.match(value) and value not in seen:
            seen.append(value)
    return tuple(seen[:6])


def run_triage(alert: SecurityAlert, context: AgentContext) -> tuple[TriageResult, list[AuditEvent]]:
    """Produce a :class:`TriageResult` for ``alert``."""
    events: list[AuditEvent] = []
    events.append(
        context.log(AuditAction.AGENT_STARTED, f"triage started for {alert.alert_id}")
    )

    # --- 1. Deterministic classification ---------------------------------
    tool_result = context.call_tool(
        "classify_alert",
        alert_summary=alert_summary_text(alert),
        reported_severity=alert.reported_severity.value,
    )
    events.extend(tool_result.audit_events)

    baseline: dict[str, Any] = tool_result.data if tool_result.ok else {}
    baseline_severity = Severity(baseline.get("severity", alert.reported_severity.value))
    baseline_category = AlertCategory(baseline.get("category", AlertCategory.UNKNOWN.value))
    baseline_confidence = float(baseline.get("confidence", 0.3))

    # --- 2. Contain the alert text and record what it contained -----------
    # The flags travel onto the TriageResult and from there into the policy
    # engine.  This is the only path by which injection carried in the *alert*
    # (rather than in tool output) can reach the approval gate -- and it must
    # not depend on enrichment running, since a benign verdict skips it.
    contained_alert = contain_alert(alert)
    alert_flags = contained_alert.injection_flags
    if alert_flags:
        metrics.injection_detected(source="alert")
        events.append(
            context.log(
                AuditAction.UNTRUSTED_CONTENT_FLAGGED,
                "prompt-injection heuristics matched in the alert content itself",
                {"source": f"alert:{alert.alert_id}", "flags": list(alert_flags)},
                success=False,
            )
        )

    # --- 3. LLM review ----------------------------------------------------
    user_prompt = (
        f"{contained_alert.as_prompt_block(label=f'alert:{alert.alert_id}')}\n\n"
        "Deterministic rule-based classification of the above alert:\n"
        f"  severity: {baseline_severity.value}\n"
        f"  category: {baseline_category.value}\n"
        f"  confidence: {baseline_confidence}\n"
        f"  rationale: {baseline.get('rationale', 'unavailable')}\n"
        f"  observations: {baseline.get('key_observations', [])}\n"
        f"  candidate techniques: {baseline.get('suggested_techniques', [])}\n\n"
        "Produce your own structured triage assessment of this alert."
    )

    call = structured_completion(
        TriageLLMOutput,
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        actor=AgentRole.TRIAGE,
        thread_id=context.thread_id,
        audit=context.audit,
    )
    events.extend(call.audit_events)

    # --- 4. Reconcile ------------------------------------------------------
    if call.ok and call.parsed is not None:
        llm: TriageLLMOutput = call.parsed
        severity = llm.severity
        adjustment_note = ""

        # Guardrail: the model may not downgrade below a deterministic
        # assessment that rested on strong aggravating evidence.
        aggravating = float(baseline.get("scores", {}).get("aggravating", 0.0))
        if severity.rank < baseline_severity.rank and aggravating >= 6.0:
            adjustment_note = (
                f" [GUARDRAIL: model proposed '{severity.value}' but the rule-based classifier "
                f"found strong aggravating evidence ({aggravating:.1f} points); severity held at "
                f"'{baseline_severity.value}' pending human review.]"
            )
            events.append(
                context.log(
                    AuditAction.POLICY_EVALUATED,
                    "triage severity downgrade blocked by guardrail",
                    {
                        "model_severity": severity.value,
                        "held_severity": baseline_severity.value,
                        "aggravating_score": aggravating,
                    },
                    success=False,
                )
            )
            severity = baseline_severity

        result = TriageResult(
            severity=severity,
            category=llm.category,
            confidence=round(min(llm.confidence, 0.95), 2),
            rationale=(llm.rationale + adjustment_note)[:4000],
            key_observations=tuple(str(o)[:400] for o in llm.key_observations[:8]),
            suggested_techniques=_coerce_technique_ids(
                llm.suggested_techniques or list(baseline.get("suggested_techniques", []))
            ),
            recommended_next_step=llm.recommended_next_step[:400],
            untrusted_content_flagged=bool(alert_flags),
            injection_flags=alert_flags,
            used_llm=True,
        )
    else:
        # --- Deterministic fallback ---------------------------------------
        result = TriageResult(
            severity=baseline_severity,
            category=baseline_category,
            # Cap confidence: a rule-based-only verdict is less trustworthy,
            # and the lower value biases the run toward human review.
            confidence=round(min(baseline_confidence, 0.6), 2),
            rationale=(
                "Produced by the deterministic classifier without LLM review "
                f"({call.error or 'model unavailable'}). "
                + str(baseline.get("rationale", "No rule-based rationale available."))
            )[:4000],
            key_observations=tuple(str(o)[:400] for o in baseline.get("key_observations", [])[:8]),
            suggested_techniques=_coerce_technique_ids(list(baseline.get("suggested_techniques", []))),
            recommended_next_step="Enrich indicators and correlate against historical logs.",
            untrusted_content_flagged=bool(alert_flags),
            injection_flags=alert_flags,
            used_llm=False,
        )

    events.append(
        context.log(
            AuditAction.AGENT_COMPLETED,
            f"triage complete: {result.severity.value} / {result.category.value}",
            {
                "severity": result.severity.value,
                "category": result.category.value,
                "confidence": result.confidence,
                "used_llm": result.used_llm,
                "suggested_techniques": list(result.suggested_techniques),
                "injection_flags": list(result.injection_flags),
            },
        )
    )
    return result, events
